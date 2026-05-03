"""Python stdlib parse echo backend for WAF bypass finding validation.

Unlike waf_marker_backend.py (raw body reflection), this backend attempts
application-level parsing to determine whether bypass techniques deliver
payloads through the WAF+parser chain to a real application.

Parses Content-Type: application/x-www-form-urlencoded, multipart/form-data,
application/json. Returns parsed field names/values in both response headers
and JSON body.

Response headers:
  X-Parse-Status: ok|error|skip
  X-Parse-Format: form|multipart|json|unknown
  X-Parsed-Field-Count: N
  X-Parsed-Field-Names: name1,name2,...  (up to 20)
  X-Parse-Error: <message if error>

Response body: JSON {"status":..., "format":..., "fields":{...}, "raw_size":N}

Port: 19110 (direct, no WAF)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import socket
import socketserver
import urllib.parse
from typing import Any


# ── Body parsers ────────────────────────────────────────────────────────────

def _flatten_json(obj: Any, prefix: str = "", max_depth: int = 6) -> dict[str, list[str]]:
    """Flatten a JSON object into {key: [str_value, ...]} pairs."""
    if max_depth <= 0:
        return {}
    result: dict[str, list[str]] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else k
            result.update(_flatten_json(v, key, max_depth - 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]" if prefix else f"[{i}]"
            result.update(_flatten_json(v, key, max_depth - 1))
    else:
        result.setdefault(prefix or "_root", []).append(str(obj) if obj is not None else "")
    return result


def _extract_boundary(content_type: str) -> str | None:
    """Extract multipart boundary from Content-Type header value."""
    # Try standard 'boundary=' parameter — handle leading/trailing spaces,
    # tab, quoted values, uppercase BOUNDARY=, duplicate params (first wins).
    ct_lower = content_type.lower()
    for part in content_type.split(";")[1:]:
        part = part.strip()
        if part.lower().startswith("boundary"):
            _, _, val = part.partition("=")
            val = val.strip()
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            if val:
                return val
    return None


_CD_NAME_RE = re.compile(
    rb'[Cc]ontent-[Dd]isposition\s*:[^\r\n]*\bname\s*=\s*(?:"([^"]*)"|([^\s;"\r\n]*))',
    re.IGNORECASE,
)


def _parse_part_name(part_headers: bytes) -> str | None:
    """Extract field name from a multipart part's headers (robust to evasion)."""
    # Unfold obs-fold (CRLF + SP/TAB continuation)
    unfolded = re.sub(rb"\r?\n[ \t]+", b" ", part_headers)
    m = _CD_NAME_RE.search(unfolded)
    if not m:
        return None
    raw = m.group(1) if m.group(1) is not None else m.group(2)
    if raw is None:
        return None
    # Strip null bytes (evasion variant: name="field\x00admin")
    raw = raw.replace(b"\x00", b"")
    return raw.decode("latin-1", errors="replace")


def _parse_multipart(body: bytes, boundary: str | None) -> dict:
    """Parse multipart/form-data body. Handles common evasion variants."""
    if not boundary:
        return {"status": "error", "fields": {}, "error": "no boundary"}

    # Normalize: strip surrounding whitespace/quotes that evasion variants add
    boundary_b = boundary.strip().encode("latin-1", errors="replace")
    delim = b"--" + boundary_b
    end_delim = delim + b"--"

    fields: dict[str, list[str]] = {}
    # Split on delimiter (allow optional trailing CRLF or LF after delimiter line)
    parts = re.split(rb"(?:\r?\n)?" + re.escape(delim) + rb"(?:\r?\n)?", body)

    for part in parts[1:]:  # skip preamble
        if part.strip().startswith(b"--"):  # end delimiter fragment
            break
        # Split headers from body at first blank line
        if b"\r\n\r\n" in part:
            header_bytes, _, part_body = part.partition(b"\r\n\r\n")
        elif b"\n\n" in part:
            header_bytes, _, part_body = part.partition(b"\n\n")
        else:
            continue

        name = _parse_part_name(header_bytes)
        if name is None:
            name = f"_part_{len(fields)}"

        # Strip trailing delimiter prefix from body
        part_body = re.sub(rb"\r?\n$", b"", part_body)

        existing = fields.get(name)
        val = part_body.decode("latin-1", errors="replace")
        if existing is None:
            fields[name] = [val]
        else:
            existing.append(val)

    return {"status": "ok", "fields": fields, "error": None}


def _parse_form(body: bytes) -> dict:
    """Parse application/x-www-form-urlencoded body."""
    try:
        text = body.decode("latin-1", errors="replace")
        parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
        return {"status": "ok", "fields": parsed, "error": None}
    except Exception as exc:
        return {"status": "error", "fields": {}, "error": str(exc)}


def _parse_json_body(body: bytes) -> dict:
    """Parse application/json body and flatten to field dict."""
    try:
        text = body.decode("utf-8", errors="replace")
        obj = json.loads(text)
        fields = _flatten_json(obj)
        return {"status": "ok", "fields": fields, "error": None}
    except Exception as exc:
        return {"status": "error", "fields": {}, "error": str(exc)}


def _parse_body(body: bytes, content_type: str) -> tuple[str, dict]:
    """Dispatch to correct parser. Returns (format_name, parse_result)."""
    if not content_type:
        return "unknown", {"status": "skip", "fields": {}, "error": None}

    ct_lower = content_type.lower().split(";")[0].strip()
    if ct_lower == "application/x-www-form-urlencoded":
        return "form", _parse_form(body)
    if ct_lower.startswith("multipart/form-data"):
        boundary = _extract_boundary(content_type)
        return "multipart", _parse_multipart(body, boundary)
    if ct_lower in ("application/json", "text/json", "application/x-json"):
        return "json", _parse_json_body(body)

    return "unknown", {"status": "skip", "fields": {}, "error": None}


# ── HTTP layer (reused from waf_marker_backend.py) ──────────────────────────

def _read_exact(conn: socket.socket, buf: bytes, n: int) -> tuple[bytes, bytes]:
    while len(buf) < n:
        chunk = conn.recv(8192)
        if not chunk:
            break
        buf += chunk
    return buf[:n], buf[n:]


def _read_chunked(conn: socket.socket, buf: bytes) -> tuple[bytes, bytes]:
    body = b""
    while True:
        while b"\r\n" not in buf and b"\n" not in buf:
            chunk = conn.recv(8192)
            if not chunk:
                return body, buf
            buf += chunk
        delim = b"\r\n" if b"\r\n" in buf else b"\n"
        line, buf = buf.split(delim, 1)
        try:
            size = int(line.decode("ascii", errors="replace").split(";", 1)[0].strip(), 16)
        except ValueError:
            return body, buf
        if size == 0:
            while True:
                while delim not in buf:
                    chunk = conn.recv(8192)
                    if not chunk:
                        return body, buf
                    buf += chunk
                trailer_line, buf = buf.split(delim, 1)
                if not trailer_line:
                    return body, buf
        data, buf = _read_exact(conn, buf, size + len(delim))
        body += data[:size]


def _parse_request(conn: socket.socket, buf: bytes) -> tuple[dict | None, bytes]:
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(8192)
        if not chunk:
            return None, b""
        buf += chunk
    head, buf = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    req_line = lines[0].decode("latin-1", errors="replace")
    parts = req_line.split()
    if len(parts) < 2:
        return None, buf
    method, path = parts[0], parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1", errors="replace")

    if "100-continue" in headers.get("expect", "").lower():
        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

    if "chunked" in headers.get("transfer-encoding", "").lower():
        body, buf = _read_chunked(conn, buf)
    else:
        length = int(headers.get("content-length", "0") or "0")
        body, buf = _read_exact(conn, buf, length)

    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
    }, buf


# ── Response builder ─────────────────────────────────────────────────────────

def _build_response(req: dict) -> bytes:
    path = req["path"]
    body = req["body"]
    headers_dict = req["headers"]

    if path.startswith("/health"):
        resp_body = b'{"status":"ok"}'
        extra_hdrs: list[bytes] = []
        resp_hdrs = [
            b"HTTP/1.1 200 OK",
            f"Content-Length: {len(resp_body)}".encode(),
            b"Content-Type: application/json",
            b"Connection: keep-alive",
            b"", b"",
        ]
        return b"\r\n".join(resp_hdrs) + resp_body

    content_type = headers_dict.get("content-type", "")
    fmt, parse_result = _parse_body(body, content_type)

    fields: dict[str, list[str]] = parse_result.get("fields", {})
    status_str = parse_result.get("status", "skip")
    error_str = parse_result.get("error") or ""
    field_count = len(fields)
    field_names = list(fields.keys())[:20]

    # Build JSON response body
    # Truncate field values to 500 chars each to avoid huge responses
    safe_fields: dict[str, list[str]] = {}
    for k, vs in fields.items():
        safe_fields[k] = [v[:500] for v in vs]

    resp_obj = {
        "status": status_str,
        "format": fmt,
        "fields": safe_fields,
        "raw_size": len(body),
        "field_count": field_count,
    }
    if error_str:
        resp_obj["error"] = error_str
    resp_body = json.dumps(resp_obj, ensure_ascii=False).encode("utf-8")

    # Build headers
    extra: list[bytes] = [
        b"HTTP/1.1 200 OK",
        f"Content-Length: {len(resp_body)}".encode(),
        b"Content-Type: application/json",
        b"X-Backend-Reached: true",
        f"X-Parse-Status: {status_str}".encode(),
        f"X-Parse-Format: {fmt}".encode(),
        f"X-Parsed-Field-Count: {field_count}".encode(),
        f"X-Parsed-Field-Names: {','.join(field_names)}".encode("utf-8", errors="replace"),
        f"X-Raw-Body-Hash: {hashlib.sha256(body).hexdigest()[:16]}".encode(),
        b"Connection: keep-alive",
    ]
    if error_str:
        safe_err = error_str[:200].encode("ascii", errors="replace")
        extra.append(b"X-Parse-Error: " + safe_err)

    # Add per-field value headers (first value, truncated)
    for name in field_names[:10]:
        vals = fields.get(name, [])
        if vals:
            safe_name = name[:30].encode("ascii", errors="replace")
            safe_val = vals[0][:100].encode("ascii", errors="replace")
            extra.append(b"X-Parsed-" + safe_name + b": " + safe_val)

    extra.extend([b"", b""])
    return b"\r\n".join(extra) + resp_body


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        buf = b""
        self.request.settimeout(3.0)
        while True:
            req, buf = _parse_request(self.request, buf)
            if req is None:
                return
            self.request.sendall(_build_response(req))


def main() -> None:
    parser = argparse.ArgumentParser(description="WAF parse echo backend (Python stdlib)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8082)
    args = parser.parse_args()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    print(f"WAF parse echo backend (stdlib) listening on {args.host}:{args.port}")
    with Server((args.host, args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
