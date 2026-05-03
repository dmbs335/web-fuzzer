"""Simple keep-alive backend for request-smuggling experiments."""

from __future__ import annotations

import argparse
import hashlib
import socket
import socketserver


def _line_delimiter(buffer: bytes) -> bytes | None:
    if b"\r\n" in buffer:
        return b"\r\n"
    if b"\n" in buffer:
        return b"\n"
    return None


def _read_exact(conn: socket.socket, buffer: bytes, needed: int) -> tuple[bytes, bytes]:
    while len(buffer) < needed:
        chunk = conn.recv(8192)
        if not chunk:
            break
        buffer += chunk
    return buffer[:needed], buffer[needed:]


def _read_chunked(conn: socket.socket, buffer: bytes) -> tuple[bytes, bytes, dict[str, str]]:
    body = b""
    trailers: dict[str, str] = {}
    while True:
        delimiter = _line_delimiter(buffer)
        while delimiter is None:
            chunk = conn.recv(8192)
            if not chunk:
                return body, buffer, trailers
            buffer += chunk
            delimiter = _line_delimiter(buffer)
        line, buffer = buffer.split(delimiter, 1)
        size = int(line.decode("ascii", errors="replace").split(";", 1)[0].strip(), 16)
        if size == 0:
            while True:
                delimiter = _line_delimiter(buffer)
                while delimiter is None:
                    chunk = conn.recv(8192)
                    if not chunk:
                        return body, buffer, trailers
                    buffer += chunk
                    delimiter = _line_delimiter(buffer)
                trailer_line, buffer = buffer.split(delimiter, 1)
                if not trailer_line:
                    return body, buffer, trailers
                if b":" not in trailer_line:
                    trailers["_malformed"] = trailer_line.decode("latin-1", errors="replace")
                    continue
                key, value = trailer_line.split(b":", 1)
                trailers[key.strip().decode("latin-1").lower()] = value.strip().decode(
                    "latin-1",
                    errors="replace",
                )
        data, buffer = _read_exact(conn, buffer, size + len(delimiter))
        body += data[:size]


def _merge_trailers(headers: dict[str, str], trailers: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    merged = dict(headers)
    merged_from_trailer: list[str] = []
    for key in ("host", "x-forwarded-host", "x-forwarded-for", "x-original-url", "x-trailer-canary"):
        value = trailers.get(key)
        if value:
            merged[key] = value
            merged_from_trailer.append(key)
    return merged, merged_from_trailer


def _parse_request(conn: socket.socket, buffer: bytes) -> tuple[dict[str, object] | None, bytes]:
    while b"\r\n\r\n" not in buffer:
        chunk = conn.recv(8192)
        if not chunk:
            return None, b""
        buffer += chunk
    head, buffer = buffer.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    req_line = lines[0].decode("latin-1", errors="replace")
    parts = req_line.split()
    if len(parts) < 3:
        return None, buffer
    method, path, _version = parts[:3]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.strip().decode("latin-1").lower()] = value.strip().decode("latin-1", errors="replace")

    # Some upstream proxies (notably Apache mod_proxy in our matrix) may wait for
    # an interim 100 Continue before sending the request body.
    expect = headers.get("expect", "").lower()
    if "100-continue" in expect:
        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

    trailers: dict[str, str] = {}
    if headers.get("transfer-encoding", "").lower().find("chunked") >= 0:
        body, buffer, trailers = _read_chunked(conn, buffer)
    else:
        length = int(headers.get("content-length", "0") or "0")
        body, buffer = _read_exact(conn, buffer, length)
    merged_headers, merged_from_trailer = _merge_trailers(headers, trailers)
    return {
        "request_line": req_line,
        "method": method,
        "path": path,
        "headers": headers,
        "trailers": trailers,
        "merged_headers": merged_headers,
        "merged_from_trailer": merged_from_trailer,
        "body": body,
    }, buffer


def _response_for(
    path: str,
    body: bytes,
    headers: dict[str, str],
    *,
    request_line: str = "",
    trailers: dict[str, str] | None = None,
    merged_headers: dict[str, str] | None = None,
    merged_from_trailer: list[str] | None = None,
) -> bytes:
    trailers = trailers or {}
    merged_headers = merged_headers or headers
    merged_from_trailer = merged_from_trailer or []
    impact = "none"
    detail = "generic"
    routing_source = "request-path"
    cache_source = "request-path"
    if path.startswith("/__canary__/"):
        payload = f"BACKEND-MARKER canary {path}".encode("utf-8")
        status = b"HTTP/1.1 404 Not Found"
        marker = "canary"
        impact = "canary"
        detail = path
    elif path.startswith("/early"):
        payload = b"BACKEND-MARKER early"
        status = b"HTTP/1.1 401 Unauthorized"
        marker = "early"
        impact = "acl_bypass"
        detail = "early-gadget"
    elif path.startswith("/cache/store"):
        cache_key = merged_headers.get("x-original-url", path)
        source = "trailer" if "x-original-url" in merged_from_trailer else "header"
        cache_source = source
        trailer_note = trailers.get("x-trailer-canary", "")
        payload = (
            f"BACKEND-MARKER cache IMPACT:cache_poison key={cache_key} "
            f"source={source} trailer={trailer_note}"
        ).encode("utf-8")
        status = b"HTTP/1.1 200 OK"
        marker = "cache"
        impact = "cache_poison"
        detail = cache_key
    elif path.startswith("/admin/panel"):
        host_value = merged_headers.get("host", "backend-admin")
        routing_source = "trailer" if "host" in merged_from_trailer else "host"
        payload = (
            f"BACKEND-MARKER admin IMPACT:acl_bypass role=backend-admin host={host_value}"
        ).encode("utf-8")
        status = b"HTTP/1.1 403 Forbidden"
        marker = "admin"
        impact = "acl_bypass"
        detail = host_value
    elif path.startswith("/queue/append"):
        routing_source = "queue"
        payload = b"BACKEND-MARKER queue IMPACT:response_queue slot=primary"
        status = b"HTTP/1.1 202 Accepted"
        marker = "queue"
        impact = "response_queue"
        detail = "slot=primary"
    elif path.startswith("/reflect/prefix"):
        reflected = body[:48].decode("latin-1", errors="replace")
        routing_source = "body_prefix"
        payload = f"BACKEND-MARKER reflect IMPACT:prefix_reflection {reflected}".encode("utf-8")
        status = b"HTTP/1.1 200 OK"
        marker = "reflect"
        impact = "prefix_reflection"
        detail = reflected
    else:
        payload = b"BACKEND-MARKER ok " + body[:32]
        status = b"HTTP/1.1 200 OK"
        marker = "ok"
    effective_headers = ";".join(
        f"{key}={merged_headers.get(key, '')}"
        for key in sorted(k for k in ("host", "x-forwarded-host", "x-original-url", "transfer-encoding", "content-length") if k in merged_headers)
    )
    body_boundary = (
        f"bytes={len(body)};chunked={'transfer-encoding' in headers and 'chunked' in headers.get('transfer-encoding', '').lower()};"
        f"trailers={len(trailers)}"
    )
    forwarded_hash = hashlib.sha1(
        f"{request_line}|{effective_headers}|{path}|{len(body)}|{','.join(sorted(merged_from_trailer))}".encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()[:20]
    headers = [
        status,
        f"Content-Length: {len(payload)}".encode("ascii"),
        f"X-Backend-Marker: {marker}".encode("ascii"),
        f"X-Impact-Marker: {impact}".encode("ascii"),
        f"X-Impact-Detail: {detail}".encode("ascii", errors="replace"),
        f"X-Trailer-Merge: {','.join(merged_from_trailer) or 'none'}".encode("ascii", errors="replace"),
        f"X-Forwarded-Request-Line: {request_line}".encode("ascii", errors="replace"),
        f"X-Forwarded-Request-Hash: {forwarded_hash}".encode("ascii", errors="replace"),
        f"X-Effective-Headers: {effective_headers or 'none'}".encode("ascii", errors="replace"),
        f"X-Body-Boundary: {body_boundary}".encode("ascii", errors="replace"),
        f"X-Trailer-Forwarded: {'true' if bool(merged_from_trailer) else 'false'}".encode("ascii"),
        f"X-Routing-Decision-Source: {routing_source}".encode("ascii", errors="replace"),
        f"X-Cache-Decision-Source: {cache_source}".encode("ascii", errors="replace"),
        b"Connection: keep-alive",
        b"",
        b"",
    ]
    return b"\r\n".join(headers) + payload


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        buffer = b""
        self.request.settimeout(2.0)
        while True:
            req, buffer = _parse_request(self.request, buffer)
            if req is None:
                return
            self.request.sendall(
                _response_for(
                    str(req["path"]),
                    bytes(req["body"]),
                    dict(req["headers"]),
                    request_line=str(req.get("request_line") or ""),
                    trailers=dict(req.get("trailers") or {}),
                    merged_headers=dict(req.get("merged_headers") or {}),
                    merged_from_trailer=list(req.get("merged_from_trailer") or []),
                )
            )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    with Server((args.host, args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
