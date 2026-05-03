"""Echo backend for WAF bypass experiments.

Reflects request body and headers back to the caller so the oracle
can determine whether a payload survived WAF inspection and reached
the backend intact.

Routes:
  /reflect  -- echo body in response body
  /echo-headers -- echo request headers as response body
  /health   -- 200 OK (container healthcheck)
  *         -- default echo (body prefix + headers)
"""

from __future__ import annotations

import argparse
import hashlib
import socket
import socketserver


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
            # skip trailers
            while True:
                while delim not in buf:
                    chunk = conn.recv(8192)
                    if not chunk:
                        return body, buf
                    buf += chunk
                trailer_line, buf = buf.split(delim, 1)
                if not trailer_line:
                    return body, buf
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
    if len(parts) < 3:
        return None, buf
    method, path = parts[0], parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1", errors="replace")

    expect = headers.get("expect", "").lower()
    if "100-continue" in expect:
        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

    if "chunked" in headers.get("transfer-encoding", "").lower():
        body, buf = _read_chunked(conn, buf)
    else:
        length = int(headers.get("content-length", "0") or "0")
        body, buf = _read_exact(conn, buf, length)

    return {
        "request_line": req_line,
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
    }, buf


def _build_response(req: dict) -> bytes:
    path = req["path"]
    body = req["body"]
    headers_dict = req["headers"]
    request_line = req["request_line"]

    # Determine response body
    if path.startswith("/health"):
        status_line = b"HTTP/1.1 200 OK"
        resp_body = b"ok"
    elif path.startswith("/reflect"):
        status_line = b"HTTP/1.1 200 OK"
        resp_body = body  # echo full body
    elif path.startswith("/upload"):
        status_line = b"HTTP/1.1 200 OK"
        resp_body = body  # same as /reflect — echo full body
    elif path.startswith("/echo-headers"):
        status_line = b"HTTP/1.1 200 OK"
        hdr_lines = [f"{k}: {v}" for k, v in sorted(headers_dict.items())]
        resp_body = "\r\n".join(hdr_lines).encode("utf-8", errors="replace")
    else:
        status_line = b"HTTP/1.1 200 OK"
        resp_body = body[:512] if body else b"ok"

    # Compute hashes
    body_hash = hashlib.sha256(body).hexdigest()[:16] if body else "empty"
    req_hash = hashlib.sha1(
        f"{request_line}|{len(body)}".encode("utf-8", errors="replace"),
    ).hexdigest()[:20]

    # Build echoed headers (reflect all request headers)
    echoed = []
    for k, v in sorted(headers_dict.items()):
        safe_v = v[:200].encode("ascii", errors="replace")
        echoed.append(f"X-Echoed-{k}: ".encode("ascii") + safe_v)

    resp_headers = [
        status_line,
        f"Content-Length: {len(resp_body)}".encode("ascii"),
        b"X-Backend-Marker: reached",
        f"X-Backend-Body-Hash: {body_hash}".encode("ascii"),
        f"X-Forwarded-Request-Line: {request_line}".encode("ascii", errors="replace"),
        f"X-Forwarded-Request-Hash: {req_hash}".encode("ascii"),
        f"X-Echoed-Request-Path: {path}".encode("ascii", errors="replace"),
        f"X-Echoed-Body-Length: {len(body)}".encode("ascii"),
        b"Connection: keep-alive",
    ]
    resp_headers.extend(echoed)
    resp_headers.append(b"")
    resp_headers.append(b"")
    return b"\r\n".join(resp_headers) + resp_body


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        buf = b""
        self.request.settimeout(2.0)
        while True:
            req, buf = _parse_request(self.request, buf)
            if req is None:
                return
            self.request.sendall(_build_response(req))


def main() -> None:
    parser = argparse.ArgumentParser(description="WAF bypass echo backend")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    print(f"WAF marker backend listening on {args.host}:{args.port}")
    with Server((args.host, args.port), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
