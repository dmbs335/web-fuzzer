"""Synthetic H2-downgrade frontend.

For request streams tagged with X-HTTP2-Downgrade + CL/TE ambiguity, this
frontend strips Transfer-Encoding before forwarding, simulating an H2->H1
downgrade that re-materializes Content-Length semantics.
"""

from __future__ import annotations

import argparse
import socket
import socketserver


def _recv_all(conn: socket.socket, timeout: float = 0.2) -> bytes:
    conn.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = conn.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data


def _rewrite_h2_downgrade(raw: bytes) -> bytes:
    if b"\r\n\r\n" not in raw:
        return raw
    head, rest = raw.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    headers = [line for line in lines[1:] if b":" in line]
    has_h2 = any(line.lower().startswith(b"x-http2-downgrade:") for line in headers)
    has_cl = any(line.lower().startswith(b"content-length:") for line in headers)
    has_te = any(line.lower().startswith(b"transfer-encoding:") for line in headers)
    if not (has_h2 and has_cl and has_te):
        return raw
    kept = [lines[0]]
    for line in headers:
        if line.lower().startswith(b"transfer-encoding:"):
            continue
        kept.append(line)
    return b"\r\n".join(kept) + b"\r\n\r\n" + rest


class Handler(socketserver.BaseRequestHandler):
    backend_host: str = "backend"
    backend_port: int = 8081

    def handle(self) -> None:
        raw = _recv_all(self.request)
        if not raw:
            return
        forwarded = _rewrite_h2_downgrade(raw)
        with socket.create_connection((self.backend_host, self.backend_port), timeout=2.0) as upstream:
            upstream.sendall(forwarded)
            upstream.settimeout(0.3)
            while True:
                try:
                    chunk = upstream.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                self.request.sendall(chunk)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", type=int, default=8080)
    parser.add_argument("--backend-host", default="backend")
    parser.add_argument("--backend-port", type=int, default=8081)
    args = parser.parse_args()

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    Handler.backend_host = args.backend_host
    Handler.backend_port = args.backend_port
    with Server(("0.0.0.0", args.listen), Handler) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
