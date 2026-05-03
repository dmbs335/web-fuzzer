"""Intentionally lenient HTTP frontend for differential smuggling tests."""

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


def _strip_transfer_encoding(raw: bytes) -> bytes:
    if b"\r\n\r\n" not in raw:
        return raw
    head, rest = raw.split(b"\r\n\r\n", 1)
    lines = []
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"transfer-encoding:"):
            continue
        lines.append(line)
    return b"\r\n".join(lines) + b"\r\n\r\n" + rest


class Handler(socketserver.BaseRequestHandler):
    backend_host: str = "backend"
    backend_port: int = 8081

    def handle(self) -> None:
        raw = _recv_all(self.request)
        if not raw:
            return
        forwarded = _strip_transfer_encoding(raw)
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
