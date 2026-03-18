"""TCP bridge for DeserTarget running inside Docker via DeserTcpServer.

Persistent mode bridge: reads 4-byte BE length-prefixed requests from stdin,
forwards to DeserTcpServer over TCP, returns responses via stdout.

JVM starts once inside Docker (via DeserTcpServer) — no per-request overhead.
Expected throughput: ~10-50 exec/s (vs ~0.2 exec/s with docker exec bridge).

Usage (by the fuzzer via _NATIVE_PERSISTENT_MAP):
    python targets/docker_deser_tcp_bridge.py <host:port>
"""
import socket
import struct
import sys


def _read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("TCP connection closed")
        buf.extend(chunk)
    return bytes(buf)


def main():
    if len(sys.argv) < 2:
        print("Usage: docker_deser_tcp_bridge.py <host:port>", file=sys.stderr)
        sys.exit(1)

    addr = sys.argv[1]
    if ":" in addr:
        host, port = addr.rsplit(":", 1)
        port = int(port)
    else:
        host, port = "172.17.0.3", int(addr)

    # Connect to DeserTcpServer
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((host, port))
    print(f"[tcp_bridge] Connected to {host}:{port}", file=sys.stderr)

    stdin_buf = sys.stdin.buffer
    stdout_buf = sys.stdout.buffer

    while True:
        # Read 4-byte BE length from fuzzer
        header = stdin_buf.read(4)
        if len(header) < 4:
            break
        length = struct.unpack(">I", header)[0]
        if length > 1_000_000:
            break

        # Read payload from fuzzer
        payload = stdin_buf.read(length)
        if len(payload) < length:
            break

        try:
            # Forward to TCP server: 4-byte length + payload
            sock.sendall(struct.pack(">I", length))
            sock.sendall(payload)

            # Read response from TCP server: 4-byte length + body + 4-byte exit code
            # (DeserTarget persistent protocol, raw-forwarded by TcpServer)
            resp_header = _read_exact(sock, 4)
            resp_len = struct.unpack(">I", resp_header)[0]
            resp_body = _read_exact(sock, resp_len)
            resp_ec = _read_exact(sock, 4)  # exit code from DeserTarget

            # Write to fuzzer: 4-byte length + body + 4-byte exit code
            stdout_buf.write(resp_header)
            stdout_buf.write(resp_body)
            stdout_buf.write(resp_ec)
            stdout_buf.flush()

        except (ConnectionError, socket.timeout) as e:
            print(f"[tcp_bridge] Connection error: {e}", file=sys.stderr)
            break

    sock.close()


if __name__ == "__main__":
    main()
