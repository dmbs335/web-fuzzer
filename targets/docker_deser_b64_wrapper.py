"""Base64 wrapper for DeserTarget persistent mode — runs INSIDE Docker.

Reads base64-encoded requests (one per line) from stdin,
decodes and forwards to DeserTarget via binary persistent protocol,
reads response, base64-encodes and writes to stdout.

This avoids Windows binary stdin piping issues with docker exec -i.

Usage (inside Docker):
    python3 /tmp/docker_deser_b64_wrapper.py <DeserTarget args...>
"""
import base64
import struct
import subprocess
import sys
import os


def read_exact(stream, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError("unexpected EOF")
        buf.extend(chunk)
    return bytes(buf)


def main():
    dt_args = sys.argv[1:]

    cp = os.environ.get("CLASSPATH", "/tmp")

    # Start DeserTarget in persistent mode
    cmd = ["java", "-cp", cp, "DeserTarget", "--persistent"] + dt_args
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        bufsize=0,
    )

    # Signal ready
    sys.stdout.write("READY\n")
    sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        # Decode base64 request
        payload = base64.b64decode(line)

        # Forward to DeserTarget: 4-byte BE length + payload
        proc.stdin.write(struct.pack(">I", len(payload)))
        proc.stdin.write(payload)
        proc.stdin.flush()

        # Read response: 4-byte length + body + 4-byte exit code
        h = read_exact(proc.stdout, 4)
        rlen = struct.unpack(">I", h)[0]
        body = read_exact(proc.stdout, rlen)
        ec = read_exact(proc.stdout, 4)

        # Base64 encode full response (length + body + exit_code) and write
        full_resp = h + body + ec
        sys.stdout.write(base64.b64encode(full_resp).decode("ascii") + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
