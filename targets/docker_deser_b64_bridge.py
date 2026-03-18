"""Base64 bridge for DeserTarget inside Docker — persistent mode.

Speaks binary persistent protocol on stdin/stdout (to fuzzer),
base64 text protocol on docker exec -i (to Docker wrapper).

JVM starts once, ~3 exec/s throughput. No Windows binary pipe issues.

Usage (by fuzzer via _NATIVE_PERSISTENT_MAP):
    python targets/docker_deser_b64_bridge.py <container_id> [DeserTarget args...]
"""
import base64
import struct
import subprocess
import sys
import threading


def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: docker_deser_b64_bridge.py <container_id> [DeserTarget args...]",
              file=sys.stderr)
        sys.exit(1)

    container_id = args[0]
    dt_args = args[1:]

    wl_cp = ":".join([
        "/u01/oracle/wlserver/server/lib/weblogic.jar",
        "/u01/oracle/coherence/lib/coherence.jar",
        "/u01/oracle/wlserver/modules/com.bea.core.repackaged.springframework.spring.jar",
        "/tmp/gson-2.11.0.jar",
        "/tmp",
    ])

    # Start docker exec -i with the Java b64 wrapper inside Docker
    cmd = [
        "docker", "exec", "-i",
        container_id,
        "java", "-cp", wl_cp,
        "DeserB64Wrapper",
    ] + dt_args

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
    )

    # Wait for READY signal
    ready = proc.stdout.readline()
    if b"READY" not in ready:
        print(f"[b64_bridge] Unexpected startup: {ready}", file=sys.stderr)
        sys.exit(1)
    print("[b64_bridge] Docker wrapper ready", file=sys.stderr)

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

        # Send base64-encoded payload to Docker wrapper
        b64_req = base64.b64encode(payload).decode("ascii") + "\n"
        try:
            proc.stdin.write(b64_req.encode("ascii"))
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            print(f"[b64_bridge] Write error: {e}", file=sys.stderr)
            break

        # Read base64-encoded response from Docker wrapper
        resp_line = proc.stdout.readline()
        if not resp_line:
            print("[b64_bridge] Docker wrapper EOF", file=sys.stderr)
            break

        # Decode: full_resp = 4-byte length + body + 4-byte exit_code
        full_resp = base64.b64decode(resp_line.strip())

        # Forward to fuzzer as-is (already in persistent protocol format)
        stdout_buf.write(full_resp)
        stdout_buf.flush()

    proc.terminate()


if __name__ == "__main__":
    main()
