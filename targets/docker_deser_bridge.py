"""Bridge for running DeserTarget inside Docker with persistent mode protocol.

Runs as a persistent target on the host side, forwarding each request
to a fresh `docker exec` invocation (single-shot mode inside Docker).
This avoids Windows binary stdin piping issues with `docker exec -i`.

Usage (by the fuzzer via _NATIVE_PERSISTENT_MAP):
    python targets/docker_deser_bridge.py <container_id> [--filter weblogic] [--classpath weblogic]
"""
import base64
import json
import struct
import subprocess
import sys
import os

def main():
    args = sys.argv[1:]
    if not args:
        print("Usage: docker_deser_bridge.py <container_id> [DeserTarget args...]", file=sys.stderr)
        sys.exit(1)

    container_id = args[0]
    dt_args = args[1:]

    # Build classpath inside container
    wl_cp = ":".join([
        "/u01/oracle/wlserver/server/lib/weblogic.jar",
        "/u01/oracle/coherence/lib/coherence.jar",
        "/u01/oracle/wlserver/modules/com.bea.core.repackaged.springframework.spring.jar",
        "/tmp/gson-2.11.0.jar",
        "/tmp",
    ])

    stdin_buf = sys.stdin.buffer
    stdout_buf = sys.stdout.buffer

    while True:
        # Read 4-byte BE length
        header = stdin_buf.read(4)
        if len(header) < 4:
            break
        length = struct.unpack(">I", header)[0]
        if length > 1_000_000:
            break

        # Read payload
        payload = stdin_buf.read(length)
        if len(payload) < length:
            break

        # Write payload to a temp file inside the container, then run DeserTarget single-shot
        b64_payload = base64.b64encode(payload).decode("ascii")

        # Build docker exec command
        cmd = [
            "docker", "exec", container_id, "bash", "-c",
            f'echo "{b64_payload}" | base64 -d > /tmp/_fuzz_input.json && '
            f'java -cp "{wl_cp}" DeserTarget {" ".join(dt_args)} /tmp/_fuzz_input.json 2>/dev/null'
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=10,
            )
            response = result.stdout
            if not response:
                # Empty response — create error JSON
                response = json.dumps({
                    "compiled": False,
                    "error": f"empty_response: {result.stderr.decode('utf-8', errors='replace')[:200]}",
                    "duration_ms": 0,
                }).encode("utf-8")
        except subprocess.TimeoutExpired:
            response = json.dumps({
                "compiled": False,
                "error": "timeout",
                "duration_ms": 10000,
            }).encode("utf-8")
        except Exception as e:
            response = json.dumps({
                "compiled": False,
                "error": f"bridge_error: {e}",
                "duration_ms": 0,
            }).encode("utf-8")

        # Write 4-byte BE length + response + 4-byte BE exit code (0 = success)
        stdout_buf.write(struct.pack(">I", len(response)))
        stdout_buf.write(response)
        stdout_buf.write(struct.pack(">I", 0))
        stdout_buf.flush()


if __name__ == "__main__":
    main()
