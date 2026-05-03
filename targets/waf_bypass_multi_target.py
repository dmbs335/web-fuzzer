"""Multi-WAF bypass target — fans out one request to N WAF containers via Rust parallel sockets.

Replaces N separate waf_bypass_target.py subprocesses with a single subprocess that:
  1. Receives wire bytes from the fuzzer engine once (one pipe round-trip)
  2. Sends to all WAF endpoints concurrently via _speedups.parallel_socket_execute (GIL-free)
  3. Parses all responses and returns a JSON array [primary_result, ref0_result, ...]

H2c port (19104) is identified by the H2_CLIENT_PREFACE and handled with Python sockets
(H2 frame parsing requires the existing logic in waf_bypass_target.py).

Usage:
  python targets/waf_bypass_multi_target.py --persistent \
      --host 127.0.0.1 \
      --primary-port 19101 \
      --ref-ports 19102,19103,19104 \
      --timeout 3.0
"""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time
from pathlib import Path

# Reuse all parsing/analysis logic from waf_bypass_target.
sys.path.insert(0, str(Path(__file__).parent))
from waf_bypass_target import (  # noqa: E402
    H2_CLIENT_PREFACE,
    WAF_BLOCK_STATUSES,
    _analyze_response,
    _empty_result,
    _extract_control,
    _extract_wire_enrichment,
    _h2c_end_stream_received,
    _parse_h2_response,
    _parse_response,
)

try:
    from webfuzzer.native import _speedups  # type: ignore[import]
    _RUST_PARALLEL = True
except Exception:
    _RUST_PARALLEL = False


# ── Response parsing from raw bytes ───────────────────────────

def _parse_response_from_bytes(raw: bytes) -> dict[str, object]:
    """Parse a complete raw HTTP/1.1 response (no socket needed).

    Works on bytes returned by parallel_socket_execute which reads
    until EOF — so the full response is already in `raw`.
    """
    if not raw:
        return {"status": None, "headers": {}, "body": b"", "closed": True}

    sep = b"\r\n\r\n"
    if sep not in raw:
        # Malformed / incomplete — treat whatever we have as the body.
        return {"status": None, "headers": {}, "body": raw, "closed": True}

    head, body_raw = raw.split(sep, 1)
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", errors="replace")
    parts = status_line.split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.strip().decode("latin-1").lower()] = v.strip().decode(
            "latin-1", errors="replace"
        )

    # Honour Content-Length if present; otherwise use everything to EOF.
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        # For chunked responses, body_raw already contains the full chunked
        # stream (Rust read until EOF).  Decode it simply.
        body = _decode_chunked(body_raw)
    else:
        cl_str = headers.get("content-length", "")
        if cl_str.strip().isdigit():
            cl = int(cl_str.strip())
            body = body_raw[:cl]
        else:
            body = body_raw

    return {"status": status, "headers": headers, "body": body, "closed": True}


def _decode_chunked(data: bytes) -> bytes:
    """Best-effort chunked decoding from raw bytes."""
    out = bytearray()
    buf = data
    while buf:
        delim = b"\r\n" if b"\r\n" in buf else (b"\n" if b"\n" in buf else None)
        if delim is None:
            break
        line, rest = buf.split(delim, 1)
        try:
            size = int(line.decode("ascii", errors="replace").split(";", 1)[0].strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out.extend(rest[:size])
        buf = rest[size:]
        # skip trailing delimiter
        if buf.startswith(b"\r\n"):
            buf = buf[2:]
        elif buf.startswith(b"\n"):
            buf = buf[1:]
    return bytes(out)


# ── Single-target fallback (Python socket) ─────────────────────

def _execute_h2c_python(
    stripped_wire: bytes,
    *,
    host: str,
    port: int,
    timeout: float,
    meta: dict,
    wire_enrichment: dict,
) -> dict[str, object]:
    """Send H2c request via Python socket (H2 frame parsing required)."""
    start = time.monotonic()
    result = _empty_result(meta)
    result.update(wire_enrichment)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(stripped_wire)
            result["request_bytes_sent"] = len(stripped_wire)
            raw_h2 = b""
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    raw_h2 += chunk
                    if _h2c_end_stream_received(raw_h2):
                        break
            except socket.timeout:
                pass
        status, resp_hdrs, resp_body = _parse_h2_response(raw_h2)
        response = {
            "status": status if status != -1 else None,
            "headers": resp_hdrs,
            "body": resp_body,
            "closed": True,
        }
        elapsed_ms = (time.monotonic() - start) * 1000
        return _analyze_response(
            meta,
            response,
            elapsed_ms=elapsed_ms,
            request_bytes_sent=len(stripped_wire),
            wire_enrichment=wire_enrichment,
        )
    except Exception as exc:
        result["parse_error"] = f"h2c:{exc}"
        result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
        return result


def _execute_python_fallback(
    stripped_wire: bytes,
    *,
    host: str,
    port: int,
    timeout: float,
    meta: dict,
    wire_enrichment: dict,
) -> dict[str, object]:
    """Python socket fallback for H1 (used when Rust not available)."""
    start = time.monotonic()
    result = _empty_result(meta)
    result.update(wire_enrichment)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.sendall(stripped_wire)
            result["request_bytes_sent"] = len(stripped_wire)
            buf = b""
            try:
                response, _ = _parse_response(sock, buf)
            except (socket.timeout, ValueError, OSError) as exc:
                result["parse_error"] = f"recv:{exc}"
                result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
                return result
        elapsed_ms = (time.monotonic() - start) * 1000
        return _analyze_response(
            meta,
            response,
            elapsed_ms=elapsed_ms,
            request_bytes_sent=len(stripped_wire),
            wire_enrichment=wire_enrichment,
        )
    except Exception as exc:
        result["parse_error"] = f"connect:{exc}"
        result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
        return result


# ── Core multi-target execution ────────────────────────────────

def execute_wire_multi(
    wire: bytes,
    *,
    host: str,
    primary_port: int,
    ref_ports: list[int],
    timeout: float,
) -> list[dict[str, object]]:
    """Execute wire against all ports, return [primary_result, *ref_results]."""
    all_ports = [primary_port] + list(ref_ports)
    meta, stripped_wire = _extract_control(wire)
    wire_enrichment = _extract_wire_enrichment(stripped_wire)
    is_h2 = stripped_wire.startswith(H2_CLIENT_PREFACE)

    # ── H2c path: sequential Python (rare, different protocol) ──
    if is_h2:
        results = []
        for port in all_ports:
            r = _execute_h2c_python(
                stripped_wire,
                host=host,
                port=port,
                timeout=timeout,
                meta=meta,
                wire_enrichment=wire_enrichment,
            )
            results.append(r)
        return results

    # ── H1 path: Rust parallel sockets ──────────────────────────
    if _RUST_PARALLEL:
        endpoints = [(host, p) for p in all_ports]
        raw_responses = _speedups.parallel_socket_execute(
            endpoints,
            stripped_wire,
            int(timeout * 1000),
        )
    else:
        # Fallback: Python threading (same result, less efficient)
        import threading

        raw_responses = [None] * len(all_ports)
        errors: list[str | None] = [None] * len(all_ports)

        def _send(i: int, port: int) -> None:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((host, port))
                    s.sendall(stripped_wire)
                    buf = b""
                    while True:
                        chunk = s.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                        if len(buf) > 512 * 1024:
                            break
                    raw_responses[i] = buf
            except Exception as exc:
                errors[i] = str(exc)
                raw_responses[i] = b""

        threads = [
            threading.Thread(target=_send, args=(i, p), daemon=True)
            for i, p in enumerate(all_ports)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 1.0)

        raw_responses = [
            (raw_responses[i] or b"", errors[i]) for i in range(len(all_ports))
        ]

    # ── Parse each raw response ──────────────────────────────────
    results: list[dict[str, object]] = []
    start_approx = time.monotonic()

    for raw_bytes, err in raw_responses:
        r = _empty_result(meta)
        r.update(wire_enrichment)
        r["request_bytes_sent"] = len(stripped_wire)

        if err:
            r["parse_error"] = err
            r["duration_ms"] = round((time.monotonic() - start_approx) * 1000, 2)
        else:
            response = _parse_response_from_bytes(raw_bytes)
            elapsed_ms = round((time.monotonic() - start_approx) * 1000, 2)
            r = _analyze_response(
                meta,
                response,
                elapsed_ms=elapsed_ms,
                request_bytes_sent=len(stripped_wire),
                wire_enrichment=wire_enrichment,
            )

        results.append(r)

    return results


# ── Persistent protocol loop ───────────────────────────────────

def _read_nbytes(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError("persistent client closed")
        buf += chunk
    return buf


def _run_persistent_loop(
    *,
    host: str,
    primary_port: int,
    ref_ports: list[int],
    timeout: float,
) -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        header = stdin.read(4)
        if len(header) < 4:
            break
        length = struct.unpack(">I", header)[0]
        wire = _read_nbytes(stdin, length)

        exit_code = 0
        try:
            results = execute_wire_multi(
                wire,
                host=host,
                primary_port=primary_port,
                ref_ports=ref_ports,
                timeout=timeout,
            )
        except Exception as exc:
            exit_code = 1
            results = [
                {
                    "parse_error": f"multi:{exc}",
                    "request_bytes_sent": 0,
                    "waf_blocked": False,
                    "bypass_detected": False,
                }
            ]

        payload = json.dumps(results, ensure_ascii=False).encode("utf-8", errors="replace")
        stdout.write(struct.pack(">I", len(payload)))
        stdout.write(payload)
        stdout.write(struct.pack(">I", exit_code))
        stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-WAF bypass target — fans out to N WAF containers via Rust"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--primary-port", type=int, required=True)
    parser.add_argument(
        "--ref-ports",
        default="",
        help="Comma-separated reference WAF ports, e.g. 19102,19103,19104",
    )
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--persistent", action="store_true")
    args = parser.parse_args()

    ref_ports = (
        [int(p.strip()) for p in args.ref_ports.split(",") if p.strip()]
        if args.ref_ports
        else []
    )

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if args.persistent:
        _run_persistent_loop(
            host=args.host,
            primary_port=args.primary_port,
            ref_ports=ref_ports,
            timeout=args.timeout,
        )
        return

    # One-shot mode: read from stdin
    wire = sys.stdin.buffer.read()
    if not wire:
        print("[]")
        return
    results = execute_wire_multi(
        wire,
        host=args.host,
        primary_port=args.primary_port,
        ref_ports=ref_ports,
        timeout=args.timeout,
    )
    print(json.dumps(results, ensure_ascii=False))


if __name__ == "__main__":
    main()
