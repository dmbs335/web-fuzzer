"""Precise RST timing test for HAProxy pseudo-trailer handling.

Measures: time from sending trailer HEADERS to receiving RST_STREAM.
If < 10ms: HAProxy rejects before backend round-trip (pure validation).
If > 50ms: HAProxy waited for backend response (forwarded, then RST'd).
If ~timeout: HAProxy waited until backend timeout to RST.
"""
from __future__ import annotations

import socket
import struct
import time
import sys

import hpack

def _pack(type_id, flags, stream_id, payload):
    length = len(payload)
    hdr = struct.pack(">I", length)[1:]
    hdr += bytes([type_id, flags])
    hdr += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return hdr + payload

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_T_HEADERS = 0x1; _T_DATA = 0x0; _T_SETTINGS = 0x4; _T_RST = 0x3
_T_WINDOW = 0x8; _T_GOAWAY = 0x7
_F_END_STREAM = 0x1; _F_END_HEADERS = 0x4; _F_ACK = 0x1

ERR = {0x0:"NO_ERROR",0x1:"PROTOCOL_ERROR",0x2:"INTERNAL_ERROR",
       0x7:"REFUSED_STREAM",0x3:"FLOW_CONTROL_ERROR"}


def recv_until_rst_or_timeout(sock, timeout=5.0):
    """Read frames until we get RST_STREAM or timeout. Returns (rst_code, elapsed_ms)."""
    sock.settimeout(0.05)  # small poll interval
    buf = b""
    t0 = time.monotonic()
    deadline = t0 + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            pass

        # parse frames on the fly
        i = 0
        while i + 9 <= len(buf):
            length = (buf[i] << 16) | (buf[i+1] << 8) | buf[i+2]
            if i + 9 + length > len(buf):
                break
            type_id = buf[i+3]
            flags   = buf[i+4]
            sid     = struct.unpack(">I", buf[i+5:i+9])[0] & 0x7FFFFFFF
            payload = buf[i+9:i+9+length]
            i += 9 + length

            if type_id == _T_RST and sid > 0:
                code = struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else -1
                elapsed = (time.monotonic() - t0) * 1000
                return code, elapsed
            elif type_id == _T_GOAWAY:
                code = struct.unpack(">I", payload[4:8])[0] if len(payload) >= 8 else -1
                elapsed = (time.monotonic() - t0) * 1000
                return -(code + 1), elapsed  # negative = goaway

    return None, (time.monotonic() - t0) * 1000


def handshake(sock):
    sock.sendall(H2_PREFACE + _pack(_T_SETTINGS, 0, 0, b""))
    sock.settimeout(3.0)
    buf = b""
    t_end = time.monotonic() + 3.0
    while time.monotonic() < t_end:
        try:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
        i = 0
        while i + 9 <= len(buf):
            length = (buf[i] << 16) | (buf[i+1] << 8) | buf[i+2]
            if i + 9 + length > len(buf):
                break
            t = buf[i+3]; f = buf[i+4]
            i += 9 + length
            if t == _T_SETTINGS and not (f & _F_ACK):
                sock.sendall(_pack(_T_SETTINGS, _F_ACK, 0, b""))
                return
    return


def measure_rst_latency(host, port, label, n=5):
    """Run N times and collect RST latencies."""
    results = []
    for i in range(n):
        try:
            sock = socket.create_connection((host, port), timeout=5.0)
            handshake(sock)
            enc = hpack.Encoder()
            init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                               (":authority", f"{host}:{port}")])
            init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
            body_f = _pack(_T_DATA, 0, 1, b"timing-body")
            trail = enc.encode([(":path", "/admin/panel")])
            trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)

            sock.sendall(init_f + body_f)
            time.sleep(0.02)  # let DATA arrive separately
            t_sent = time.monotonic()
            sock.sendall(trail_f)
            code, elapsed = recv_until_rst_or_timeout(sock, timeout=5.0)
            sock.close()
            results.append((code, elapsed))
            sys.stdout.write(f"  run {i+1}: code={ERR.get(code, code)} elapsed={elapsed:.1f}ms\n")
            sys.stdout.flush()
            time.sleep(0.1)
        except Exception as e:
            results.append((None, None))
            sys.stdout.write(f"  run {i+1}: ERROR {e!r}\n")
    return results


def measure_without_data(host, port, n=3):
    """T10 variant: no DATA frame, direct pseudo-trailer - is timing different?"""
    print(f"\n  Without DATA frame (trailer immediately after init HEADERS):")
    for i in range(n):
        try:
            sock = socket.create_connection((host, port), timeout=5.0)
            handshake(sock)
            enc = hpack.Encoder()
            init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                               (":authority", f"{host}:{port}")])
            init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
            trail = enc.encode([(":path", "/no-data-trailer")])
            trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)

            t_sent = time.monotonic()
            sock.sendall(init_f + trail_f)
            code, elapsed = recv_until_rst_or_timeout(sock, timeout=5.0)
            sock.close()
            sys.stdout.write(f"  run {i+1}: code={ERR.get(code, code)} elapsed={elapsed:.1f}ms\n")
            sys.stdout.flush()
            time.sleep(0.1)
        except Exception as e:
            sys.stdout.write(f"  run {i+1}: ERROR {e!r}\n")


def measure_regular_trailer(host, port, n=3):
    """T2 variant: regular trailer - confirm HAProxy accepts and doesn't RST."""
    print(f"\n  Regular (non-pseudo) trailer timing:")
    for i in range(n):
        try:
            sock = socket.create_connection((host, port), timeout=5.0)
            handshake(sock)
            enc = hpack.Encoder()
            init = enc.encode([(":method", "GET"), (":path", "/"), (":scheme", "http"),
                               (":authority", f"{host}:{port}")])
            init_f = _pack(_T_HEADERS, _F_END_HEADERS, 1, init)
            body_f = _pack(_T_DATA, 0, 1, b"body-regular")
            trail = enc.encode([("x-trailer", "harmless")])
            trail_f = _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, 1, trail)

            t_sent = time.monotonic()
            sock.sendall(init_f + body_f + trail_f)
            code, elapsed = recv_until_rst_or_timeout(sock, timeout=3.0)
            sock.close()
            if code is None:
                sys.stdout.write(f"  run {i+1}: no RST (accepted) elapsed={elapsed:.1f}ms\n")
            else:
                sys.stdout.write(f"  run {i+1}: RST code={ERR.get(code, code)} elapsed={elapsed:.1f}ms\n")
            sys.stdout.flush()
            time.sleep(0.1)
        except Exception as e:
            sys.stdout.write(f"  run {e!r}\n")


HOST = "localhost"
PORT = 18082   # haproxy_confusion

print("#"*60)
print("  HAProxy RST Latency Analysis")
print("  Pseudo-headers in trailer -> RST timing")
print("#"*60)
print(f"\n  Target: {HOST}:{PORT}")
print(f"  Hypothesis: if elapsed < 10ms -> reject before backend forward")
print(f"              if elapsed > 100ms -> waited for backend round-trip")
print(f"              if elapsed ~5000ms -> backend timeout before RST")
print()
print(f"  With DATA frame + :path in trailer:")
measure_rst_latency(HOST, PORT, "haproxy_confusion", n=5)
measure_without_data(HOST, PORT, n=3)
measure_regular_trailer(HOST, PORT, n=3)

print("\n" + "#"*60)
print("  Interpretation:")
print("  Sub-10ms = pure validation path (safe, no backend leak)")
print("  10-500ms = some backend interaction before reject (partial leak)")
print("  >500ms   = backend timeout drives the RST (DON'T confirm yet)")
print("#"*60)
