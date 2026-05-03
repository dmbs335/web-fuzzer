"""Intentionally lenient H2->H1 bridge for TR.PSEUDO.MRG research.

Accepts H2c (Prior Knowledge) connections and does NOT validate whether
pseudo-headers appear in trailing HEADERS frames. This violates RFC 9113
§8.1.2.1, which requires malformed treatment of such requests.

Vulnerable merge behaviour:
  trailer :path      -> overwrites request-line path
  trailer :authority -> overwrites Host header
  trailer :method    -> overwrites request method

Effect: the validator upstream sees one (path, authority), the backend
sees another — TR.PSEUDO.MRG.
"""
from __future__ import annotations

import argparse
import socket
import socketserver
import struct
import sys

import hpack


def _dbg(msg: str) -> None:
    sys.stderr.write(f"[bridge] {msg}\n")
    sys.stderr.flush()

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


def _pack(type_id: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    length = len(payload)
    hdr = struct.pack(">I", length)[1:]          # 3-byte big-endian length
    hdr += bytes([type_id, flags])
    hdr += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return hdr + payload


class _FrameReader:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buf = b""

    def next(self, timeout: float = 5.0) -> tuple[int, int, int, bytes]:
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
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buf += chunk


class _Stream:
    __slots__ = ("initial", "body", "trailer", "got_initial", "pending_hpack")

    def __init__(self) -> None:
        self.initial: list[tuple[str, str]] = []
        self.body: bytes = b""
        self.trailer: list[tuple[str, str]] = []
        self.got_initial: bool = False
        self.pending_hpack: bytes = b""


class H2LenientBridgeHandler(socketserver.BaseRequestHandler):
    backend_host: str = "backend"
    backend_port: int = 8081

    def handle(self) -> None:
        _dbg(f"new connection from {self.client_address}")
        try:
            self._run()
        except (ConnectionError, OSError, socket.timeout) as e:
            _dbg(f"connection closed: {e}")
        except Exception as e:
            _dbg(f"UNEXPECTED: {e!r}")
        finally:
            _dbg("handler done")

    def _run(self) -> None:
        sock: socket.socket = self.request
        sock.settimeout(10.0)
        reader = _FrameReader(sock)

        # Consume client preface
        preface = H2_PREFACE
        buf = b""
        while len(buf) < len(preface):
            chunk = sock.recv(len(preface) - len(buf))
            if not chunk:
                return
            buf += chunk
        if buf != preface:
            return
        reader.buf = b""

        # Send server SETTINGS (HEADER_TABLE_SIZE=4096)
        sock.sendall(_pack(_T_SETTINGS, 0, 0, struct.pack(">HI", 0x1, 4096)))

        dec = hpack.Decoder()
        streams: dict[int, _Stream] = {}

        while True:
            try:
                type_id, flags, sid, payload = reader.next(timeout=10.0)
            except (ConnectionError, socket.timeout):
                return

            if type_id == _T_SETTINGS:
                if not (flags & _F_ACK):
                    sock.sendall(_pack(_T_SETTINGS, _F_ACK, 0, b""))
                continue

            if type_id in (_T_WINDOW, _T_RST):
                if type_id == _T_RST:
                    streams.pop(sid, None)
                continue

            if type_id == _T_GOAWAY:
                return

            if type_id == _T_HEADERS:
                st = streams.setdefault(sid, _Stream())
                hpack_block = payload
                if not (flags & _F_END_HEADERS):
                    # Accumulate CONTINUATION frames
                    st.pending_hpack = payload
                    while True:
                        ct, cf, cs, cp = reader.next(timeout=5.0)
                        if ct == _T_CONTINUATION and cs == sid:
                            st.pending_hpack += cp
                            if cf & _F_END_HEADERS:
                                break
                        # unexpected frame — best-effort: ignore and stop collecting
                        break
                    hpack_block = st.pending_hpack
                    st.pending_hpack = b""

                try:
                    hdrs = dec.decode(hpack_block)
                except Exception:
                    hdrs = []

                if st.got_initial:
                    # ---- LENIENT: trailer HEADERS accepted even with pseudo-headers ----
                    _dbg(f"stream {sid}: trailer HEADERS, hdrs={hdrs}")
                    st.trailer = list(hdrs)
                else:
                    _dbg(f"stream {sid}: initial HEADERS got_initial=True, {len(hdrs)} hdrs")
                    st.initial = list(hdrs)
                    st.got_initial = True

                if flags & _F_END_STREAM:
                    _dbg(f"stream {sid}: END_STREAM on HEADERS, dispatching")
                    try:
                        resp = self._dispatch(sid, streams.pop(sid))
                        _dbg(f"stream {sid}: dispatch returned {len(resp)} bytes")
                        sock.sendall(resp)
                    except Exception as e:
                        _dbg(f"stream {sid}: dispatch/sendall ERROR: {e!r}")
                continue

            if type_id == _T_DATA:
                if sid in streams:
                    streams[sid].body += payload
                    _dbg(f"stream {sid}: DATA {len(payload)}B body_total={len(streams[sid].body)}")
                    if flags & _F_END_STREAM:
                        _dbg(f"stream {sid}: END_STREAM on DATA, dispatching")
                        try:
                            resp = self._dispatch(sid, streams.pop(sid))
                            _dbg(f"stream {sid}: dispatch returned {len(resp)} bytes")
                            sock.sendall(resp)
                        except Exception as e:
                            _dbg(f"stream {sid}: dispatch/sendall ERROR: {e!r}")
                continue

    # ------------------------------------------------------------------
    def _dispatch(self, sid: int, st: _Stream) -> bytes:
        method    = "GET"
        path      = "/"
        authority = "localhost"
        reg: dict[str, str] = {}

        for name, value in st.initial:
            if   name == ":method":    method    = value
            elif name == ":path":      path      = value
            elif name == ":authority": authority = value
            elif not name.startswith(":"):
                reg[name.lower()] = value

        # ---- VULNERABLE: pseudo-headers from trailer override routing ----
        overrides: list[str] = []
        for name, value in st.trailer:
            if name == ":path":
                overrides.append(f"path:{path}->{value}")
                path = value
            elif name == ":authority":
                overrides.append(f"host:{reg.get('host', authority)}->{value}")
                reg["host"] = value
                authority   = value
            elif name == ":method":
                overrides.append(f"method:{method}->{value}")
                method = value

        if "host" not in reg:
            reg["host"] = authority

        # Forward as H1
        lines = [f"{method} {path} HTTP/1.1\r\n",
                 f"Host: {reg['host']}\r\n"]
        if st.body:
            lines.append(f"Content-Length: {len(st.body)}\r\n")
        if overrides:
            lines.append(f"X-Pseudo-Trailer-Override: {';'.join(overrides)}\r\n")
        for k, v in reg.items():
            if k not in ("host", "content-length"):
                lines.append(f"{k}: {v}\r\n")
        lines.append("\r\n")
        h1_req = "".join(lines).encode("latin-1") + st.body

        try:
            with socket.create_connection(
                (self.backend_host, self.backend_port), timeout=3.0
            ) as up:
                up.sendall(h1_req)
                up.settimeout(2.0)
                h1_resp = b""
                while True:
                    try:
                        chunk = up.recv(65536)
                        if not chunk:
                            break
                        h1_resp += chunk
                    except socket.timeout:
                        break
        except Exception:
            return self._h2_status(sid, 502)

        return self._h1_to_h2(sid, h1_resp)

    def _h2_status(self, sid: int, code: int) -> bytes:
        enc = hpack.Encoder()
        block = enc.encode([(":status", str(code))])
        return _pack(_T_HEADERS, _F_END_HEADERS | _F_END_STREAM, sid, block)

    def _h1_to_h2(self, sid: int, raw: bytes) -> bytes:
        if b"\r\n\r\n" not in raw:
            return self._h2_status(sid, 502)
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status = 200
        try:
            status = int(lines[0].split()[1])
        except (IndexError, ValueError):
            pass
        enc = hpack.Encoder()
        hdr_list: list[tuple[str, str]] = [(":status", str(status))]
        _skip = {"connection", "keep-alive", "transfer-encoding", "upgrade"}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                ks = k.strip().lower().decode("latin-1")
                if ks not in _skip:
                    hdr_list.append((ks, v.strip().decode("latin-1", errors="replace")))
        block = enc.encode(hdr_list)
        return (
            _pack(_T_HEADERS, _F_END_HEADERS, sid, block)
            + _pack(_T_DATA, _F_END_STREAM, sid, body)
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen",       type=int, default=8080)
    parser.add_argument("--backend-host", default="backend")
    parser.add_argument("--backend-port", type=int, default=8081)
    args = parser.parse_args()

    H2LenientBridgeHandler.backend_host = args.backend_host
    H2LenientBridgeHandler.backend_port = args.backend_port

    class _Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    with _Server(("0.0.0.0", args.listen), H2LenientBridgeHandler) as srv:
        print(f"[*] H2 lenient bridge :{args.listen} -> {args.backend_host}:{args.backend_port}")
        srv.serve_forever()


if __name__ == "__main__":
    main()
