"""HTTP/2 binary frame encoder for WAF bypass fuzzing.

Builds raw H2 binary (h2c Prior Knowledge) without the h2 library's
RFC-compliance enforcement — required to generate malformed/evasion frames.

Frame wire format:
    [3B length][1B type][1B flags][4B stream_id & 0x7FFFFFFF][payload]

Types used:
    0x0  DATA
    0x1  HEADERS
    0x4  SETTINGS
    0x8  WINDOW_UPDATE

HEADERS flags:
    0x1  END_STREAM
    0x4  END_HEADERS

DATA flags:
    0x1  END_STREAM
"""

from __future__ import annotations

import struct

import hpack

# H2c connection preface — every client connection starts with this.
H2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_FRAME_TYPES = {
    "DATA": 0x0,
    "HEADERS": 0x1,
    "SETTINGS": 0x4,
    "WINDOW_UPDATE": 0x8,
}


def _frame(type_id: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    """Encode a single H2 frame."""
    length = len(payload)
    # 3-byte big-endian length
    header = struct.pack(">I", length)[1:]  # drop first byte → 3 bytes
    header += bytes([type_id, flags])
    header += struct.pack(">I", stream_id & 0x7FFFFFFF)
    return header + payload


def build_settings_frame(
    settings: dict[int, int] | None = None,
    stream_id: int = 0,
) -> bytes:
    """Build an empty or populated SETTINGS frame (type 0x4).

    Default: SETTINGS_MAX_HEADER_LIST_SIZE=65536 (param id 0x6).
    """
    if settings is None:
        settings = {0x6: 65536}
    payload = b""
    for key, val in settings.items():
        payload += struct.pack(">HI", key, val)
    return _frame(0x4, 0x0, stream_id, payload)


def build_settings_ack(stream_id: int = 0) -> bytes:
    """Build a SETTINGS ACK frame (type 0x4, flags 0x1)."""
    return _frame(0x4, 0x1, stream_id, b"")


def build_window_update(increment: int = 65535, stream_id: int = 0) -> bytes:
    """Build a WINDOW_UPDATE frame (type 0x8).

    ``stream_id=0`` updates the connection-level window.
    """
    payload = struct.pack(">I", increment & 0x7FFFFFFF)
    return _frame(0x8, 0x0, stream_id, payload)


def build_headers_frame(
    headers: list[tuple[str, str]],
    stream_id: int = 1,
    end_stream: bool = False,
    end_headers: bool = True,
    encoder: hpack.Encoder | None = None,
) -> bytes:
    """Build a HEADERS frame with HPACK-encoded header block.

    ``headers`` must include H2 pseudo-headers (:method, :path, etc.)
    before regular headers — callers are responsible for ordering.

    The encoder is NOT shared across calls by default so each frame
    gets a fresh context (no dynamic table dependency between requests).
    """
    if encoder is None:
        encoder = hpack.Encoder()
    block = encoder.encode(headers)
    flags = 0x0
    if end_stream:
        flags |= 0x1
    if end_headers:
        flags |= 0x4
    return _frame(0x1, flags, stream_id, block)


def build_padded_headers_frame(
    block: bytes,
    stream_id: int = 1,
    pad_length: int = 0,
    end_stream: bool = False,
    end_headers: bool = True,
) -> bytes:
    """Build a HEADERS frame with the PADDED flag (0x08) set.

    Wire layout when PADDED:
        [1B pad_length][HPACK block][pad_length zero bytes]

    ``pad_length`` is clamped to 0-255 and must leave room for the HPACK
    block within the frame payload.
    """
    pad_length = max(0, min(pad_length, 255))
    flags = 0x08  # PADDED
    if end_stream:
        flags |= 0x01
    if end_headers:
        flags |= 0x04
    payload = bytes([pad_length]) + block + b"\x00" * pad_length
    return _frame(0x1, flags, stream_id, payload)


def build_data_frame(
    data: bytes,
    stream_id: int = 1,
    end_stream: bool = True,
) -> bytes:
    """Build a DATA frame."""
    flags = 0x1 if end_stream else 0x0
    return _frame(0x0, flags, stream_id, data)


def build_h2_request(
    method: str,
    path: str,
    authority: str,
    body: bytes,
    extra_headers: list[tuple[str, str]] | None = None,
    stream_id: int = 1,
    scheme: str = "http",
) -> bytes:
    """Build a complete H2c message ready to send over a raw TCP socket.

    Returns:
        client preface + SETTINGS + WINDOW_UPDATE + HEADERS + DATA

    The SETTINGS and WINDOW_UPDATE establish a minimal connection context.
    The HEADERS frame contains all pseudo-headers + regular headers.
    The DATA frame carries the body with END_STREAM set.

    ``extra_headers`` are appended after the four required pseudo-headers.
    Use this to inject evasion headers (e.g. ``transfer-encoding: chunked``).
    """
    pseudo = [
        (":method", method),
        (":path", path),
        (":authority", authority),
        (":scheme", scheme),
    ]
    regular: list[tuple[str, str]] = []
    if extra_headers:
        regular.extend(extra_headers)
    if body:
        regular.append(("content-length", str(len(body))))

    encoder = hpack.Encoder()
    headers_frame = build_headers_frame(
        pseudo + regular,
        stream_id=stream_id,
        end_stream=(not body),
        end_headers=True,
        encoder=encoder,
    )

    parts: list[bytes] = [
        H2_CLIENT_PREFACE,
        build_settings_frame(),
        build_window_update(65535, stream_id=0),  # connection-level
        headers_frame,
    ]
    if body:
        parts.append(build_data_frame(body, stream_id=stream_id, end_stream=True))

    return b"".join(parts)


def build_h2_request_raw_headers(
    pseudo_headers: list[tuple[str, str]],
    regular_headers: list[tuple[str, str]],
    body: bytes,
    stream_id: int = 1,
) -> bytes:
    """Lower-level variant that gives full control over pseudo-headers.

    Use when a family needs to manipulate :path, :scheme, :authority
    directly (e.g. h2_pseudo_path_inject sets :path to a CRLF payload).
    """
    all_headers = pseudo_headers + regular_headers
    encoder = hpack.Encoder()
    headers_frame = build_headers_frame(
        all_headers,
        stream_id=stream_id,
        end_stream=(not body),
        end_headers=True,
        encoder=encoder,
    )

    parts: list[bytes] = [
        H2_CLIENT_PREFACE,
        build_settings_frame(),
        build_window_update(65535, stream_id=0),
        headers_frame,
    ]
    if body:
        parts.append(build_data_frame(body, stream_id=stream_id, end_stream=True))
    return b"".join(parts)


def build_continuation_frame(
    block: bytes,
    stream_id: int = 1,
    end_headers: bool = True,
) -> bytes:
    """Build a CONTINUATION frame (type 0x9).

    Must follow a HEADERS or PUSH_PROMISE frame that does not set END_HEADERS.
    ``end_headers=True`` sets the END_HEADERS (0x4) flag, closing the header
    block; False allows further CONTINUATION frames.
    """
    flags = 0x4 if end_headers else 0x0
    return _frame(0x9, flags, stream_id, block)


def parse_h2_response_frames(raw: bytes) -> list[tuple[int, int, int, bytes]]:
    """Parse raw H2 response bytes into a list of (type, flags, stream_id, payload).

    Best-effort: stops on truncated frame, returns what was successfully parsed.
    Skips the server connection preface if present.
    """
    frames: list[tuple[int, int, int, bytes]] = []
    pos = 0
    # Server preface is a SETTINGS frame (no magic string), but some
    # implementations include an upgrade response or similar — just scan.
    while pos + 9 <= len(raw):
        length = (raw[pos] << 16) | (raw[pos + 1] << 8) | raw[pos + 2]
        type_id = raw[pos + 3]
        flags = raw[pos + 4]
        stream_id = struct.unpack(">I", raw[pos + 5: pos + 9])[0] & 0x7FFFFFFF
        payload_end = pos + 9 + length
        if payload_end > len(raw):
            break  # truncated
        payload = raw[pos + 9: payload_end]
        frames.append((type_id, flags, stream_id, payload))
        pos = payload_end
    return frames


def decode_response_status(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    """Extract (status_code, response_headers, body) from raw H2 response bytes.

    Returns (-1, {}, b"") on parse failure.
    """
    frames = parse_h2_response_frames(raw)
    dec = hpack.Decoder()
    status = -1
    resp_headers: dict[str, str] = {}
    body_parts: list[bytes] = []

    for type_id, _flags, _stream_id, payload in frames:
        if type_id == 0x1:  # HEADERS
            try:
                hdrs = dec.decode(payload)
                for name, value in hdrs:
                    if name == ":status":
                        try:
                            status = int(value)
                        except ValueError:
                            pass
                    else:
                        resp_headers[name] = value
            except Exception:
                pass
        elif type_id == 0x0:  # DATA
            body_parts.append(payload)

    return status, resp_headers, b"".join(body_parts)
