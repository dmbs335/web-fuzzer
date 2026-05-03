"""Unit tests for the H2 binary frame encoder (webfuzzer.fuzzer.mutators.h2_frames)."""

from __future__ import annotations

import struct

import pytest

from webfuzzer.fuzzer.mutators.h2_frames import (
    H2_CLIENT_PREFACE,
    build_data_frame,
    build_h2_request,
    build_h2_request_raw_headers,
    build_headers_frame,
    build_settings_frame,
    build_window_update,
    decode_response_status,
    parse_h2_response_frames,
)


# ---------------------------------------------------------------------------
# Preface
# ---------------------------------------------------------------------------


def test_preface_bytes() -> None:
    assert H2_CLIENT_PREFACE == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    assert len(H2_CLIENT_PREFACE) == 24


# ---------------------------------------------------------------------------
# Frame layout helpers
# ---------------------------------------------------------------------------


def _read_frame(data: bytes, pos: int = 0) -> tuple[int, int, int, bytes]:
    """Parse one frame at *pos*, return (type_id, flags, stream_id, payload)."""
    length = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2]
    type_id = data[pos + 3]
    flags = data[pos + 4]
    stream_id = struct.unpack(">I", data[pos + 5:pos + 9])[0] & 0x7FFFFFFF
    payload = data[pos + 9:pos + 9 + length]
    return type_id, flags, stream_id, payload


# ---------------------------------------------------------------------------
# SETTINGS frame
# ---------------------------------------------------------------------------


def test_settings_frame_type() -> None:
    frame = build_settings_frame()
    assert frame[3] == 0x4, "SETTINGS frame type must be 0x4"


def test_settings_frame_stream_id_zero() -> None:
    frame = build_settings_frame()
    stream_id = struct.unpack(">I", frame[5:9])[0] & 0x7FFFFFFF
    assert stream_id == 0


def test_settings_frame_default_payload() -> None:
    frame = build_settings_frame()
    # Default: SETTINGS_MAX_HEADER_LIST_SIZE (0x6) = 65536
    type_id, flags, stream_id, payload = _read_frame(frame)
    assert type_id == 0x4
    assert len(payload) == 6  # one setting: 2B id + 4B value
    key, val = struct.unpack(">HI", payload)
    assert key == 0x6
    assert val == 65536


# ---------------------------------------------------------------------------
# HEADERS frame — HPACK roundtrip
# ---------------------------------------------------------------------------


def test_headers_frame_hpack_roundtrip() -> None:
    import hpack

    headers = [
        (":method", "POST"),
        (":path", "/submit"),
        (":authority", "example.com"),
        (":scheme", "http"),
        ("content-type", "application/json"),
    ]
    frame = build_headers_frame(headers, stream_id=1, end_headers=True)
    type_id, flags, stream_id, payload = _read_frame(frame)
    assert type_id == 0x1, "HEADERS frame type must be 0x1"
    assert flags & 0x4, "END_HEADERS flag (0x4) must be set"
    assert stream_id == 1

    dec = hpack.Decoder()
    decoded = dict(dec.decode(payload))
    assert decoded[":method"] == "POST"
    assert decoded[":path"] == "/submit"
    assert decoded[":authority"] == "example.com"


def test_headers_frame_end_stream_flag() -> None:
    headers = [(":method", "GET"), (":path", "/"), (":authority", "x"), (":scheme", "http")]
    frame = build_headers_frame(headers, end_stream=True, end_headers=True)
    _, flags, _, _ = _read_frame(frame)
    assert flags & 0x1, "END_STREAM flag (0x1) must be set when end_stream=True"


# ---------------------------------------------------------------------------
# DATA frame
# ---------------------------------------------------------------------------


def test_data_frame_end_stream() -> None:
    payload = b"hello"
    frame = build_data_frame(payload, stream_id=1, end_stream=True)
    type_id, flags, stream_id, data = _read_frame(frame)
    assert type_id == 0x0, "DATA frame type must be 0x0"
    assert flags == 0x1, "END_STREAM flag must be 0x1"
    assert data == payload


def test_data_frame_no_end_stream() -> None:
    frame = build_data_frame(b"chunk", stream_id=1, end_stream=False)
    _, flags, _, _ = _read_frame(frame)
    assert flags == 0x0


# ---------------------------------------------------------------------------
# build_h2_request — structure
# ---------------------------------------------------------------------------


def test_build_h2_request_starts_with_preface() -> None:
    wire = build_h2_request("GET", "/", "host.local", b"")
    assert wire.startswith(H2_CLIENT_PREFACE)


def test_build_h2_request_contains_settings_and_headers() -> None:
    wire = build_h2_request("POST", "/api", "host.local", b"data=1")
    # After preface: SETTINGS (type 0x4), WINDOW_UPDATE (type 0x8), HEADERS (type 0x1), DATA (type 0x0)
    pos = len(H2_CLIENT_PREFACE)
    frame_types = []
    while pos + 9 <= len(wire):
        length = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2]
        frame_types.append(wire[pos + 3])
        pos += 9 + length
    assert 0x4 in frame_types, "SETTINGS frame missing"
    assert 0x1 in frame_types, "HEADERS frame missing"
    assert 0x0 in frame_types, "DATA frame missing"


def test_build_h2_request_no_body_no_data_frame() -> None:
    wire = build_h2_request("GET", "/", "host.local", b"")
    pos = len(H2_CLIENT_PREFACE)
    frame_types = []
    while pos + 9 <= len(wire):
        length = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2]
        frame_types.append(wire[pos + 3])
        pos += 9 + length
    assert 0x0 not in frame_types, "no DATA frame expected for empty body"


# ---------------------------------------------------------------------------
# build_h2_request_raw_headers
# ---------------------------------------------------------------------------


def test_build_h2_request_raw_headers_roundtrip() -> None:
    import hpack

    pseudo = [(":method", "POST"), (":path", "/raw"), (":authority", "x"), (":scheme", "http")]
    regular = [("content-length", "5")]
    body = b"hello"
    wire = build_h2_request_raw_headers(pseudo, regular, body)
    assert wire.startswith(H2_CLIENT_PREFACE)
    # Find HEADERS frame and decode
    pos = len(H2_CLIENT_PREFACE)
    while pos + 9 <= len(wire):
        length = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2]
        type_id = wire[pos + 3]
        if type_id == 0x1:
            payload = wire[pos + 9:pos + 9 + length]
            dec = hpack.Decoder()
            hdrs = dict(dec.decode(payload))
            assert hdrs[":method"] == "POST"
            assert hdrs["content-length"] == "5"
            break
        pos += 9 + length


# ---------------------------------------------------------------------------
# parse_h2_response_frames
# ---------------------------------------------------------------------------


def test_parse_h2_response_frames_empty() -> None:
    assert parse_h2_response_frames(b"") == []


def test_parse_h2_response_frames_truncated() -> None:
    # A 9-byte header with length=100 but only 5 payload bytes
    partial = b"\x00\x00\x64\x01\x04\x00\x00\x00\x01" + b"x" * 5
    result = parse_h2_response_frames(partial)
    assert result == []


def test_parse_h2_response_frames_roundtrip() -> None:
    settings = build_settings_frame()
    window = build_window_update(65535, stream_id=0)
    combined = settings + window
    frames = parse_h2_response_frames(combined)
    assert len(frames) == 2
    assert frames[0][0] == 0x4  # SETTINGS
    assert frames[1][0] == 0x8  # WINDOW_UPDATE
