"""Translate H2 frame sequence text (from grammar) to binary H2 wire format.

Follows the pgsql_wire_session pattern: grammar produces structured text,
translator converts to binary protocol frames using h2_frames.py builders.

H2SEQ text format::

    H2SEQ
    :method POST
    :path /api/data
    :authority target.local
    :scheme http
    content-type: application/x-www-form-urlencoded
    x-injection: <script>alert(1)</script>
    ---SPLIT 2---
    x-extra: value
    ---BODY---
    canary=C123&data=test
    ---TRAILER---
    x-trailer-inject: payload

Directives:
    ``:stream N``   — set stream ID (default 1)
    ``---SPLIT N---``  — split HPACK block into N+1 CONTINUATION frames
    ``---BODY---``  — begin DATA frame body
    ``---TRAILER---`` — begin trailing HEADERS frame
"""

from __future__ import annotations

import re

import hpack

from .h2_frames import (
    H2_CLIENT_PREFACE,
    _frame,
    build_continuation_frame,
    build_data_frame,
    build_settings_frame,
    build_window_update,
)

_SPLIT_RE = re.compile(r"---SPLIT\s+(\d+)---")


class H2GrammarTranslator:
    """Parse H2SEQ text format and produce binary H2c wire bytes."""

    def translate(self, text: str) -> bytes:
        """Convert grammar-generated H2SEQ text to binary H2 frame sequence.

        Returns raw bytes: preface + SETTINGS + WINDOW_UPDATE + frame sequence.
        Raises ``ValueError`` on unparseable input.
        """
        lines = text.strip().split("\n")
        if not lines or lines[0].strip() != "H2SEQ":
            raise ValueError("H2SEQ marker not found")

        pseudo: list[tuple[str, str]] = []
        regular: list[tuple[str, str]] = []
        body_parts: list[bytes] = []
        trailer_headers: list[tuple[str, str]] = []
        stream_id: int = 1
        split_count: int = 0

        section = "headers"  # headers → body → trailer

        for raw_line in lines[1:]:
            line = raw_line.strip()
            if not line:
                continue

            # Section markers
            m = _SPLIT_RE.match(line)
            if m:
                split_count = int(m.group(1))
                continue
            if line == "---BODY---":
                section = "body"
                continue
            if line == "---TRAILER---":
                section = "trailer"
                continue

            if section == "headers":
                if line.startswith(":stream "):
                    stream_id = int(line.split(" ", 1)[1])
                elif line.startswith(":"):
                    name, _, value = line.partition(" ")
                    pseudo.append((name, value))
                else:
                    name, _, value = line.partition(": ")
                    if name:
                        regular.append((name, value))
            elif section == "body":
                body_parts.append(line.encode("utf-8", errors="replace"))
            elif section == "trailer":
                name, _, value = line.partition(": ")
                if name:
                    trailer_headers.append((name, value))

        # ── Encode ───────────────────────────────────────────────────
        enc = hpack.Encoder()
        all_headers = pseudo + regular
        block = enc.encode(all_headers)

        body_data = b"".join(body_parts)
        has_body = bool(body_data)
        has_trailers = bool(trailer_headers)

        frame_seq: list[bytes] = []

        # ── HEADERS / CONTINUATION ───────────────────────────────────
        if split_count > 0 and len(block) > 4:
            chunk_size = max(1, len(block) // (split_count + 1))
            chunks = [block[i:i + chunk_size]
                      for i in range(0, len(block), chunk_size)]
            flags_h = 0x00
            if not has_body and not has_trailers:
                flags_h |= 0x01  # END_STREAM
            frame_seq.append(_frame(0x1, flags_h, stream_id, chunks[0]))
            for i, chunk in enumerate(chunks[1:]):
                is_last = (i == len(chunks) - 2)
                frame_seq.append(
                    build_continuation_frame(
                        chunk, stream_id=stream_id, end_headers=is_last,
                    ),
                )
        else:
            flags_h = 0x04  # END_HEADERS
            if not has_body and not has_trailers:
                flags_h |= 0x01  # END_STREAM
            frame_seq.append(_frame(0x1, flags_h, stream_id, block))

        # ── DATA ─────────────────────────────────────────────────────
        if has_body:
            data_end_stream = not has_trailers
            frame_seq.append(
                build_data_frame(
                    body_data, stream_id=stream_id, end_stream=data_end_stream,
                ),
            )

        # ── Trailer HEADERS ──────────────────────────────────────────
        if has_trailers:
            trailer_block = enc.encode(trailer_headers)
            # END_STREAM(0x1) | END_HEADERS(0x4) = 0x5
            frame_seq.append(_frame(0x1, 0x05, stream_id, trailer_block))

        # ── Assemble ─────────────────────────────────────────────────
        parts = [
            H2_CLIENT_PREFACE,
            build_settings_frame(),
            build_window_update(65535, stream_id=0),
            *frame_seq,
        ]
        return b"".join(parts)
