"""Tests for H2GrammarTranslator — structured text → binary H2 wire."""

from __future__ import annotations

import pytest

from webfuzzer.fuzzer.mutators.h2_frames import (
    H2_CLIENT_PREFACE,
    parse_h2_response_frames,
)
from webfuzzer.fuzzer.mutators.h2_grammar_translator import H2GrammarTranslator


class TestH2GrammarTranslator:
    def test_simple_sequence_produces_valid_h2(self):
        text = (
            "H2SEQ\n"
            ":method POST\n"
            ":path /api/test\n"
            ":authority target.local\n"
            ":scheme http\n"
            "content-type: application/json\n"
            "---BODY---\n"
            '{"key":"value"}\n'
        )
        wire = H2GrammarTranslator().translate(text)
        assert wire.startswith(H2_CLIENT_PREFACE)
        frames = parse_h2_response_frames(wire[len(H2_CLIENT_PREFACE):])
        types = [f[0] for f in frames]
        assert 0x4 in types  # SETTINGS
        assert 0x1 in types  # HEADERS
        assert 0x0 in types  # DATA

    def test_continuation_split(self):
        text = (
            "H2SEQ\n"
            ":method POST\n"
            ":path /api/test\n"
            ":authority target.local\n"
            ":scheme http\n"
            "content-type: application/x-www-form-urlencoded\n"
            "x-long-header: " + "A" * 200 + "\n"
            "---SPLIT 2---\n"
            "---BODY---\n"
            "data=test\n"
        )
        wire = H2GrammarTranslator().translate(text)
        assert wire.startswith(H2_CLIENT_PREFACE)
        frames = parse_h2_response_frames(wire[len(H2_CLIENT_PREFACE):])
        types = [f[0] for f in frames]
        assert 0x9 in types  # CONTINUATION frame present

    def test_trailer_section(self):
        text = (
            "H2SEQ\n"
            ":method POST\n"
            ":path /api/test\n"
            ":authority target.local\n"
            ":scheme http\n"
            "---BODY---\n"
            "data=test\n"
            "---TRAILER---\n"
            "x-trailer: value\n"
        )
        wire = H2GrammarTranslator().translate(text)
        frames = parse_h2_response_frames(wire[len(H2_CLIENT_PREFACE):])
        # Should have 2 HEADERS frames: main + trailer
        headers_frames = [f for f in frames if f[0] == 0x1]
        assert len(headers_frames) == 2

    def test_custom_stream_id(self):
        text = (
            "H2SEQ\n"
            ":method GET\n"
            ":path /test\n"
            ":authority target.local\n"
            ":scheme http\n"
            ":stream 5\n"
        )
        wire = H2GrammarTranslator().translate(text)
        frames = parse_h2_response_frames(wire[len(H2_CLIENT_PREFACE):])
        headers = [f for f in frames if f[0] == 0x1]
        assert len(headers) == 1
        # stream_id is 3rd element (index 2)
        assert headers[0][2] == 5

    def test_invalid_input_raises(self):
        with pytest.raises(ValueError, match="H2SEQ"):
            H2GrammarTranslator().translate("NOT_H2SEQ\ngarbage")

    def test_no_body_sets_end_stream(self):
        text = (
            "H2SEQ\n"
            ":method GET\n"
            ":path /health\n"
            ":authority target.local\n"
            ":scheme http\n"
        )
        wire = H2GrammarTranslator().translate(text)
        frames = parse_h2_response_frames(wire[len(H2_CLIENT_PREFACE):])
        headers = [f for f in frames if f[0] == 0x1]
        assert len(headers) == 1
        # flags should include END_STREAM(0x1) and END_HEADERS(0x4) = 0x5
        assert headers[0][1] == 0x05
