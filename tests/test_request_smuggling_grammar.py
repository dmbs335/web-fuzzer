"""Tests for the request smuggling stream grammar."""

from webfuzzer.core.generator import Generator
from webfuzzer.core.registry import GrammarRegistry


def _build_generator(seed: int = 42) -> Generator:
    registry = GrammarRegistry()
    registry.load_builtins()
    return Generator(registry, seed=seed)


def test_request_smuggling_stream_grammar_loaded():
    gen = _build_generator()
    assert "request_smuggling_stream" in gen.registry


def test_root_generation_contains_two_requests_and_control_headers():
    gen = _build_generator(seed=7)
    result = gen.generate("request_smuggling_stream")
    assert result.count("HTTP/1.1") >= 2
    assert "X-WF-Family:" in result
    assert "X-WF-Canary-Path: /__canary__/grammar" in result
    assert "GET /__canary__/grammar HTTP/1.1" in result


def test_trailer_merge_rule_generates_trailer_override():
    gen = _build_generator()
    result = gen.generate("request_smuggling_stream", "trailer_merge_stream")
    assert "POST /cache/store HTTP/1.1" in result
    assert "Trailer: X-Original-URL, X-Trailer-Canary" in result
    assert "X-Original-URL: /front-cache/base" in result
    assert "X-Original-URL: /trailer-cache/grammar" in result
    assert "X-Trailer-Canary: merged" in result
    assert result.count("HTTP/1.1") >= 2


def test_trailer_header_rule_generates_host_override_trailers():
    gen = _build_generator()
    result = gen.generate("request_smuggling_stream", "trailer_header_stream")
    assert "POST /admin/panel HTTP/1.1" in result
    assert "Trailer: Host, X-Forwarded-Host" in result
    assert "Host: trailer-grammar.invalid" in result
    assert "X-Forwarded-Host: trailer-grammar.invalid" in result


def test_zero_cl_rule_uses_obfuscated_content_length_header():
    gen = _build_generator()
    result = gen.generate("request_smuggling_stream", "zero_cl_stream")
    assert "GET /reflect/prefix HTTP/1.1" in result
    assert "Content-Length : 11" in result
    assert "SMUGGLED=1" in result


def test_chunk_bare_lf_rule_uses_bare_lf_delimiters():
    gen = _build_generator()
    result = gen.generate("request_smuggling_stream", "chunk_bare_lf_stream")
    assert "\r\n" not in result
    assert "\n\n" in result
    assert "Transfer-Encoding: chunked" in result


def test_baseline_stream_rule_generates_well_formed_single_request():
    gen = _build_generator()
    result = gen.generate("request_smuggling_stream", "baseline_stream")
    assert result.startswith("POST /queue/append HTTP/1.1\r\n")
    assert "Content-Length: 13" in result
    assert result.endswith("seed=baseline")
