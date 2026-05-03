import json

from webfuzzer.fuzzer.oracles.waf_bypass_diff_strategy import (
    WafBypassStrategy,
    WafPartialBypassStrategy,
    WafEvasionStrategy,
    ContentTypeConfusionStrategy,
    EncodingBypassStrategy,
    MultipartBoundaryStrategy,
    HeaderNormalizationStrategy,
    UrlNormalizationStrategy,
    CharsetConfusionStrategy,
    HPPStrategy,
    BodyBoundaryMismatchStrategy,
    XmlContentStrategy,
    H2DowngradeStrategy,
    RfcParserQuirkStrategy,
    get_waf_bypass_strategies,
    _is_waf_block,
    _is_payload_reflected,
    _waf_interpretation,
    _difference_fields,
    _diff_pattern_hash,
    _is_preamble_family,
    _has_no_behavioral_divergence,
    _extract_header,
    _extract_query_params,
    _extract_body_params,
    _extract_body_boundary,
)
from webfuzzer.fuzzer.protocols import ExecutionResult, Input, Severity


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(exit_code=exit_code, stdout=json.dumps(data).encode())


BASE_WAF = {
    "response_status": 200,
    "waf_blocked": False,
    "waf_block_reason": "",
    "waf_score": 0,
    "backend_reached": True,
    "backend_status": 200,
    "payload_reflected": False,
    "canary_in_body": False,
    "canary_in_headers": False,
    "content_type_sent": "application/x-www-form-urlencoded",
    "content_type_parsed": "application/x-www-form-urlencoded",
    "encoding_applied": "none",
    "encoding_depth": 0,
    "charset_sent": "utf-8",
    "charset_detected": "utf-8",
    "waf_headers": "",
    "normalized_path": "/reflect",
    "original_path": "/reflect",
    "host_header": "target.local",
    "x_forwarded_for": "",
    "payload_type": "xss",
    "technique_family": "ct_duplicate",
    "mutation_lane": "content_type_confusion",
    "encoding_chain": "",
    "boundary_used": "",
    "boundary_parsed": "",
    "part_count": 0,
    "nested_multipart": False,
    "bypass_detected": False,
    "request_id": "test-001",
    "variant_family": "ct_duplicate",
    "canary_marker": "WF-CANARY-test00001",
    "duration_ms": 5.0,
    "response_body_prefix": "",
    "response_body_crc32": 0,
    "response_body_length": 0,
    "waf_block_status": None,
    "waf_signature": "",
    "backend_marker": "reached",
    "connection_closed": False,
    "timeout_phase": None,
    "parse_error": None,
    "request_bytes_sent": 256,
    "url_path": "/reflect",
    "url_path_raw": "/reflect",
    "path_normalized": "/reflect",
    "path_raw": "/reflect",
    "headers_normalized": False,
    "payload_in_header": False,
    "header_count": 5,
    "body_structure": "form",
    "lt_type": "crlf",
    "has_null_bytes": False,
    "applied_transforms": [],
    "chain_depth": 0,
    "chain_layers": "",
    "technique_family": "unknown",
    "ct_count": 1,
    "cl_te_conflict": False,
    "charset_declared": "",
    "has_trailers": False,
    "trailer_names": "",
    "duplicate_cl": False,
    "duplicate_te": False,
    "chunk_quirk_type": "",
    "zero_body_type": "",
    "http_version": "HTTP/1.1",
    "method_override": "",
    "te_variation": "",
    "xml_variant": "",
    "json_quirk_type": "",
    "enc_overflow_type": "",
    "transport_mode": "",
    "h2_variant": "",
}


class TestWafBypassStrategies:
    def test_waf_bypass_full_critical(self):
        """WAF passed + payload reflected + ref blocked = CRITICAL bypass."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "bypass_detected": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "waf_blocked": True,
            "response_status": 403,
            "payload_reflected": False,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "waf_bypass_full"
        assert finding.metadata["diff_pattern_hash"]

    def test_waf_blocked_returns_none(self):
        """When WAF blocks the request, no bypass finding."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": True,
            "response_status": 403,
            "payload_reflected": False,
        })
        reference = _make_result({
            **BASE_WAF,
            "payload_reflected": True,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_partial_bypass_high(self):
        """WAF passed, canary seen but payload sanitized + ref blocked = HIGH."""
        strat = WafPartialBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": False,
            "canary_in_body": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "waf_blocked": True,
            "response_status": 403,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "waf_bypass_partial"

    def test_content_type_confusion_medium(self):
        """Content-Type mismatch between sent and parsed = MEDIUM."""
        strat = ContentTypeConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "content_type_sent": "text/plain",
            "content_type_parsed": "application/x-www-form-urlencoded",
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "payload_reflected": True,
            "content_type_sent": "text/plain",
            "content_type_parsed": "application/x-www-form-urlencoded",
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_content_type"

    def test_encoding_bypass_medium(self):
        """Encoding depth > 0 and WAF passed = MEDIUM."""
        strat = EncodingBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "encoding_depth": 2,
            "encoding_applied": "gzip",
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "payload_reflected": True,
            "encoding_depth": 0,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_encoding"

    def test_multipart_boundary_medium(self):
        """Boundary mismatch = MEDIUM."""
        strat = MultipartBoundaryStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "boundary_used": '"wf-boundary"',
            "boundary_parsed": "wf-boundary",
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "payload_reflected": True,
            "boundary_used": '"wf-boundary"',
            "boundary_parsed": "wf-boundary",
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_multipart"

    def test_strategy_set(self):
        """All 14 strategies returned by factory."""
        strategies = get_waf_bypass_strategies()
        assert len(strategies) == 14
        names = {s.name for s in strategies}
        expected = {
            "waf_bypass_full", "waf_bypass_partial", "waf_bypass_evasion",
            "waf_bypass_content_type", "waf_bypass_encoding",
            "waf_bypass_multipart", "waf_bypass_header_norm",
            "waf_bypass_url_norm", "waf_bypass_charset",
            "waf_bypass_hpp", "waf_bypass_body_boundary",
            "waf_bypass_xml", "waf_bypass_h2_downgrade",
            "waf_bypass_rfc_quirk",
        }
        assert names == expected


class TestWafBypassHelpers:
    def test_is_waf_block_true(self):
        assert _is_waf_block({"waf_blocked": True, "response_status": 403}) is True

    def test_is_waf_block_false(self):
        assert _is_waf_block({"waf_blocked": False, "response_status": 200}) is False

    def test_is_waf_block_status_based(self):
        assert _is_waf_block({"waf_blocked": False, "response_status": 403}) is True

    def test_is_payload_reflected_true(self):
        assert _is_payload_reflected({"payload_reflected": True, "canary_in_body": False}) is True

    def test_is_payload_reflected_canary(self):
        assert _is_payload_reflected({"payload_reflected": False, "canary_in_body": True}) is True

    def test_is_payload_reflected_false(self):
        assert _is_payload_reflected({"payload_reflected": False, "canary_in_body": False}) is False

    def test_waf_interpretation_blocked(self):
        assert _waf_interpretation({"waf_blocked": True, "response_status": 403}) == "blocked"

    def test_waf_interpretation_passed(self):
        assert _waf_interpretation({"waf_blocked": False, "response_status": 200, "payload_reflected": True}) == "passed"

    def test_waf_interpretation_unknown(self):
        """No reflection, no backend_reached, not blocked → unknown."""
        assert _waf_interpretation({"waf_blocked": False, "response_status": 200}) == "unknown"

    def test_waf_interpretation_none(self):
        assert _waf_interpretation(None) == "no_output"

    def test_diff_pattern_hash_varies_by_payload_type(self):
        h1 = _diff_pattern_hash(
            bypass_type="full", payload_type="xss",
            technique_family="ct_duplicate", waf_response="passed",
            backend_response="reflected", ref_index=0,
            diff_fields=["payload_reflected"],
        )
        h2 = _diff_pattern_hash(
            bypass_type="full", payload_type="sqli",
            technique_family="ct_duplicate", waf_response="passed",
            backend_response="reflected", ref_index=0,
            diff_fields=["payload_reflected"],
        )
        assert h1 != h2

    def test_diff_pattern_hash_varies_by_technique(self):
        h1 = _diff_pattern_hash(
            bypass_type="full", payload_type="xss",
            technique_family="ct_duplicate", waf_response="passed",
            backend_response="reflected", ref_index=0,
            diff_fields=["payload_reflected"],
        )
        h2 = _diff_pattern_hash(
            bypass_type="full", payload_type="xss",
            technique_family="mp_boundary_spoof", waf_response="passed",
            backend_response="reflected", ref_index=0,
            diff_fields=["payload_reflected"],
        )
        assert h1 != h2

    def test_difference_fields_detects_changes(self):
        p = {**BASE_WAF, "payload_reflected": True}
        r = {**BASE_WAF, "payload_reflected": False}
        fields = _difference_fields(p, r)
        assert "payload_reflected" in fields

    def test_difference_fields_no_changes(self):
        fields = _difference_fields(BASE_WAF, BASE_WAF)
        assert len(fields) == 0


class TestWafBypassV2Enrichment:
    """Tests for v2 enrichment fields and severity adjustments."""

    def test_ct_confusion_fires_with_enrichment(self):
        """Content-Type mismatch with enriched fields → MEDIUM."""
        strat = ContentTypeConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "content_type_sent": "multipart/form-data; boundary=abc",
            "content_type_parsed": "application/x-www-form-urlencoded",
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "content_type_sent": "multipart/form-data; boundary=abc",
            "content_type_parsed": "multipart/form-data; boundary=abc",
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_encoding_bypass_fires(self):
        """encoding_depth > 0 + reflected → MEDIUM."""
        strat = EncodingBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "encoding_depth": 2,
        })
        reference = _make_result({**BASE_WAF, "response_status": 400, "payload_reflected": True})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_encoding"

    def test_multipart_boundary_fires(self):
        """boundary_used ≠ boundary_parsed → MEDIUM."""
        strat = MultipartBoundaryStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "boundary_used": "----WebKitFormBoundary",
            "boundary_parsed": "WebKitFormBoundary",
        })
        reference = _make_result({**BASE_WAF, "response_status": 400})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_multipart"

    def test_url_normalization_fires(self):
        """url_path ≠ path_normalized + ref blocked → MEDIUM."""
        strat = UrlNormalizationStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "url_path": "/safe/../admin",
            "url_path_raw": "/safe/../admin",
            "path_normalized": "/admin",
            "path_raw": "/safe/../admin",
            "backend_reached": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "waf_blocked": True,
            "response_status": 403,
            "url_path": "/safe/../admin",
            "url_path_raw": "/safe/../admin",
            "path_normalized": "/safe/../admin",
            "path_raw": "/safe/../admin",
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_url_norm"

    def test_waf_evasion_fires(self):
        """base_payload_blocked=True + encoded bypasses + ref blocked → HIGH."""
        strat = WafEvasionStrategy()
        inp = Input(data=b"x", metadata={"base_payload_blocked": True})
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "canary_in_body": True,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": True, "response_status": 403})
        finding = strat.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "waf_bypass_evasion"

    def test_header_norm_fires_with_enrichment(self):
        """headers_normalized divergence + ref blocked → MEDIUM."""
        strat = HeaderNormalizationStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "headers_normalized": True,
            "payload_in_header": True,
            "canary_in_headers": True,
            "backend_reached": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "waf_blocked": True,
            "response_status": 403,
            "headers_normalized": False,
            "payload_in_header": False,
            "canary_in_headers": False,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_header_norm"

    def test_bypass_severity_downgrade_400(self):
        """Full bypass with status=400 + ref blocked → HIGH (not CRITICAL)."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "waf_blocked": False,
            "payload_reflected": True,
            "bypass_detected": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "waf_blocked": True,
            "response_status": 403,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_partial_bypass_severity_downgrade_400(self):
        """Partial bypass with status=400 + ref blocked → MEDIUM (not HIGH)."""
        strat = WafPartialBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "waf_blocked": False,
            "payload_reflected": False,
            "canary_in_body": True,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": True, "response_status": 403})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM


class TestH2DowngradeStrategy:
    """Tests for the H2 → H1 downgrade smuggling strategy."""

    def test_h2_downgrade_strategy_fires(self):
        """H2c transport + h2_variant + backend reached + ref blocked → MEDIUM finding."""
        strat = H2DowngradeStrategy()
        primary = _make_result({
            **BASE_WAF,
            "transport_mode": "h2c",
            "h2_variant": "cl_zero_body",
            "backend_reached": True,
            "waf_blocked": False,
            "payload_reflected": False,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": True, "response_status": 403})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert "cl_zero_body" in finding.title

    def test_h2_downgrade_high_when_payload_reflected(self):
        """H2c bypass with payload reflection → HIGH."""
        strat = H2DowngradeStrategy()
        primary = _make_result({
            **BASE_WAF,
            "transport_mode": "h2c",
            "h2_variant": "header_crlf",
            "backend_reached": True,
            "waf_blocked": False,
            "payload_reflected": True,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": True, "response_status": 403})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_h2_downgrade_requires_h2c_transport(self):
        """No H2c transport → no finding (H1 request)."""
        strat = H2DowngradeStrategy()
        primary = _make_result({
            **BASE_WAF,
            "transport_mode": "",
            "h2_variant": "header_crlf",
            "backend_reached": True,
            "waf_blocked": False,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": True, "response_status": 403})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_h2_downgrade_requires_h2_variant(self):
        """H2c transport but no h2_variant → no finding."""
        strat = H2DowngradeStrategy()
        primary = _make_result({
            **BASE_WAF,
            "transport_mode": "h2c",
            "h2_variant": "",
            "backend_reached": True,
            "waf_blocked": False,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": True, "response_status": 403})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_h2_downgrade_waf_blocked_suppressed(self):
        """WAF blocked the H2 request → no finding."""
        strat = H2DowngradeStrategy()
        primary = _make_result({
            **BASE_WAF,
            "transport_mode": "h2c",
            "h2_variant": "te_forbidden",
            "backend_reached": False,
            "waf_blocked": True,
            "response_status": 403,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": True, "response_status": 403})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_h2_downgrade_requires_ref_blocked(self):
        """Reference not blocked → no finding (no differential signal)."""
        strat = H2DowngradeStrategy()
        primary = _make_result({
            **BASE_WAF,
            "transport_mode": "h2c",
            "h2_variant": "cl_zero_body",
            "backend_reached": True,
            "waf_blocked": False,
        })
        reference = _make_result({**BASE_WAF, "waf_blocked": False, "response_status": 200})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None


class TestRfcParserQuirkStrategy:
    """Tests for the RFC parser specification quirk strategy."""

    def test_rfc_quirk_strategy_fires(self):
        """RFC quirk technique + backend_reached + WAF passed → MEDIUM finding."""
        strat = RfcParserQuirkStrategy()
        inp = Input(data=b"x", metadata={"technique_family": "rfc_trailer_inject"})
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "payload_reflected": False,
        })
        reference = _make_result({**BASE_WAF, "response_status": 400, "waf_blocked": True})
        finding = strat.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_rfc_quirk"
        assert "rfc_trailer_inject" in finding.title

    def test_rfc_quirk_high_when_payload_reflected(self):
        """RFC quirk bypass with payload reflected → HIGH."""
        strat = RfcParserQuirkStrategy()
        inp = Input(data=b"x", metadata={"technique_family": "rfc_param_continuation"})
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "payload_reflected": True,
        })
        reference = _make_result({**BASE_WAF, "response_status": 400, "waf_blocked": True})
        finding = strat.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_rfc_quirk_requires_backend_reached(self):
        """backend_reached=False → no finding."""
        strat = RfcParserQuirkStrategy()
        inp = Input(data=b"x", metadata={"technique_family": "rfc_vt_ff_separator"})
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": False,
            "payload_reflected": True,
        })
        reference = _make_result({**BASE_WAF, "response_status": 400, "waf_blocked": True})
        finding = strat.compare(inp, primary, reference, 0)
        assert finding is None

    def test_rfc_quirk_requires_rfc_technique(self):
        """Non-RFC technique → strategy does not fire."""
        strat = RfcParserQuirkStrategy()
        inp = Input(data=b"x", metadata={"technique_family": "ct_duplicate"})
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "payload_reflected": True,
        })
        reference = _make_result({**BASE_WAF, "response_status": 400, "waf_blocked": True})
        finding = strat.compare(inp, primary, reference, 0)
        assert finding is None

    def test_all_7_rfc_families_trigger_strategy(self):
        """Every rfc_spec_quirks family name fires the strategy."""
        strat = RfcParserQuirkStrategy()
        families = [
            "rfc_vt_ff_separator", "rfc_absolute_target", "rfc_trailer_inject",
            "rfc_param_continuation", "rfc_obs_text_header", "rfc_method_case",
            "rfc_host_case",
        ]
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "payload_reflected": False,
        })
        reference = _make_result({**BASE_WAF, "response_status": 400, "waf_blocked": True})
        for fam in families:
            inp = Input(data=b"x", metadata={"technique_family": fam})
            finding = strat.compare(inp, primary, reference, 0)
            assert finding is not None, f"strategy should fire for {fam}"


class TestFPSuppression:
    """Tests for false-positive suppression guards."""

    def test_preamble_family_suppressed_full(self):
        """mp_preamble_payload → no finding (RFC 2046: backend ignores preamble)."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "technique_family": "mp_preamble_payload",
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "payload_reflected": True,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_epilogue_family_suppressed_partial(self):
        """mp_epilogue_payload → no finding (RFC 2046: backend ignores epilogue)."""
        strat = WafPartialBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": False,
            "canary_in_body": True,
            "technique_family": "mp_epilogue_payload",
        })
        reference = _make_result({**BASE_WAF, "response_status": 400})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_preamble_from_input_metadata(self):
        """Preamble family from input metadata also suppressed."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "payload_reflected": True,
        })
        inp = Input(data=b"x", metadata={"technique_family": "mp_preamble_payload"})
        finding = strat.compare(inp, primary, reference, 0)
        assert finding is None

    def test_identical_behavior_no_bypass(self):
        """Both targets pass and reflect → no differential signal → no finding."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_ct_confusion_reported_despite_identical_status(self):
        """CT mismatch is a structural finding even when behavioral outcome
        matches — WAF parsed body with wrong content type."""
        strat = ContentTypeConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "content_type_sent": "text/plain",
            "content_type_parsed": "application/x-www-form-urlencoded",
        })
        reference = _make_result({
            **BASE_WAF,
            "content_type_sent": "text/plain",
            "content_type_parsed": "text/plain",
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_divergence_not_suppressed(self):
        """Different status → finding NOT suppressed."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 403,
            "waf_blocked": True,
            "payload_reflected": True,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_non_preamble_family_not_suppressed(self):
        """Normal family (ct_duplicate) + ref blocked → finding proceeds."""
        strat = WafBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "technique_family": "ct_duplicate",
        })
        reference = _make_result({
            **BASE_WAF,
            "waf_blocked": True,
            "response_status": 403,
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None


class TestFPHelpers:
    """Tests for FP suppression helper functions."""

    def test_is_preamble_family_true(self):
        assert _is_preamble_family(
            {"technique_family": "mp_preamble_payload"}, Input(data=b"x")
        ) is True

    def test_is_preamble_family_epilogue(self):
        assert _is_preamble_family(
            {"technique_family": "mp_epilogue_payload"}, Input(data=b"x")
        ) is True

    def test_is_preamble_family_false(self):
        assert _is_preamble_family(
            {"technique_family": "ct_duplicate"}, Input(data=b"x")
        ) is False

    def test_is_preamble_family_from_metadata(self):
        inp = Input(data=b"x", metadata={"technique_family": "mp_epilogue_payload"})
        assert _is_preamble_family({}, inp) is True

    def test_is_preamble_family_newline_artifact(self):
        """Newline-injected family names still matched."""
        assert _is_preamble_family(
            {"technique_family": "mp_preamble_payload\nX-Inject: foo"}, Input(data=b"x")
        ) is True

    def test_nodiv_true_identical(self):
        p = {**BASE_WAF, "payload_reflected": True}
        r = {**BASE_WAF, "payload_reflected": True}
        assert _has_no_behavioral_divergence(p, r) is True

    def test_nodiv_false_status_differs(self):
        p = {**BASE_WAF, "response_status": 200}
        r = {**BASE_WAF, "response_status": 403}
        assert _has_no_behavioral_divergence(p, r) is False

    def test_nodiv_false_blocking_differs(self):
        p = {**BASE_WAF, "waf_blocked": False}
        r = {**BASE_WAF, "waf_blocked": True}
        assert _has_no_behavioral_divergence(p, r) is False

    def test_nodiv_false_reflection_differs(self):
        p = {**BASE_WAF, "payload_reflected": True}
        r = {**BASE_WAF, "payload_reflected": False}
        assert _has_no_behavioral_divergence(p, r) is False

    def test_nodiv_false_canary_differs(self):
        p = {**BASE_WAF, "canary_in_body": True}
        r = {**BASE_WAF, "canary_in_body": False}
        assert _has_no_behavioral_divergence(p, r) is False

    def test_nodiv_none_input(self):
        assert _has_no_behavioral_divergence(None, {**BASE_WAF}) is False
        assert _has_no_behavioral_divergence({**BASE_WAF}, None) is False


class TestCharsetConfusionStrategy:
    def test_exotic_charset_fires(self):
        """Exotic charset (ibm037) without WAF block → finding."""
        strat = CharsetConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "charset_declared": "ibm037",
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF, "charset_declared": "ibm037"})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "waf_bypass_charset"

    def test_exotic_charset_with_reflection_high(self):
        """Exotic charset + payload reflected → HIGH."""
        strat = CharsetConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "charset_declared": "utf-7",
            "waf_blocked": False,
            "backend_reached": True,
            "payload_reflected": True,
        })
        reference = _make_result({**BASE_WAF, "charset_declared": "utf-7"})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_normal_charset_returns_none(self):
        """Normal charset (utf-8) → no finding."""
        strat = CharsetConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "charset_declared": "utf-8",
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF})
        assert strat.compare(Input(data=b"x"), primary, reference, 0) is None

    def test_waf_blocked_returns_none(self):
        """WAF blocked → no charset finding."""
        strat = CharsetConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "charset_declared": "ibm037",
            "waf_blocked": True,
            "response_status": 403,
        })
        reference = _make_result({**BASE_WAF})
        assert strat.compare(Input(data=b"x"), primary, reference, 0) is None


class TestHPPStrategy:
    def test_hpp_fires_on_overlap(self):
        """Same param in query + body → finding."""
        strat = HPPStrategy()
        raw = b"POST /test?q=safe HTTP/1.1\r\nHost: t\r\nContent-Length: 14\r\n\r\nq=<script>xss"
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF})
        finding = strat.compare(Input(data=raw), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "waf_bypass_hpp"

    def test_hpp_no_overlap_returns_none(self):
        """Different params in query vs body → no finding."""
        strat = HPPStrategy()
        raw = b"POST /test?a=1 HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nb=2"
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF})
        assert strat.compare(Input(data=raw), primary, reference, 0) is None

    def test_hpp_no_query_returns_none(self):
        """No query string → no HPP finding."""
        strat = HPPStrategy()
        raw = b"POST /test HTTP/1.1\r\nHost: t\r\nContent-Length: 3\r\n\r\nq=1"
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF})
        assert strat.compare(Input(data=raw), primary, reference, 0) is None

    def test_hpp_with_reflection_high(self):
        """HPP + payload reflected → HIGH."""
        strat = HPPStrategy()
        raw = b"POST /test?q=safe HTTP/1.1\r\nHost: t\r\nContent-Length: 14\r\n\r\nq=<script>xss"
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "payload_reflected": True,
        })
        reference = _make_result({**BASE_WAF})
        finding = strat.compare(Input(data=raw), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH


class TestBodyBoundaryMismatchStrategy:
    def test_mismatch_fires(self):
        """Header boundary differs from body boundary → finding."""
        strat = BodyBoundaryMismatchStrategy()
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Content-Type: multipart/form-data; boundary=HeaderBnd\r\n"
            b"Content-Length: 100\r\n\r\n"
            b"--BodyBnd\r\n"
            b"Content-Disposition: form-data; name=\"x\"\r\n\r\n"
            b"payload\r\n"
            b"--BodyBnd--\r\n"
        )
        primary = _make_result({
            **BASE_WAF,
            "boundary_used": "HeaderBnd",
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF})
        finding = strat.compare(Input(data=raw), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "waf_bypass_body_boundary"

    def test_matching_boundary_returns_none(self):
        """Header and body use same boundary → no finding."""
        strat = BodyBoundaryMismatchStrategy()
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Content-Type: multipart/form-data; boundary=SameBnd\r\n"
            b"Content-Length: 80\r\n\r\n"
            b"--SameBnd\r\n"
            b"Content-Disposition: form-data; name=\"x\"\r\n\r\n"
            b"data\r\n"
            b"--SameBnd--\r\n"
        )
        primary = _make_result({
            **BASE_WAF,
            "boundary_used": "SameBnd",
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF})
        assert strat.compare(Input(data=raw), primary, reference, 0) is None

    def test_no_boundary_returns_none(self):
        """No boundary in header → no finding."""
        strat = BodyBoundaryMismatchStrategy()
        raw = b"POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}"
        primary = _make_result({
            **BASE_WAF,
            "boundary_used": "",
            "waf_blocked": False,
            "backend_reached": True,
        })
        reference = _make_result({**BASE_WAF})
        assert strat.compare(Input(data=raw), primary, reference, 0) is None


class TestExtractHeader:
    def test_basic_extraction(self):
        data = b"POST / HTTP/1.1\r\nX-WF-Family: ct_json_smuggle\r\n\r\nbody"
        assert _extract_header(data, b"X-WF-Family") == "ct_json_smuggle"

    def test_case_insensitive(self):
        data = b"POST / HTTP/1.1\r\nx-wf-family: hdr_duplicate\r\n\r\n"
        assert _extract_header(data, b"X-WF-Family") == "hdr_duplicate"

    def test_newline_injection_sanitized(self):
        data = b"POST / HTTP/1.1\r\nX-WF-Family: lt_mixed_crlf\nX-Evil: injected\r\n\r\n"
        assert _extract_header(data, b"X-WF-Family") == "lt_mixed_crlf"

    def test_missing_header(self):
        data = b"POST / HTTP/1.1\r\nHost: test\r\n\r\n"
        assert _extract_header(data, b"X-WF-Family") == ""

    def test_stops_at_body(self):
        data = b"POST / HTTP/1.1\r\n\r\nX-WF-Family: in_body"
        assert _extract_header(data, b"X-WF-Family") == ""


class TestExtractHelpers:
    def test_query_params(self):
        data = b"GET /test?a=1&b=2 HTTP/1.1\r\nHost: t\r\n\r\n"
        params = _extract_query_params(data)
        assert params == {"a": "1", "b": "2"}

    def test_body_params(self):
        data = b"POST / HTTP/1.1\r\nHost: t\r\n\r\na=1&b=2"
        params = _extract_body_params(data)
        assert params == {"a": "1", "b": "2"}

    def test_body_boundary(self):
        data = b"POST / HTTP/1.1\r\n\r\n--MyBoundary\r\nContent: x\r\n\r\ndata"
        assert _extract_body_boundary(data) == "MyBoundary"

    def test_no_query_params(self):
        data = b"GET /test HTTP/1.1\r\n\r\n"
        assert _extract_query_params(data) == {}

    def test_no_body_boundary(self):
        data = b"POST / HTTP/1.1\r\n\r\njust plain body"
        assert _extract_body_boundary(data) == ""


class TestV34Strategies:
    """v3.4 — XmlContentStrategy + enrichment-driven existing strategies."""

    def test_xml_doctype_close_detection(self):
        """XmlContentStrategy fires on xml body + xml_variant + canary_in_body."""
        strat = XmlContentStrategy()
        raw = (
            b"POST /submit HTTP/1.1\r\n"
            b"Host: t\r\n"
            b"Content-Type: application/xml\r\n\r\n"
            b"<!DOCTYPE foo [<!ELEMENT bar ANY>]><root>"
            b"<canary>WF-CANARY-xxx</canary></root>"
        )
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "body_structure": "xml",
            "xml_variant": "doctype,multi_field",
            "canary_in_body": True,
        })
        reference = _make_result({**BASE_WAF, "response_status": 400})
        finding = strat.compare(Input(data=raw), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "waf_bypass_xml"
        assert "doctype" in finding.metadata["mechanism"]
        assert finding.severity == Severity.MEDIUM

    def test_xml_strategy_requires_xml_structure(self):
        """Non-xml body_structure → XmlContentStrategy silent."""
        strat = XmlContentStrategy()
        primary = _make_result({
            **BASE_WAF,
            "body_structure": "form",
            "xml_variant": "",
            "canary_in_body": True,
        })
        reference = _make_result({**BASE_WAF})
        assert strat.compare(Input(data=b"x"), primary, reference, 0) is None

    def test_json_field_wrapper_ct_confusion(self):
        """JSON field wrapper quirk flows through ContentTypeConfusionStrategy."""
        strat = ContentTypeConfusionStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "content_type_sent": "application/json",
            "content_type_parsed": "application/x-www-form-urlencoded",
            "body_structure": "json",
            "json_quirk_type": "field_wrapper",
        })
        reference = _make_result({
            **BASE_WAF,
            "response_status": 400,
            "content_type_sent": "application/json",
            "content_type_parsed": "application/json",
        })
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "waf_bypass_content_type"

    def test_enc_te_zero_triggers_encoding_bypass(self):
        """TE:0 variant shows up through encoding_depth + EncodingBypassStrategy."""
        strat = EncodingBypassStrategy()
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "payload_reflected": True,
            "encoding_depth": 1,
            "encoding_applied": "chunked",
            "enc_overflow_type": "te_zero",
        })
        reference = _make_result({**BASE_WAF, "response_status": 400, "payload_reflected": True})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "waf_bypass_encoding"

    def test_mp_boundary_header_tamper_body_mismatch(self):
        """boundary ;extra= tamper surfaces via BodyBoundaryMismatchStrategy."""
        strat = BodyBoundaryMismatchStrategy()
        raw = (
            b"POST / HTTP/1.1\r\n"
            b"Content-Type: multipart/form-data; boundary=foo;extra=bar\r\n"
            b"Content-Length: 80\r\n\r\n"
            b"--actualfoo\r\n"
            b"Content-Disposition: form-data; name=\"x\"\r\n\r\n"
            b"data\r\n"
            b"--actualfoo--\r\n"
        )
        primary = _make_result({
            **BASE_WAF,
            "waf_blocked": False,
            "backend_reached": True,
            "payload_reflected": True,
            "boundary_used": "foo;extra=bar",
        })
        reference = _make_result({**BASE_WAF})
        finding = strat.compare(Input(data=raw), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "waf_bypass_body_boundary"


class TestV34MutatorSmoke:
    """v3.4 / v4.0 smoke test — all families should appear in a 5k-input run."""

    def test_h2_families_present(self):
        """All 6 H2 downgrade families appear in a 5k-input smoke run."""
        from collections import Counter

        from webfuzzer.fuzzer.mutators.waf_bypass_mutator import WafBypassMutator
        from webfuzzer.fuzzer.mutators.h2_frames import H2_CLIENT_PREFACE

        h2_families = [
            "h2_header_inject_crlf", "h2_cl_zero_body", "h2_te_forbidden",
            "h2_pseudo_path_inject", "h2_authority_mismatch", "h2_scheme_mismatch",
        ]
        m = WafBypassMutator(seed=99, mode="hybrid")
        seed = Input(data=b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        observed: Counter[str] = Counter()
        h2_preface_ok = True
        for _ in range(5000):
            out = m.mutate(seed, corpus=[])
            fam = out.metadata.get("variant_family", "?")
            observed[fam] += 1
            if fam in h2_families:
                # Envelope + H2 preface must be intact
                if H2_CLIENT_PREFACE not in out.data[:1024]:
                    h2_preface_ok = False
        missing = [f for f in h2_families if observed.get(f, 0) == 0]
        assert not missing, f"Missing H2 families: {missing}"
        assert h2_preface_ok, "H2 preface was corrupted in at least one H2 wire"

    def test_all_families_observable(self):
        from collections import Counter

        from webfuzzer.fuzzer.mutators.waf_bypass_mutator import (
            WafBypassMutator,
            _ALL_FAMILIES,
        )

        m = WafBypassMutator(seed=42, mode="hybrid")
        seed = Input(data=b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        observed: Counter[str] = Counter()
        for _ in range(5000):
            out = m.mutate(seed, corpus=[])
            observed[out.metadata.get("variant_family", "?")] += 1
        missing = set(_ALL_FAMILIES) - set(observed.keys())
        assert not missing, f"Missing families: {sorted(missing)}"

    def test_v34_new_families_present(self):
        from collections import Counter

        from webfuzzer.fuzzer.mutators.waf_bypass_mutator import WafBypassMutator

        v34 = [
            "xml_doctype_close", "xml_schema_manip", "xml_extra_field",
            "xml_newline_abuse", "xml_misplaced", "xml_cdata_hide",
            "ct_json_field_wrapper", "ct_json_field_name_null",
            "ct_json_quote_replace", "ct_json_ct_removal",
            "enc_te_zero", "enc_chunk_overflow", "enc_zero_cl",
            "mp_boundary_header_tamper",
        ]
        m = WafBypassMutator(seed=7, mode="hybrid")
        seed = Input(data=b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
        observed: Counter[str] = Counter()
        for _ in range(5000):
            out = m.mutate(seed, corpus=[])
            observed[out.metadata.get("variant_family", "?")] += 1
        missing = [f for f in v34 if observed.get(f, 0) == 0]
        assert not missing, f"Missing v3.4 families: {missing}"
