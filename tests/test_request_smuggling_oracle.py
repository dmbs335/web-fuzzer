import json

from webfuzzer.fuzzer.oracles.request_smuggling_diff_strategy import (
    CanaryMisassociationStrategy,
    ChunkSemanticGapStrategy,
    ConnectionLockedDesyncStrategy,
    DesyncPreconditionStrategy,
    DowngradeSemanticGapStrategy,
    EarlyResponseDesyncStrategy,
    PauseDesyncCandidateStrategy,
    PipelinePoisoningStrategy,
    RequestSmugglingFramingDivergenceStrategy,
    RoutingSemanticGapStrategy,
    TrailerEffectiveHeaderGapStrategy,
    get_request_smuggling_strategies,
    _diff_pattern_hash,
    _difference_fields,
    _interpretation,
    _timing_bucket,
)
from webfuzzer.fuzzer.protocols import ExecutionResult, Input, Severity


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(exit_code=exit_code, stdout=json.dumps(data).encode())


BASE = {
    "transport_mode": "h1_raw",
    "delivery_mode": "oneshot_h1",
    "probe_mode": "none",
    "probe_outcome": "completed",
    "request_id": "abc123",
    "variant_family": "cl_te",
    "taxonomy_tags": ["CL.TE", "content_length", "transfer_encoding"],
    "first_response_status": 200,
    "second_response_status": None,
    "first_response_timing_ms": 10.5,
    "second_response_timing_ms": None,
    "response_count_observed": 1,
    "connection_closed": False,
    "timeout_phase": None,
    "parse_error": None,
    "canary_seen_in_first": False,
    "canary_seen_in_second": False,
    "backend_marker_seen": False,
    "frontend_marker_seen": False,
    "impact_marker_seen": False,
    "impact_type": "",
    "impact_detail": "",
    "effective_headers": "",
    "effective_body_boundary": "",
    "forwarded_request_hash": "",
    "forwarded_request_line": "",
    "trailer_forwarded": False,
    "trailer_merge_keys": "",
    "routing_decision_source": "",
    "cache_decision_source": "",
    "axis_projection": "framing=CL|leniency=strict|chunk=none|connection=keepalive|timing=none|routing=host|shape=body_plus_canary",
    "axis_framing": "CL",
    "axis_leniency": "strict",
    "axis_chunk": "none",
    "axis_connection": "keepalive",
    "axis_timing": "none",
    "axis_routing": "host",
    "stream_shape": "body_plus_canary",
    "reflected_smuggled_prefix": "",
    "extra_bytes_left": 0,
    "request_bytes_sent": 123,
    "h2_event_trace": [],
    "h2_headers_seen": 0,
    "h2_trailers_seen": 0,
    "h2_data_frames": 0,
    "h2_bytes_received": 0,
    "h2_reset_error": "",
    "h2_goaway_error": "",
    "h2_error_detail": "",
    "artifact_path_stable": "C:/tmp/sample.wire",
    "raw_artifact_path": "C:/tmp/sample.wire",
    "target_host": "127.0.0.1",
    "target_port": 8080,
}


class TestRequestSmugglingStrategies:
    def test_framing_divergence_medium(self):
        strat = RequestSmugglingFramingDivergenceStrategy()
        primary = _make_result(BASE)
        reference = _make_result({**BASE, "second_response_status": 404, "response_count_observed": 2})
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "framing_divergence"
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["diff_pattern_hash"]

    def test_malformed_accept_reject_is_low(self):
        strat = RequestSmugglingFramingDivergenceStrategy()
        primary = _make_result({**BASE, "parse_error": "incomplete_headers", "response_count_observed": 0})
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.LOW

    def test_canary_misassociation_high(self):
        strat = CanaryMisassociationStrategy()
        primary = _make_result({**BASE, "canary_seen_in_first": True})
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "canary_misassociation"
        assert finding.severity == Severity.HIGH

    def test_early_response_desync(self):
        strat = EarlyResponseDesyncStrategy()
        primary = _make_result(
            {
                **BASE,
                "probe_mode": "early_response",
                "probe_outcome": "late_bytes_consumed_as_second",
                "first_response_status": 100,
                "second_response_status": 200,
                "response_count_observed": 2,
            }
        )
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "early_response_desync"

    def test_h2_gap(self):
        strat = DowngradeSemanticGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "transport_mode": "h2_raw",
                "delivery_mode": "h2_raw",
                "variant_family": "h2_cl",
                "second_response_status": 200,
                "response_count_observed": 2,
            }
        )
        reference = _make_result(
            {
                **BASE,
                "transport_mode": "h2_raw",
                "delivery_mode": "h2_raw",
                "variant_family": "h2_cl",
            }
        )
        finding = strat.compare(
            Input(data=b"x", metadata={"transport_mode": "h2_raw"}),
            primary,
            reference,
            0,
        )
        assert finding is not None
        assert finding.metadata["category"] == "downgrade_semantic_gap"
        assert "explanation" in finding.metadata
        assert "difference_fields" in finding.metadata

    def test_h2_gap_explains_reset_difference(self):
        strat = DowngradeSemanticGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "transport_mode": "h2_raw",
                "delivery_mode": "h2_raw",
                "variant_family": "h2_te",
                "probe_outcome": "h2_stream_reset:1",
                "h2_reset_error": "1",
            }
        )
        reference = _make_result(
            {
                **BASE,
                "transport_mode": "h2_raw",
                "delivery_mode": "h2_raw",
                "variant_family": "h2_te",
                "probe_outcome": "h2_complete",
                "first_response_status": 200,
                "response_count_observed": 1,
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert "h2_reset_error" in finding.metadata["difference_fields"]
        assert "primary=h2_reset:1" in finding.metadata["explanation"]

    def test_pause_desync_candidate(self):
        strat = PauseDesyncCandidateStrategy()
        primary = _make_result(
            {
                **BASE,
                "probe_mode": "pause_prefix",
                "delivery_mode": "pause_probe_h1",
                "probe_outcome": "late_bytes_consumed_as_second",
                "response_count_observed": 2,
                "second_response_status": 404,
            }
        )
        reference = _make_result(
            {
                **BASE,
                "probe_mode": "pause_prefix",
                "delivery_mode": "pause_probe_h1",
                "probe_outcome": "pause_timeout_no_desync",
                "timeout_phase": "second_response",
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "pause_desync_candidate"
        assert finding.severity == Severity.HIGH

    def test_chunk_semantic_gap(self):
        strat = ChunkSemanticGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "variant_family": "chunk_ext",
                "chunk_shape": "chunk_ext",
                "taxonomy_tags": ["TE.TE", "chunk_extension"],
                "parse_error": "chunk_size:bad",
                "response_count_observed": 0,
            }
        )
        reference = _make_result(
            {
                **BASE,
                "variant_family": "chunk_ext",
                "chunk_shape": "chunk_ext",
                "taxonomy_tags": ["TE.TE", "chunk_extension"],
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "chunk_semantic_gap"

    def test_trailer_merge_gap_is_high_when_impact_differs(self):
        strat = ChunkSemanticGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "variant_family": "trailer_merge",
                "impact_marker_seen": True,
                "impact_type": "cache_poison",
                "impact_detail": "/trailer-cache/demo",
                "response_count_observed": 1,
            }
        )
        reference = _make_result(
            {
                **BASE,
                "variant_family": "trailer_merge",
                "response_count_observed": 0,
                "timeout_phase": "first_response",
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "chunk_semantic_gap"
        assert finding.severity == Severity.HIGH

    def test_framing_divergence_tracks_impact_difference(self):
        strat = RequestSmugglingFramingDivergenceStrategy()
        primary = _make_result(
            {
                **BASE,
                "impact_marker_seen": True,
                "impact_type": "cache_poison",
                "impact_detail": "key=/cache/store",
            }
        )
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert "impact_type" in finding.metadata["difference_fields"]
        assert finding.metadata["primary_impact"]["type"] == "cache_poison"
        assert finding.metadata["axis_projection"].startswith("framing=CL")

    def test_connection_locked_desync(self):
        strat = ConnectionLockedDesyncStrategy()
        primary = _make_result(
            {
                **BASE,
                "probe_mode": "connection_locked",
                "delivery_mode": "pause_probe_h1",
                "probe_outcome": "backend_timeout_after_pause",
                "timeout_phase": "first_response",
                "response_count_observed": 0,
            }
        )
        reference = _make_result(
            {
                **BASE,
                "probe_mode": "connection_locked",
                "delivery_mode": "pause_probe_h1",
                "probe_outcome": "accepted_after_pause",
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "connection_locked_desync"

    def test_routing_semantic_gap(self):
        strat = RoutingSemanticGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "routing_decision_source": "trailer",
                "cache_decision_source": "trailer",
                "impact_type": "cache_poison",
                "forwarded_request_hash": "aaa",
            }
        )
        reference = _make_result(
            {
                **BASE,
                "routing_decision_source": "header",
                "cache_decision_source": "header",
                "forwarded_request_hash": "bbb",
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "routing_semantic_gap"

    def test_trailer_effective_header_gap(self):
        strat = TrailerEffectiveHeaderGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "variant_family": "trailer_merge",
                "trailer_forwarded": True,
                "trailer_merge_keys": "x-original-url",
                "effective_headers": "host=victim.local;x-original-url=/shadow",
            }
        )
        reference = _make_result(
            {
                **BASE,
                "variant_family": "trailer_merge",
                "trailer_forwarded": False,
                "effective_headers": "host=victim.local",
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "trailer_effective_header_gap"

    def test_strategy_set(self):
        names = {s.name for s in get_request_smuggling_strategies()}
        assert names == {
            "request_smuggling_pipeline_poisoning",
            "request_smuggling_desync_precondition",
            "request_smuggling_framing",
            "request_smuggling_canary",
            "request_smuggling_early_response",
            "request_smuggling_h2_gap",
            "request_smuggling_pause_probe",
            "request_smuggling_chunk_gap",
            "request_smuggling_routing_gap",
            "request_smuggling_trailer_effective_header_gap",
            "request_smuggling_connection_locked",
        }

    # ------------------------------------------------------------------
    # Oracle refinement tests (fingerprint granularity)
    # ------------------------------------------------------------------

    def test_interpretation_returns_informational_for_100(self):
        data = {**BASE, "first_response_status": 100}
        assert _interpretation(data) == "informational:100"

    def test_interpretation_returns_informational_for_h2_info_list(self):
        data = {**BASE, "h2_informational_status": [100, 103]}
        assert _interpretation(data) == "informational:100,103"

    def test_100_vs_400_produces_different_hash(self):
        p_100 = {**BASE, "first_response_status": 100}
        p_400 = {**BASE, "first_response_status": 400}
        ref = {**BASE}
        hash_100 = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p_100, reference=ref,
        )
        hash_400 = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p_400, reference=ref,
        )
        assert hash_100 != hash_400

    def test_reflected_prefix_different_hash(self):
        p_with = {**BASE, "reflected_smuggled_prefix": "GET /smuggled HTTP/1.1"}
        p_without = {**BASE, "reflected_smuggled_prefix": ""}
        ref = {**BASE}
        hash_with = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p_with, reference=ref,
        )
        hash_without = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p_without, reference=ref,
        )
        assert hash_with != hash_without

    def test_body_crc_in_difference_fields(self):
        p = {**BASE, "first_body_crc32": "aabb1122"}
        r = {**BASE, "first_body_crc32": "ccdd3344"}
        diff = _difference_fields(p, r)
        assert "first_body_crc32" in diff

    def test_informational_status_in_difference_fields(self):
        p = {**BASE, "h2_informational_status": [100]}
        r = {**BASE, "h2_informational_status": []}
        diff = _difference_fields(p, r)
        assert "h2_informational_status" in diff

    def test_timing_bucket_helper(self):
        assert _timing_bucket(None) == "none"
        assert _timing_bucket(10) == "<=50"
        assert _timing_bucket(50) == "<=50"
        assert _timing_bucket(51) == "<=200"
        assert _timing_bucket(200) == "<=200"
        assert _timing_bucket(500) == "<=500"
        assert _timing_bucket(1000) == "<=1000"
        assert _timing_bucket(3000) == "<=3000"
        assert _timing_bucket(5000) == ">3000"

    def test_timing_divergence_produces_different_hash(self):
        p_fast = {**BASE, "first_response_timing_ms": 10}
        p_slow = {**BASE, "first_response_timing_ms": 2000}
        ref = {**BASE}
        hash_fast = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p_fast, reference=ref,
        )
        hash_slow = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p_slow, reference=ref,
        )
        assert hash_fast != hash_slow

    def test_ref_index_differentiates_hash(self):
        p = {**BASE, "first_response_status": 200}
        ref = {**BASE}
        hash_ref0 = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p, reference=ref,
        )
        hash_ref1 = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=1,
            difference_fields=[], primary=p, reference=ref,
        )
        assert hash_ref0 != hash_ref1

    def test_mechanism_differentiates_hash(self):
        p = {**BASE, "first_response_status": 200}
        ref = {**BASE}
        hash_a = _diff_pattern_hash(
            category="pipeline_poisoning", mechanism="cross_request_contamination",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p, reference=ref,
        )
        hash_b = _diff_pattern_hash(
            category="pipeline_poisoning", mechanism="connection_reuse",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=[], primary=p, reference=ref,
        )
        assert hash_a != hash_b

    def test_difference_fields_differentiates_hash(self):
        p = {**BASE, "first_response_status": 200}
        ref = {**BASE}
        hash_a = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=["effective_headers"], primary=p, reference=ref,
        )
        hash_b = _diff_pattern_hash(
            category="framing_divergence", mechanism="request_boundary",
            probe_mode="none", variant_family="cl_te", ref_index=0,
            difference_fields=["effective_headers", "forwarded_request_hash"],
            primary=p, reference=ref,
        )
        assert hash_a != hash_b

    # ------------------------------------------------------------------
    # Pipeline poisoning strategy tests
    # ------------------------------------------------------------------

    def test_pipeline_poisoning_critical(self):
        strat = PipelinePoisoningStrategy()
        primary = _make_result({
            **BASE,
            "response_count_observed": 2,
            "second_response_status": 200,
            "pipeline_victim_sent": True,
            "pipeline_victim_status": 200,
            "pipeline_victim_outcome": "misrouted",
            "pipeline_victim_contaminated": True,
            "pipeline_victim_body_preview": "BACKEND-MARKER ok smuggled",
        })
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "pipeline_poisoning"

    def test_pipeline_poisoning_no_contamination_returns_none(self):
        strat = PipelinePoisoningStrategy()
        primary = _make_result({
            **BASE,
            "response_count_observed": 2,
            "pipeline_victim_sent": True,
            "pipeline_victim_outcome": "clean",
            "pipeline_victim_contaminated": False,
        })
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_desync_precondition_high(self):
        strat = DesyncPreconditionStrategy()
        primary = _make_result({
            **BASE,
            "response_count_observed": 2,
            "second_response_status": 200,
            "pipeline_victim_sent": True,
            "pipeline_victim_outcome": "clean",
            "pipeline_victim_contaminated": False,
        })
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "desync_precondition"

    def test_desync_precondition_not_sent_returns_none(self):
        strat = DesyncPreconditionStrategy()
        primary = _make_result({**BASE, "response_count_observed": 2})
        reference = _make_result(BASE)
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_strategy_set_includes_pipeline(self):
        names = {s.name for s in get_request_smuggling_strategies()}
        assert "request_smuggling_pipeline_poisoning" in names
        assert "request_smuggling_desync_precondition" in names

    def test_pipeline_fields_in_difference_fields(self):
        p = {**BASE, "pipeline_victim_contaminated": True, "pipeline_victim_sent": True}
        r = {**BASE, "pipeline_victim_contaminated": False, "pipeline_victim_sent": False}
        diff = _difference_fields(p, r)
        assert "pipeline_victim_contaminated" in diff
        assert "pipeline_victim_sent" in diff
