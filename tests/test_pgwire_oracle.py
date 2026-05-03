import json

from webfuzzer.fuzzer.oracles.pgwire_diff_strategy import (
    PgwireErrorCodeGapStrategy,
    PgwireExecutionProgressGapStrategy,
    PgwireFramingDivergenceStrategy,
    PgwireStateMachineGapStrategy,
    get_pgwire_strategies,
)
from webfuzzer.fuzzer.protocols import ExecutionResult, Input, Severity


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(exit_code=exit_code, stdout=json.dumps(data).encode())


BASE = {
    "transport_mode": "pgsql_v3",
    "variant_family": "simple_query_baseline",
    "delivery_mode": "single",
    "probe_mode": "none",
    "handshake_trace_hash": "h0",
    "handshake_response_types": [],
    "ready_for_query_seen": True,
    "ready_for_query_count": 2,
    "error_response_seen": False,
    "response_trace_hash": "abc",
    "startup_trace_hash": "startup",
    "execution_trace_hash": "exec",
    "first_response_type": "R",
    "last_response_type": "Z",
    "leftover_bytes": 0,
    "timeout_phase": "",
    "parse_error": "",
    "startup_completed": True,
    "query_execution_started": True,
    "query_effect_seen": True,
    "execution_completed": True,
    "post_probe_startup_seen": False,
    "post_probe_execution_seen": False,
    "progress_stage": "execution_complete",
    "auth_ok_seen": True,
    "auth_challenge_seen": False,
    "auth_codes": [0],
    "tx_statuses": ["I", "I"],
    "backend_key_data_seen": False,
    "command_complete_seen": 1,
    "parse_complete_seen": 0,
    "bind_complete_seen": 0,
    "copy_in_seen": False,
    "copy_out_seen": False,
    "portal_suspended_seen": False,
    "error_codes": [],
    "response_types": ["R", "Z", "C", "Z"],
    "startup_response_types": ["R", "Z"],
    "execution_response_types": ["C", "Z"],
    "startup_parameter_status_count": 0,
}


class TestPgwireStrategies:
    def test_framing_divergence_high_when_ready_differs(self):
        strat = PgwireFramingDivergenceStrategy()
        primary = _make_result(BASE)
        reference = _make_result(
            {
                **BASE,
                "ready_for_query_seen": False,
                "response_trace_hash": "def",
                "execution_trace_hash": "exec-def",
                "last_response_type": "E",
                "execution_response_types": ["E"],
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "pgwire_framing_divergence"
        assert finding.severity == Severity.HIGH

    def test_error_code_gap_detects_sqlstate_change(self):
        strat = PgwireErrorCodeGapStrategy()
        primary = _make_result(
            {**BASE, "error_response_seen": True, "error_codes": ["42601"]}
        )
        reference = _make_result(
            {**BASE, "error_response_seen": True, "error_codes": ["08P01"]}
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "pgwire_error_code_gap"

    def test_state_machine_gap_detects_parse_complete_difference(self):
        strat = PgwireStateMachineGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "variant_family": "extended_query_basic",
                "parse_complete_seen": 1,
                "bind_complete_seen": 1,
            }
        )
        reference = _make_result(
            {
                **BASE,
                "variant_family": "extended_query_basic",
                "parse_complete_seen": 0,
                "bind_complete_seen": 0,
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "pgwire_state_machine_gap"
        assert finding.severity == Severity.HIGH

    def test_strategy_set(self):
        names = {strategy.name for strategy in get_pgwire_strategies()}
        assert names == {
            "pgwire_framing",
            "pgwire_error_code_gap",
            "pgwire_state_machine_gap",
            "pgwire_execution_progress_gap",
            "pgwire_smuggle_indicator",
        }

    def test_framing_ignores_startup_only_variance(self):
        strat = PgwireFramingDivergenceStrategy()
        primary = _make_result(BASE)
        reference = _make_result(
            {
                **BASE,
                "response_trace_hash": "startup-only-diff",
                "startup_trace_hash": "startup-diff",
                "response_types": ["R", "S", "Z", "C", "Z"],
                "startup_response_types": ["R", "S", "Z"],
                "startup_parameter_status_count": 1,
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is None

    def test_framing_detects_handshake_difference(self):
        strat = PgwireFramingDivergenceStrategy()
        primary = _make_result(
            {
                **BASE,
                "variant_family": "ssl_probe",
                "execution_trace_hash": "da39a3ee5e6b4b0d3255",
                "execution_response_types": [],
                "handshake_trace_hash": "ssl:S",
                "handshake_response_types": ["S"],
            }
        )
        reference = _make_result(
            {
                **BASE,
                "variant_family": "ssl_probe",
                "execution_trace_hash": "da39a3ee5e6b4b0d3255",
                "execution_response_types": [],
                "handshake_trace_hash": "ssl:N",
                "handshake_response_types": ["N"],
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "pgwire_framing_divergence"

    def test_execution_progress_gap_detects_post_probe_execution_difference(self):
        strat = PgwireExecutionProgressGapStrategy()
        primary = _make_result(
            {
                **BASE,
                "variant_family": "gss_then_query",
                "handshake_trace_hash": "gss:closed",
                "handshake_response_types": [],
                "startup_completed": False,
                "query_execution_started": False,
                "query_effect_seen": False,
                "execution_completed": False,
                "post_probe_startup_seen": False,
                "post_probe_execution_seen": False,
                "progress_stage": "probe_only",
                "response_types": [],
                "startup_response_types": [],
                "execution_response_types": [],
                "ready_for_query_seen": False,
                "ready_for_query_count": 0,
                "auth_ok_seen": False,
                "auth_codes": [],
                "tx_statuses": [],
            }
        )
        reference = _make_result(
            {
                **BASE,
                "variant_family": "gss_then_query",
                "handshake_trace_hash": "gss:N",
                "handshake_response_types": ["N"],
                "post_probe_startup_seen": True,
                "post_probe_execution_seen": True,
                "progress_stage": "execution_complete",
            }
        )
        finding = strat.compare(Input(data=b"x"), primary, reference, 0)
        assert finding is not None
        assert finding.metadata["category"] == "pgwire_execution_progress_gap"
        assert finding.severity == Severity.HIGH
