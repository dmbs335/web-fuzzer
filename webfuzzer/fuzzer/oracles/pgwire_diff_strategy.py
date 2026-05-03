"""PostgreSQL wire-protocol differential strategies."""

from __future__ import annotations

from typing import Iterable

from ..protocols import ExecutionResult, Finding, Input, Severity


_TRACE_KEYS = (
    "handshake_trace_hash",
    "handshake_response_types",
    "ready_for_query_seen",
    "ready_for_query_count",
    "error_response_seen",
    "execution_trace_hash",
    "execution_response_types",
    "first_response_type",
    "last_response_type",
    "leftover_bytes",
    "timeout_phase",
    "parse_error",
)

_STATE_KEYS = (
    "startup_completed",
    "query_execution_started",
    "query_effect_seen",
    "execution_completed",
    "post_probe_startup_seen",
    "post_probe_execution_seen",
    "progress_stage",
    "auth_ok_seen",
    "auth_challenge_seen",
    "backend_key_data_seen",
    "command_complete_seen",
    "parse_complete_seen",
    "bind_complete_seen",
    "close_complete_seen",
    "copy_in_seen",
    "copy_out_seen",
    "portal_suspended_seen",
)


def _parse_pgwire_output(result: ExecutionResult) -> dict | None:
    data = result.parsed_json()
    if not isinstance(data, dict):
        return None
    if "transport_mode" not in data and "response_trace_hash" not in data:
        return None
    return data


def _variant_family(inp: Input, primary: dict | None, reference: dict | None) -> str:
    for source in (primary, reference, inp.metadata):
        if not source:
            continue
        value = source.get("variant_family")
        if value:
            return str(value)
    return "unknown"


def _difference_fields(primary: dict | None, reference: dict | None) -> list[str]:
    p = primary or {}
    r = reference or {}
    keys = (
        *_TRACE_KEYS,
        *_STATE_KEYS,
        "error_codes",
        "response_types",
        "startup_parameter_status_count",
        "startup_trace_hash",
        "auth_codes",
        "tx_statuses",
        "progress_stage",
    )
    diff: list[str] = []
    for key in keys:
        if p.get(key) != r.get(key):
            diff.append(key)
    return diff


def _tuple(data: dict | None, keys: Iterable[str]) -> tuple:
    if not data:
        return tuple(None for _ in keys)
    return tuple(data.get(key) for key in keys)


def _make_finding(
    *,
    title: str,
    severity: Severity,
    category: str,
    mechanism: str,
    inp: Input,
    primary_result: ExecutionResult,
    primary_data: dict | None,
    reference_data: dict | None,
    ref_index: int,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        input=inp,
        result=primary_result,
        oracle_name="differential",
        metadata={
            "strategy": category,
            "category": category,
            "mechanism": mechanism,
            "variant_family": _variant_family(inp, primary_data, reference_data),
            "diff_fields": _difference_fields(primary_data, reference_data),
            "difference_fields": _difference_fields(primary_data, reference_data),
            "primary_trace": (primary_data or {}).get("response_trace_hash"),
            "ref_trace": (reference_data or {}).get("response_trace_hash"),
            "primary_error_codes": (primary_data or {}).get("error_codes", []),
            "ref_error_codes": (reference_data or {}).get("error_codes", []),
            "primary_ready": (primary_data or {}).get("ready_for_query_seen", False),
            "ref_ready": (reference_data or {}).get("ready_for_query_seen", False),
            "delivery_mode": (primary_data or {}).get("delivery_mode")
            or (reference_data or {}).get("delivery_mode")
            or inp.metadata.get("delivery_mode"),
            "ref_index": ref_index,
        },
    )


class PgwireFramingDivergenceStrategy:
    """Detects material differences in response framing and stream shape."""

    name = "pgwire_framing"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_pgwire_output(primary)
        rp = _parse_pgwire_output(reference)
        if pp is None or rp is None:
            return None

        # Ignore startup-only ParameterStatus / banner variance when the
        # execution phase is otherwise identical. This keeps version skew
        # between real PostgreSQL servers from dominating findings.
        execution_trace_pp = pp.get("execution_trace_hash")
        execution_trace_rp = rp.get("execution_trace_hash")
        if execution_trace_pp == execution_trace_rp:
            if (
                pp.get("execution_response_types") == rp.get("execution_response_types")
                and pp.get("handshake_trace_hash") == rp.get("handshake_trace_hash")
            ):
                return None

        if _tuple(pp, _TRACE_KEYS) == _tuple(rp, _TRACE_KEYS):
            return None

        severity = Severity.MEDIUM
        if pp.get("ready_for_query_seen") != rp.get("ready_for_query_seen"):
            severity = Severity.HIGH
        elif pp.get("leftover_bytes") or rp.get("leftover_bytes"):
            severity = Severity.HIGH

        return _make_finding(
            title="Pgwire framing divergence",
            severity=severity,
            category="pgwire_framing_divergence",
            mechanism="response_trace_gap",
            inp=inp,
            primary_result=primary,
            primary_data=pp,
            reference_data=rp,
            ref_index=ref_index,
        )


class PgwireErrorCodeGapStrategy:
    """Detects cases where the same transcript yields different SQLSTATE paths."""

    name = "pgwire_error_code_gap"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_pgwire_output(primary)
        rp = _parse_pgwire_output(reference)
        if pp is None or rp is None:
            return None

        primary_codes = tuple(pp.get("error_codes") or [])
        ref_codes = tuple(rp.get("error_codes") or [])
        if (
            primary_codes == ref_codes
            and bool(pp.get("error_response_seen")) == bool(rp.get("error_response_seen"))
        ):
            return None

        severity = Severity.MEDIUM
        if bool(pp.get("error_response_seen")) != bool(rp.get("error_response_seen")):
            severity = Severity.HIGH

        return _make_finding(
            title="Pgwire error-code divergence",
            severity=severity,
            category="pgwire_error_code_gap",
            mechanism="sqlstate_divergence",
            inp=inp,
            primary_result=primary,
            primary_data=pp,
            reference_data=rp,
            ref_index=ref_index,
        )


class PgwireStateMachineGapStrategy:
    """Detects different protocol-state progression for the same transcript."""

    name = "pgwire_state_machine_gap"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_pgwire_output(primary)
        rp = _parse_pgwire_output(reference)
        if pp is None or rp is None:
            return None

        if _tuple(pp, _STATE_KEYS) == _tuple(rp, _STATE_KEYS):
            return None

        severity = Severity.MEDIUM
        if (
            pp.get("command_complete_seen") != rp.get("command_complete_seen")
            or pp.get("parse_complete_seen") != rp.get("parse_complete_seen")
        ):
            severity = Severity.HIGH

        return _make_finding(
            title="Pgwire state-machine divergence",
            severity=severity,
            category="pgwire_state_machine_gap",
            mechanism="state_progression_divergence",
            inp=inp,
            primary_result=primary,
            primary_data=pp,
            reference_data=rp,
            ref_index=ref_index,
        )


class PgwireExecutionProgressGapStrategy:
    """Detects when one side advances meaningfully further into execution."""

    name = "pgwire_execution_progress_gap"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_pgwire_output(primary)
        rp = _parse_pgwire_output(reference)
        if pp is None or rp is None:
            return None

        progress_keys = (
            "startup_completed",
            "query_execution_started",
            "query_effect_seen",
            "execution_completed",
            "post_probe_startup_seen",
            "post_probe_execution_seen",
            "progress_stage",
            "command_complete_seen",
            "parse_complete_seen",
            "bind_complete_seen",
        )
        if _tuple(pp, progress_keys) == _tuple(rp, progress_keys):
            return None

        severity = Severity.MEDIUM
        if pp.get("query_effect_seen") != rp.get("query_effect_seen"):
            severity = Severity.HIGH
        elif pp.get("post_probe_execution_seen") != rp.get("post_probe_execution_seen"):
            severity = Severity.HIGH
        elif pp.get("startup_completed") != rp.get("startup_completed"):
            severity = Severity.HIGH

        return _make_finding(
            title="Pgwire execution-progress divergence",
            severity=severity,
            category="pgwire_execution_progress_gap",
            mechanism="execution_progress_divergence",
            inp=inp,
            primary_result=primary,
            primary_data=pp,
            reference_data=rp,
            ref_index=ref_index,
        )


class PgwireSmuggleIndicatorStrategy:
    """Detects evidence of SQL smuggling — divergent response counts or
    extra ReadyForQuery responses that indicate a smuggled query was
    processed differently by the two targets."""

    name = "pgwire_smuggle_indicator"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_pgwire_output(primary)
        rp = _parse_pgwire_output(reference)
        if pp is None or rp is None:
            return None

        # Only fire for smuggle-mode inputs.
        smuggle_mode = str(
            pp.get("smuggle_mode")
            or rp.get("smuggle_mode")
            or inp.metadata.get("smuggle_mode")
            or "none"
        )
        if smuggle_mode == "none":
            return None

        p_ready = int(pp.get("ready_for_query_count") or 0)
        r_ready = int(rp.get("ready_for_query_count") or 0)
        p_cmd = int(pp.get("command_complete_seen") or 0)
        r_cmd = int(rp.get("command_complete_seen") or 0)
        p_extra = int(pp.get("smuggle_extra_ready") or 0)
        r_extra = int(rp.get("smuggle_extra_ready") or 0)
        p_indicator = bool(pp.get("smuggle_indicator"))
        r_indicator = bool(rp.get("smuggle_indicator"))

        # Interesting when: one side shows smuggle evidence but the other
        # doesn't, or they have divergent ready/command counts.
        has_divergence = (
            p_indicator != r_indicator
            or p_ready != r_ready
            or p_cmd != r_cmd
            or p_extra != r_extra
        )
        if not has_divergence:
            return None

        severity = Severity.MEDIUM
        if p_indicator != r_indicator:
            severity = Severity.HIGH
        elif p_ready != r_ready:
            severity = Severity.HIGH

        return _make_finding(
            title=f"Pgwire smuggle indicator ({smuggle_mode})",
            severity=severity,
            category="pgwire_smuggle_indicator",
            mechanism=f"smuggle_{smuggle_mode}",
            inp=inp,
            primary_result=primary,
            primary_data=pp,
            reference_data=rp,
            ref_index=ref_index,
        )


def get_pgwire_strategies() -> list:
    return [
        PgwireFramingDivergenceStrategy(),
        PgwireErrorCodeGapStrategy(),
        PgwireStateMachineGapStrategy(),
        PgwireExecutionProgressGapStrategy(),
        PgwireSmuggleIndicatorStrategy(),
    ]
