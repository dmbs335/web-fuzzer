"""HTTP Request Smuggling differential strategies."""

from __future__ import annotations

import hashlib
from typing import Iterable

from ..protocols import ExecutionResult, Finding, Input, Severity


_RESPONSE_KEYS = (
    "first_response_status",
    "second_response_status",
    "response_count_observed",
    "connection_closed",
    "parse_error",
    "timeout_phase",
    "extra_bytes_left",
    "probe_outcome",
)

_CANARY_KEYS = (
    "canary_seen_in_first",
    "canary_seen_in_second",
    "backend_marker_seen",
    "frontend_marker_seen",
)

_IMPACT_KEYS = (
    "impact_marker_seen",
    "impact_type",
    "impact_detail",
)

_OBSERVATION_KEYS = (
    "effective_headers",
    "effective_body_boundary",
    "forwarded_request_hash",
    "forwarded_request_line",
    "trailer_forwarded",
    "trailer_merge_keys",
    "routing_decision_source",
    "cache_decision_source",
    "axis_projection",
    "axis_framing",
    "axis_leniency",
    "axis_chunk",
    "axis_connection",
    "axis_timing",
    "axis_routing",
    "stream_shape",
)

_BODY_KEYS = (
    "reflected_smuggled_prefix",
    "first_body_crc32",
    "second_body_crc32",
    "request_bytes_sent",
)

_INFORMATIONAL_KEYS = (
    "h2_informational_status",
)

_CHUNK_FAMILIES = {
    "chunk_ws",
    "chunk_ext",
    "chunk_bare_lf",
    "trailer_merge",
    "trailer_header_ambiguity",
    "chunk_terminator",
}
_TRAILER_FAMILIES = {"trailer_merge", "trailer_header_ambiguity"}

_PAUSE_PROBES = {"pause_prefix", "pause_suffix", "early_response"}
_LOCK_PROBES = {"connection_locked", "halfclose"}


def _parse_result(result: ExecutionResult) -> dict | None:
    data = result.parsed_json()
    if not isinstance(data, dict):
        return None
    if "first_response_status" not in data and "transport_mode" not in data:
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


def _probe_mode(inp: Input, primary: dict | None, reference: dict | None) -> str:
    for source in (primary, reference, inp.metadata):
        if not source:
            continue
        value = source.get("probe_mode")
        if value:
            return str(value)
    return "none"


def _taxonomy_tags(inp: Input, primary: dict | None, reference: dict | None) -> list[str]:
    for source in (primary, reference, inp.metadata):
        if not source:
            continue
        value = source.get("taxonomy_tags")
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, str):
            return [tag.strip() for tag in value.split(",") if tag.strip()]
    return []


def _transport_mode(inp: Input, primary: dict | None, reference: dict | None) -> str:
    for source in (primary, reference, inp.metadata):
        if not source:
            continue
        value = source.get("transport_mode")
        if value:
            return str(value)
    return "h1_raw"


def _artifact_path(data: dict | None) -> str:
    if not data:
        return ""
    for key in ("artifact_path_stable", "raw_artifact_path"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    return ""


def _replay_command(data: dict | None) -> str:
    if not data:
        return ""
    artifact = _artifact_path(data)
    host = str(data.get("target_host") or "127.0.0.1")
    port = data.get("target_port")
    if artifact and port:
        return (
            f"python targets/request_smuggling_target.py --host {host} "
            f"--port {port} \"{artifact}\""
        )
    return ""


def _interpretation(data: dict | None) -> str:
    if not data:
        return "no_output"
    if data.get("h2_reset_error"):
        return f"h2_reset:{data.get('h2_reset_error')}"
    if data.get("h2_goaway_error"):
        return f"h2_goaway:{data.get('h2_goaway_error')}"
    if data.get("probe_outcome") and data.get("probe_outcome") != "completed":
        return f"probe:{data.get('probe_outcome')}"
    if data.get("parse_error"):
        return f"parse_error:{data.get('parse_error')}"
    if data.get("timeout_phase"):
        return f"timeout:{data.get('timeout_phase')}"
    # 100-continue / informational status detection
    info_status = data.get("h2_informational_status")
    first_status = data.get("first_response_status")
    if first_status == 100 or (isinstance(info_status, list) and info_status):
        info_tag = ",".join(str(s) for s in info_status) if info_status else str(first_status)
        return f"informational:{info_tag}"
    if data.get("canary_seen_in_first"):
        return "canary_in_first"
    if data.get("canary_seen_in_second"):
        return "canary_in_second"
    if data.get("second_response_status") is not None:
        return "two_responses"
    if data.get("connection_closed"):
        return "connection_closed"
    return "single_response"


def _tuple(data: dict | None, keys: Iterable[str]) -> tuple:
    if not data:
        return tuple(None for _ in keys)
    return tuple(data.get(key) for key in keys)


def _has_high_signal(data: dict | None) -> bool:
    if not data:
        return False
    return (
        any(bool(data.get(key)) for key in _CANARY_KEYS)
        or any(bool(data.get(key)) for key in _IMPACT_KEYS)
        or bool(data.get("second_response_status"))
    )


def _smuggled_prefix_hash(data: dict | None) -> str:
    """Hash the reflected smuggled prefix for fingerprint differentiation."""
    prefix = str((data or {}).get("reflected_smuggled_prefix") or "").strip()
    if not prefix:
        return "none"
    method = prefix.split(" ", 1)[0] if " " in prefix else "raw"
    sig = hashlib.sha1(prefix[:16].encode("utf-8", errors="replace")).hexdigest()[:6]
    return f"{method}:{sig}"


_TIMING_THRESHOLDS = (50, 200, 500, 1000, 3000)


def _timing_bucket(ms) -> str:
    """Bucket response timing into coarse categories for fingerprinting."""
    if ms is None:
        return "none"
    for t in _TIMING_THRESHOLDS:
        if float(ms) <= t:
            return f"<={t}"
    return ">3000"


def _difference_fields(primary: dict | None, reference: dict | None) -> list[str]:
    keys = (
        *_RESPONSE_KEYS,
        *_CANARY_KEYS,
        *_IMPACT_KEYS,
        *_OBSERVATION_KEYS,
        *_BODY_KEYS,
        *_INFORMATIONAL_KEYS,
        *_PIPELINE_KEYS,
        "h2_reset_error",
        "h2_goaway_error",
        "h2_error_detail",
        "h2_headers_seen",
        "h2_trailers_seen",
        "h2_data_frames",
        "h2_bytes_received",
    )
    diff: list[str] = []
    p = primary or {}
    r = reference or {}
    for key in keys:
        if p.get(key) != r.get(key):
            diff.append(key)
    return diff


def _summary_label(data: dict | None) -> str:
    if not data:
        return "no-output"
    impact = str(data.get("impact_type") or "").strip()
    impact_part = f" impact={impact}" if impact else ""
    return (
        f"{_interpretation(data)}"
        f" status1={data.get('first_response_status')}"
        f" status2={data.get('second_response_status')}"
        f" count={data.get('response_count_observed')}"
        f"{impact_part}"
    )


def _axis_projection(inp: Input, primary: dict | None, reference: dict | None) -> str:
    for source in (primary, reference, inp.metadata):
        if not source:
            continue
        value = source.get("axis_projection")
        if value:
            return str(value)
    return "unknown"


def _normalized_parse_summary(data: dict | None) -> dict[str, object]:
    if not data:
        return {}
    return {
        "interpretation": _interpretation(data),
        "forwarded_request_hash": data.get("forwarded_request_hash"),
        "effective_headers": data.get("effective_headers"),
        "effective_body_boundary": data.get("effective_body_boundary"),
        "trailer_forwarded": data.get("trailer_forwarded"),
        "routing_decision_source": data.get("routing_decision_source"),
        "cache_decision_source": data.get("cache_decision_source"),
        "axis_projection": data.get("axis_projection"),
    }


def _parse_error_only(primary: dict | None, reference: dict | None) -> bool:
    p = primary or {}
    r = reference or {}
    return (
        (p.get("parse_error") or r.get("parse_error") or p.get("timeout_phase") or r.get("timeout_phase"))
        and not _has_high_signal(primary)
        and not _has_high_signal(reference)
        and p.get("response_count_observed", 0) in (0, 1)
        and r.get("response_count_observed", 0) in (0, 1)
    )


def _diff_pattern_hash(
    *,
    category: str,
    mechanism: str,
    probe_mode: str,
    variant_family: str,
    ref_index: int,
    difference_fields: list[str],
    primary: dict | None,
    reference: dict | None,
) -> str:
    observation_keys = (*_OBSERVATION_KEYS, *_RESPONSE_KEYS, *_CANARY_KEYS, *_IMPACT_KEYS)
    p = primary or {}
    r = reference or {}
    material = {
        "category": category,
        "mechanism": mechanism,
        "probe_mode": probe_mode,
        "variant_family": variant_family,
        "ref_index": ref_index,
        "difference_fields": tuple(sorted(difference_fields)),
        "axis_projection": p.get("axis_projection") or r.get("axis_projection"),
        "primary": {key: p.get(key) for key in observation_keys},
        "reference": {key: r.get(key) for key in observation_keys},
        # High-resolution dimensions
        "primary_smuggled": _smuggled_prefix_hash(primary),
        "ref_smuggled": _smuggled_prefix_hash(reference),
        "primary_info": str(p.get("h2_informational_status") or ""),
        "ref_info": str(r.get("h2_informational_status") or ""),
        "primary_timing": _timing_bucket(p.get("first_response_timing_ms")),
        "ref_timing": _timing_bucket(r.get("first_response_timing_ms")),
        "primary_crc1": str(p.get("first_body_crc32") or ""),
        "ref_crc1": str(r.get("first_body_crc32") or ""),
        "primary_pipeline": str(p.get("pipeline_victim_outcome") or ""),
        "ref_pipeline": str(r.get("pipeline_victim_outcome") or ""),
    }
    return hashlib.sha1(repr(material).encode("utf-8", errors="replace")).hexdigest()[:20]


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
    variant_family = _variant_family(inp, primary_data, reference_data)
    probe_mode = _probe_mode(inp, primary_data, reference_data)
    diff_fields = _difference_fields(primary_data, reference_data)
    diff_hash = _diff_pattern_hash(
        category=category,
        mechanism=mechanism,
        probe_mode=probe_mode,
        variant_family=variant_family,
        ref_index=ref_index,
        difference_fields=diff_fields,
        primary=primary_data,
        reference=reference_data,
    )
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
            "variant_family": variant_family,
            "taxonomy_tags": _taxonomy_tags(inp, primary_data, reference_data),
            "transport_mode": _transport_mode(inp, primary_data, reference_data),
            "probe_mode": probe_mode,
            "axis_projection": _axis_projection(inp, primary_data, reference_data),
            "axis_framing": (primary_data or {}).get("axis_framing") or (reference_data or {}).get("axis_framing") or inp.metadata.get("axis_framing"),
            "axis_leniency": (primary_data or {}).get("axis_leniency") or (reference_data or {}).get("axis_leniency") or inp.metadata.get("axis_leniency"),
            "axis_chunk": (primary_data or {}).get("axis_chunk") or (reference_data or {}).get("axis_chunk") or inp.metadata.get("axis_chunk"),
            "axis_connection": (primary_data or {}).get("axis_connection") or (reference_data or {}).get("axis_connection") or inp.metadata.get("axis_connection"),
            "axis_timing": (primary_data or {}).get("axis_timing") or (reference_data or {}).get("axis_timing") or inp.metadata.get("axis_timing"),
            "axis_routing": (primary_data or {}).get("axis_routing") or (reference_data or {}).get("axis_routing") or inp.metadata.get("axis_routing"),
            "primary_interpretation": _interpretation(primary_data),
            "ref_interpretation": _interpretation(reference_data),
            "frontend_interpretation": _interpretation(primary_data),
            "backend_interpretation": _interpretation(reference_data),
            "primary_parse_summary": _normalized_parse_summary(primary_data),
            "ref_parse_summary": _normalized_parse_summary(reference_data),
            "primary_h2_summary": {
                "reset": (primary_data or {}).get("h2_reset_error"),
                "goaway": (primary_data or {}).get("h2_goaway_error"),
                "events": (primary_data or {}).get("h2_event_trace", []),
            },
            "ref_h2_summary": {
                "reset": (reference_data or {}).get("h2_reset_error"),
                "goaway": (reference_data or {}).get("h2_goaway_error"),
                "events": (reference_data or {}).get("h2_event_trace", []),
            },
            "primary_impact": {
                "seen": (primary_data or {}).get("impact_marker_seen"),
                "type": (primary_data or {}).get("impact_type"),
                "detail": (primary_data or {}).get("impact_detail"),
            },
            "ref_impact": {
                "seen": (reference_data or {}).get("impact_marker_seen"),
                "type": (reference_data or {}).get("impact_type"),
                "detail": (reference_data or {}).get("impact_detail"),
            },
            "primary_observation": {
                "forwarded_request_hash": (primary_data or {}).get("forwarded_request_hash"),
                "effective_headers": (primary_data or {}).get("effective_headers"),
                "effective_body_boundary": (primary_data or {}).get("effective_body_boundary"),
                "trailer_forwarded": (primary_data or {}).get("trailer_forwarded"),
                "routing_decision_source": (primary_data or {}).get("routing_decision_source"),
                "cache_decision_source": (primary_data or {}).get("cache_decision_source"),
            },
            "ref_observation": {
                "forwarded_request_hash": (reference_data or {}).get("forwarded_request_hash"),
                "effective_headers": (reference_data or {}).get("effective_headers"),
                "effective_body_boundary": (reference_data or {}).get("effective_body_boundary"),
                "trailer_forwarded": (reference_data or {}).get("trailer_forwarded"),
                "routing_decision_source": (reference_data or {}).get("routing_decision_source"),
                "cache_decision_source": (reference_data or {}).get("cache_decision_source"),
            },
            "primary_pipeline": {
                "sent": (primary_data or {}).get("pipeline_victim_sent"),
                "outcome": (primary_data or {}).get("pipeline_victim_outcome"),
                "contaminated": (primary_data or {}).get("pipeline_victim_contaminated"),
                "status": (primary_data or {}).get("pipeline_victim_status"),
                "body_preview": (primary_data or {}).get("pipeline_victim_body_preview"),
            },
            "ref_pipeline": {
                "sent": (reference_data or {}).get("pipeline_victim_sent"),
                "outcome": (reference_data or {}).get("pipeline_victim_outcome"),
                "contaminated": (reference_data or {}).get("pipeline_victim_contaminated"),
                "status": (reference_data or {}).get("pipeline_victim_status"),
                "body_preview": (reference_data or {}).get("pipeline_victim_body_preview"),
            },
            "artifact_path_stable": _artifact_path(primary_data) or _artifact_path(reference_data),
            "raw_artifact_path": _artifact_path(primary_data) or _artifact_path(reference_data),
            "replay_command": _replay_command(primary_data) or _replay_command(reference_data),
            "diff_pattern_hash": diff_hash,
            "diff_fields": diff_fields,
            "difference_fields": diff_fields,
            "explanation": (
                f"primary={_summary_label(primary_data)} | "
                f"ref={_summary_label(reference_data)} | "
                f"diff={','.join(diff_fields) if diff_fields else 'none'}"
            ),
            "ref_index": ref_index,
        },
    )


class RequestSmugglingFramingDivergenceStrategy:
    name = "request_smuggling_framing"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if (
            _tuple(p, _RESPONSE_KEYS) == _tuple(r, _RESPONSE_KEYS)
            and _tuple(p, _IMPACT_KEYS) == _tuple(r, _IMPACT_KEYS)
        ):
            return None
        severity = Severity.LOW if _parse_error_only(p, r) else Severity.MEDIUM
        return _make_finding(
            title=f"HTTP request framing divergence against ref[{ref_index}]",
            severity=severity,
            category="framing_divergence",
            mechanism="request_boundary",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class CanaryMisassociationStrategy:
    name = "request_smuggling_canary"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if not any((p.get(key) != r.get(key)) for key in _CANARY_KEYS):
            return None
        if not any(bool(p.get(key)) or bool(r.get(key)) for key in _CANARY_KEYS):
            return None
        return _make_finding(
            title=f"HTTP request canary misassociation against ref[{ref_index}]",
            severity=Severity.HIGH,
            category="canary_misassociation",
            mechanism="canary_reassociation",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class EarlyResponseDesyncStrategy:
    name = "request_smuggling_early_response"

    _EARLY_CODES = {100, 301, 302, 400, 401, 403, 413}
    _EARLY_OUTCOMES = {"early_response_before_body", "late_bytes_consumed_as_second"}

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        p_early = bool(p.get("first_response_status") in self._EARLY_CODES or p.get("probe_outcome") in self._EARLY_OUTCOMES)
        r_early = bool(r.get("first_response_status") in self._EARLY_CODES or r.get("probe_outcome") in self._EARLY_OUTCOMES)
        p_follow = bool(p.get("second_response_status") is not None or p.get("response_count_observed", 0) > 1 or p.get("extra_bytes_left"))
        r_follow = bool(r.get("second_response_status") is not None or r.get("response_count_observed", 0) > 1 or r.get("extra_bytes_left"))
        if p_early == r_early and p_follow == r_follow:
            return None
        if not (p_early or r_early):
            return None
        return _make_finding(
            title=f"HTTP early-response desync against ref[{ref_index}]",
            severity=Severity.HIGH,
            category="early_response_desync",
            mechanism="early_response_gadget",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class DowngradeSemanticGapStrategy:
    name = "request_smuggling_h2_gap"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        transport = _transport_mode(inp, p, r)
        if not transport.startswith("h2"):
            return None
        if _tuple(p, _RESPONSE_KEYS) == _tuple(r, _RESPONSE_KEYS) and _tuple(p, _CANARY_KEYS) == _tuple(r, _CANARY_KEYS):
            return None
        severity = Severity.HIGH if (_has_high_signal(p) or _has_high_signal(r)) else Severity.MEDIUM
        return _make_finding(
            title=f"HTTP/2 downgrade semantic gap against ref[{ref_index}]",
            severity=severity,
            category="downgrade_semantic_gap",
            mechanism="h2_downgrade",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class PauseDesyncCandidateStrategy:
    name = "request_smuggling_pause_probe"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        probe_mode = _probe_mode(inp, p, r)
        if probe_mode not in _PAUSE_PROBES:
            return None
        signal = (
            p.get("probe_outcome") != r.get("probe_outcome")
            or p.get("response_count_observed") != r.get("response_count_observed")
            or p.get("timeout_phase") != r.get("timeout_phase")
            or p.get("second_response_status") != r.get("second_response_status")
        )
        if not signal:
            return None
        severity = Severity.HIGH if (_has_high_signal(p) or _has_high_signal(r)) else Severity.MEDIUM
        if _parse_error_only(p, r):
            severity = Severity.LOW
        return _make_finding(
            title=f"HTTP pause-based desync candidate against ref[{ref_index}]",
            severity=severity,
            category="pause_desync_candidate",
            mechanism="pause_probe",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class ChunkSemanticGapStrategy:
    name = "request_smuggling_chunk_gap"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        family = _variant_family(inp, p, r)
        if family not in _CHUNK_FAMILIES:
            return None
        keys = ("parse_error", "timeout_phase", "extra_bytes_left", "response_count_observed", "second_response_status")
        if _tuple(p, keys) == _tuple(r, keys):
            return None
        severity = Severity.HIGH if (_has_high_signal(p) or _has_high_signal(r)) else Severity.MEDIUM
        if family in _TRAILER_FAMILIES and _tuple(p, _IMPACT_KEYS) != _tuple(r, _IMPACT_KEYS):
            severity = Severity.HIGH
        if _parse_error_only(p, r):
            severity = Severity.LOW
        return _make_finding(
            title=f"HTTP chunk semantic gap against ref[{ref_index}]",
            severity=severity,
            category="chunk_semantic_gap",
            mechanism="chunk_parser",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class RoutingSemanticGapStrategy:
    name = "request_smuggling_routing_gap"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        routing_keys = (
            "routing_decision_source",
            "cache_decision_source",
            "impact_type",
            "impact_detail",
            "forwarded_request_hash",
        )
        if _tuple(p, routing_keys) == _tuple(r, routing_keys):
            return None
        if not any(
            bool((p or {}).get(key) or (r or {}).get(key))
            for key in ("routing_decision_source", "cache_decision_source", "impact_type")
        ):
            return None
        severity = Severity.HIGH if (_has_high_signal(p) or _has_high_signal(r)) else Severity.MEDIUM
        return _make_finding(
            title=f"HTTP routing semantic gap against ref[{ref_index}]",
            severity=severity,
            category="routing_semantic_gap",
            mechanism="routing_headers",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class TrailerEffectiveHeaderGapStrategy:
    name = "request_smuggling_trailer_effective_header_gap"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if not (
            bool((p or {}).get("trailer_forwarded"))
            or bool((r or {}).get("trailer_forwarded"))
            or "trailer" in str((p or {}).get("variant_family") or "")
            or "trailer" in str((r or {}).get("variant_family") or "")
        ):
            return None
        keys = ("trailer_forwarded", "trailer_merge_keys", "effective_headers", "routing_decision_source", "cache_decision_source")
        if _tuple(p, keys) == _tuple(r, keys):
            return None
        severity = Severity.HIGH if (_has_high_signal(p) or _has_high_signal(r)) else Severity.MEDIUM
        return _make_finding(
            title=f"HTTP trailer effective-header gap against ref[{ref_index}]",
            severity=severity,
            category="trailer_effective_header_gap",
            mechanism="trailer_merge",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class ConnectionLockedDesyncStrategy:
    name = "request_smuggling_connection_locked"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        probe_mode = _probe_mode(inp, p, r)
        if probe_mode not in _LOCK_PROBES:
            return None
        signal = (
            p.get("probe_outcome") != r.get("probe_outcome")
            or p.get("response_count_observed") != r.get("response_count_observed")
            or p.get("timeout_phase") != r.get("timeout_phase")
            or p.get("first_response_status") != r.get("first_response_status")
        )
        if not signal:
            return None
        severity = Severity.HIGH if (_has_high_signal(p) or _has_high_signal(r)) else Severity.MEDIUM
        if _parse_error_only(p, r):
            severity = Severity.LOW
        return _make_finding(
            title=f"HTTP connection-locked desync against ref[{ref_index}]",
            severity=severity,
            category="connection_locked_desync",
            mechanism="connection_locked",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


_PIPELINE_KEYS = (
    "pipeline_victim_sent",
    "pipeline_victim_status",
    "pipeline_victim_outcome",
    "pipeline_victim_contaminated",
)


class PipelinePoisoningStrategy:
    """Detects confirmed cross-request pipeline poisoning.

    When the target's pipeline victim probe detected contamination
    (victim got a response meant for a smuggled request), this fires
    as CRITICAL — it means real exploitable request smuggling.
    """

    name = "request_smuggling_pipeline_poisoning"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None

        p_contaminated = bool((p or {}).get("pipeline_victim_contaminated"))
        r_contaminated = bool((r or {}).get("pipeline_victim_contaminated"))

        if not (p_contaminated or r_contaminated):
            return None

        return _make_finding(
            title=f"CONFIRMED pipeline poisoning against ref[{ref_index}]",
            severity=Severity.CRITICAL,
            category="pipeline_poisoning",
            mechanism="cross_request_contamination",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class DesyncPreconditionStrategy:
    """Detects desync preconditions: backend processed extra requests
    AND connection stayed alive, but pipeline victim probe was clean.

    This is HIGH — the parsing divergence is real, but exploitation
    wasn't confirmed on this specific connection.
    """

    name = "request_smuggling_desync_precondition"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None

        # Only fire when pipeline probe was sent but came back clean
        p_sent = bool((p or {}).get("pipeline_victim_sent"))
        r_sent = bool((r or {}).get("pipeline_victim_sent"))
        if not (p_sent or r_sent):
            return None

        p_contaminated = bool((p or {}).get("pipeline_victim_contaminated"))
        r_contaminated = bool((r or {}).get("pipeline_victim_contaminated"))
        if p_contaminated or r_contaminated:
            return None  # PipelinePoisoningStrategy handles this

        # Check that there IS a response count divergence
        p_count = int((p or {}).get("response_count_observed") or 0)
        r_count = int((r or {}).get("response_count_observed") or 0)
        if p_count == r_count:
            return None

        return _make_finding(
            title=f"Desync precondition met (probe clean) against ref[{ref_index}]",
            severity=Severity.HIGH,
            category="desync_precondition",
            mechanism="response_count_divergence_connection_alive",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


def get_request_smuggling_strategies() -> list:
    return [
        PipelinePoisoningStrategy(),
        DesyncPreconditionStrategy(),
        RequestSmugglingFramingDivergenceStrategy(),
        CanaryMisassociationStrategy(),
        EarlyResponseDesyncStrategy(),
        DowngradeSemanticGapStrategy(),
        PauseDesyncCandidateStrategy(),
        ChunkSemanticGapStrategy(),
        RoutingSemanticGapStrategy(),
        TrailerEffectiveHeaderGapStrategy(),
        ConnectionLockedDesyncStrategy(),
    ]
