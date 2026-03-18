"""Java deserialization differential strategies for cross-library comparison.

Architecture mirrors JWT oracle patterns:
- Per-attack-class strategies with parsed JSON gating
- Compares deserialization behavior across open vs filtered targets
- Sink-reach and filter-bypass detection for gadget chain analysis

Target output JSON format:
    {
        "compiled": true,
        "deserialized": true/false,
        "sink_reached": "cmd_exec" or null,
        "sink_depth": 3,
        "chain_classes": ["PriorityQueue", "TransformingComparator", ...],
        "chain_class_hash": "abc123",
        "filter_decision": "ALLOWED" / "REJECTED",
        "filter_rejected_class": null / "InvokerTransformer",
        "readObject_calls": 5,
        "method_invocations": ["reflection:...", "cmd_exec:..."],
        "method_invocation_hash": "def456",
        "process_spawned": true/false,
        "jndi_lookup": true/false,
        "class_loaded": true/false,
        "file_accessed": true/false,
        "network_connected": true/false,
        "duration_ms": 15
    }
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_deser_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a deserialization target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and (
            "deserialized" in data
            or "sink_reached" in data
            or "filter_decision" in data
        ):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


# ── Sink severity mapping ────────────────────────────────────────

_SINK_SEVERITY: dict[str, Severity] = {
    "cmd_exec": Severity.CRITICAL,
    "jndi_lookup": Severity.CRITICAL,
    "script_exec": Severity.CRITICAL,
    "file_write": Severity.HIGH,
    "file_read": Severity.HIGH,
    "network": Severity.HIGH,
    "class_load": Severity.HIGH,
    "reflection": Severity.MEDIUM,
}


def _sink_severity(sink: str | None) -> Severity:
    """Map a sink type to its severity."""
    if not sink:
        return Severity.MEDIUM
    return _SINK_SEVERITY.get(sink.lower(), Severity.HIGH)


def _has_dangerous_behavior(parsed: dict) -> bool:
    """Check if deserialization produced any security-relevant side effect.

    Returns True when ANY of these runtime indicators is present:
      - sink_reached is non-null (cmd_exec, jndi_lookup, etc.)
      - Side-effect boolean flags are True

    This is a Java-serialization invariant check: if readObject() is empty,
    readResolve() returns a singleton, or sink fields are transient, the
    target will report no dangerous behavior regardless of environment.
    Safe to use as a severity gate because it relies on *observed runtime
    output*, not on class-name predictions that could miss variants.
    """
    if parsed.get("sink_reached"):
        return True
    _SIDE_EFFECT_KEYS = (
        "process_spawned", "jndi_lookup", "script_executed",
        "class_loaded", "file_accessed", "network_connected",
        "thread_spawned",
    )
    return any(parsed.get(k) for k in _SIDE_EFFECT_KEYS)


def _sink_mechanism(p_sink: str | None, r_sink: str | None) -> str:
    """Classify the divergence mechanism for sink reach."""
    p = (p_sink or "none").lower()
    r = (r_sink or "none").lower()
    if p != "none" and r == "none":
        return "primary_reaches_sink"
    if p == "none" and r != "none":
        return "ref_reaches_sink"
    if p != r:
        return "different_sinks"
    return "same_sink"


# ── Per-Attack-Class Strategies ──────────────────────────────────


class SinkReachDivergenceStrategy:
    """Detect when one target reaches a dangerous sink but the other doesn't.

    CRITICAL for cmd_exec, jndi_lookup, script_exec sinks.
    HIGH for file_write, network, class_load sinks.
    Also fires on side-effect divergences (process_spawned, jndi_lookup flags).
    """

    name = "deser_sink_reach"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | None:
        p = _parse_deser_output(primary.stdout)
        r = _parse_deser_output(reference.stdout)
        if p is None or r is None:
            return None

        all_findings: list[Finding] = []

        # sink_reached divergence
        p_sink = p.get("sink_reached")
        r_sink = r.get("sink_reached")
        if p_sink != r_sink and (p_sink is not None or r_sink is not None):
            # Severity based on the more dangerous sink
            reaching_sink = p_sink or r_sink
            severity = _sink_severity(reaching_sink)
            reaching_side = "primary" if p_sink else f"ref[{ref_index}]"

            all_findings.append(Finding(
                title=(
                    f"Deser Sink Reach Divergence: {reaching_side} reaches "
                    f"{reaching_sink!r} (ref[{ref_index}])"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "sink_reach_divergence",
                    "mechanism": _sink_mechanism(p_sink, r_sink),
                    "primary_sink": p_sink,
                    "ref_sink": r_sink,
                    "reaching_side": reaching_side,
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            ))

        # Side-effect flag divergences
        _SIDE_EFFECT_FIELDS = [
            ("process_spawned", "process_spawn_divergence", Severity.CRITICAL),
            ("jndi_lookup", "jndi_lookup_divergence", Severity.CRITICAL),
            ("class_loaded", "class_load_divergence", Severity.HIGH),
            ("file_accessed", "file_access_divergence", Severity.HIGH),
            ("network_connected", "network_connect_divergence", Severity.HIGH),
        ]
        for field, category, severity in _SIDE_EFFECT_FIELDS:
            pv = p.get(field)
            rv = r.get(field)
            if pv != rv and (pv is not None or rv is not None):
                triggering_side = "primary" if pv else f"ref[{ref_index}]"
                all_findings.append(Finding(
                    title=(
                        f"Deser Side-Effect Divergence: {triggering_side} "
                        f"triggers {field} (ref[{ref_index}])"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "mechanism": field,
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "triggering_side": triggering_side,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                ))

        return all_findings or None


class FilterBypassStrategy:
    """Detect filter bypass: a filtered target accepts deserialization unexpectedly.

    CRITICAL when: ref target's filter_decision="REJECTED" but test target's
    filter_decision="ALLOWED" AND deserialized=true.
    Reports which class was expected to be rejected but wasn't.
    """

    name = "deser_filter_bypass"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_deser_output(primary.stdout)
        r = _parse_deser_output(reference.stdout)
        if p is None or r is None:
            return None

        p_filter = str(p.get("filter_decision") or "").upper()
        r_filter = str(r.get("filter_decision") or "").upper()

        # Check both directions: primary bypasses ref's filter, or vice versa
        bypass_found = False
        bypassing_side = ""
        filtered_data: dict = {}
        bypassing_data: dict = {}

        if r_filter == "REJECTED" and p_filter == "ALLOWED" and p.get("deserialized") is True:
            bypass_found = True
            bypassing_side = "primary"
            filtered_data = r
            bypassing_data = p
        elif p_filter == "REJECTED" and r_filter == "ALLOWED" and r.get("deserialized") is True:
            bypass_found = True
            bypassing_side = f"ref[{ref_index}]"
            filtered_data = p
            bypassing_data = r

        if not bypass_found:
            return None

        # Determine which class was expected to be rejected
        rejected_class = filtered_data.get("filter_rejected_class")
        sink_reached = bypassing_data.get("sink_reached")

        # Escalate severity if the bypass leads to a dangerous sink
        severity = Severity.CRITICAL
        if sink_reached:
            mechanism = f"filter_bypass_to_{sink_reached}"
        else:
            mechanism = "filter_bypass_deser_only"

        return Finding(
            title=(
                f"Deser Filter Bypass: {bypassing_side} bypasses filter "
                f"for class {rejected_class!r} (ref[{ref_index}])"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "filter_bypass",
                "mechanism": mechanism,
                "bypassing_side": bypassing_side,
                "filter_rejected_class": rejected_class,
                "sink_reached_after_bypass": sink_reached,
                "primary_filter": p_filter,
                "ref_filter": r_filter,
                "primary_deserialized": p.get("deserialized"),
                "ref_deserialized": r.get("deserialized"),
                "chain_classes": bypassing_data.get("chain_classes"),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


class ChainDepthDivergenceStrategy:
    """Detect different chain resolution depths during deserialization.

    MEDIUM severity when sink_depth differs by more than 2 between targets.
    A significant depth difference suggests different gadget chain resolution
    paths, which may indicate exploitable differences in class resolution.
    """

    name = "deser_chain_depth"

    _DEPTH_THRESHOLD = 2

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_deser_output(primary.stdout)
        r = _parse_deser_output(reference.stdout)
        if p is None or r is None:
            return None

        p_depth = p.get("sink_depth")
        r_depth = r.get("sink_depth")

        # Both must report depth for meaningful comparison
        if not isinstance(p_depth, (int, float)) or not isinstance(r_depth, (int, float)):
            return None

        diff = abs(p_depth - r_depth)
        if diff <= self._DEPTH_THRESHOLD:
            return None

        deeper_side = "primary" if p_depth > r_depth else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"Deser Chain Depth Divergence: {deeper_side} resolves "
                f"depth {max(p_depth, r_depth)} vs {min(p_depth, r_depth)} "
                f"(diff={diff}, ref[{ref_index}])"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "chain_depth_divergence",
                "mechanism": "depth_diff",
                "primary_depth": p_depth,
                "ref_depth": r_depth,
                "depth_diff": diff,
                "deeper_side": deeper_side,
                "primary_chain_classes": p.get("chain_classes"),
                "ref_chain_classes": r.get("chain_classes"),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


class ClassResolutionDivergenceStrategy:
    """Detect different classes resolved during deserialization.

    HIGH severity when chain_class_hash values differ between targets,
    indicating the two implementations resolved a different set of classes
    for the same serialized input. This can reveal gadget chains that one
    implementation blocks while the other allows.
    """

    name = "deser_class_resolution"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_deser_output(primary.stdout)
        r = _parse_deser_output(reference.stdout)
        if p is None or r is None:
            return None

        # Both must have deserialized to have meaningful class hashes
        if not p.get("deserialized") or not r.get("deserialized"):
            return None

        p_hash = p.get("chain_class_hash")
        r_hash = r.get("chain_class_hash")

        if p_hash is None or r_hash is None:
            return None
        if p_hash == r_hash:
            return None

        # Determine mechanism from class lists
        p_classes = set(p.get("chain_classes") or [])
        r_classes = set(r.get("chain_classes") or [])
        primary_only = p_classes - r_classes
        ref_only = r_classes - p_classes

        if primary_only and not ref_only:
            mechanism = "primary_extra_classes"
        elif ref_only and not primary_only:
            mechanism = "ref_extra_classes"
        elif primary_only and ref_only:
            mechanism = "divergent_classes"
        else:
            mechanism = "hash_diff"

        return Finding(
            title=(
                f"Deser Class Resolution Divergence: "
                f"chain_class_hash {p_hash[:8]}... vs {r_hash[:8]}... "
                f"(ref[{ref_index}])"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "type_resolution_divergence",
                "mechanism": mechanism,
                "primary_class_hash": p_hash,
                "ref_class_hash": r_hash,
                "primary_classes": sorted(p_classes),
                "ref_classes": sorted(r_classes),
                "primary_only_classes": sorted(primary_only),
                "ref_only_classes": sorted(ref_only),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


class ExceptionDivergenceStrategy:
    """Detect deserialization success/failure divergence.

    MEDIUM severity when one target successfully deserializes but the other
    throws an exception. Partial deserialization (deserialized=true but with
    errors or limited sink reach) is especially interesting as it may indicate
    a bypass path.
    """

    name = "deser_exception"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_deser_output(primary.stdout)
        r = _parse_deser_output(reference.stdout)
        if p is None or r is None:
            return None

        p_deser = p.get("deserialized")
        r_deser = r.get("deserialized")

        if p_deser == r_deser:
            return None
        # Skip when both are None/absent
        if p_deser is None and r_deser is None:
            return None

        accepting_side = "primary" if p_deser else f"ref[{ref_index}]"
        accepting_data = p if p_deser else r
        rejecting_data = r if p_deser else p

        dangerous = _has_dangerous_behavior(accepting_data)

        # Escalate to HIGH when accepting side reaches a sink
        severity = Severity.MEDIUM
        mechanism = "accept_reject"
        sink = accepting_data.get("sink_reached")
        if sink:
            severity = Severity.HIGH
            mechanism = f"accept_reject_with_sink_{sink}"

        # Detect partial deserialization: accepting side deserialized but
        # readObject_calls is low or chain is short.
        # Only escalate when dangerous behavior was observed — empty
        # readObject() or readResolve-singleton chains produce low
        # readObject_calls without any security impact (Java invariant).
        p_calls = accepting_data.get("readObject_calls", 0)
        if isinstance(p_calls, int) and 0 < p_calls <= 2 and dangerous:
            mechanism = "partial_deserialization"
            severity = Severity.HIGH

        # Downgrade to LOW when accepting side produced no dangerous
        # behavior at all.  This catches dead chains caused by Java
        # serialization invariants (empty readObject, readResolve
        # singleton, transient sink fields, NOT-Serializable
        # intermediaries, type-mismatch ClassCastExceptions).
        # Safe: based on observed runtime output, not class-name guesses.
        if not dangerous and severity is not Severity.LOW:
            severity = Severity.LOW
            mechanism = f"dead_chain:{mechanism}"

        return Finding(
            title=(
                f"Deser Exception Divergence: {accepting_side} deserializes "
                f"but the other rejects (ref[{ref_index}])"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "exception_divergence",
                "mechanism": mechanism,
                "accepting_side": accepting_side,
                "primary_deserialized": p_deser,
                "ref_deserialized": r_deser,
                "accepting_sink": accepting_data.get("sink_reached"),
                "accepting_readObject_calls": accepting_data.get("readObject_calls"),
                "accepting_chain_classes": accepting_data.get("chain_classes"),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


# ── Strategy aggregation ─────────────────────────────────────────


def get_deser_strategies() -> list:
    """Return deserialization-focused differential strategies plus defaults.

    Architecture:
    - SinkReachDivergenceStrategy: ungated, detects sink_reached + side-effect divergence
    - FilterBypassStrategy: ungated, detects filter_decision bypass
    - ChainDepthDivergenceStrategy: ungated, detects sink_depth divergence (>2)
    - ClassResolutionDivergenceStrategy: gated on deserialized=True, detects class hash divergence
    - ExceptionDivergenceStrategy: ungated, detects deserialized true vs false
    """
    from .diff_oracle import DEFAULT_STRATEGIES

    base = [s for s in DEFAULT_STRATEGIES if getattr(s, "name", "") != "output"]
    return base + [
        SinkReachDivergenceStrategy(),
        FilterBypassStrategy(),
        ChainDepthDivergenceStrategy(),
        ClassResolutionDivergenceStrategy(),
        ExceptionDivergenceStrategy(),
    ]
