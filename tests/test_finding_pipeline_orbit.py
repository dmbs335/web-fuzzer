"""Tests for the E6 Stage A orbit hook in FindingProcessor.

Two findings whose inputs are syntactic permutations of the same SAML
payload (attribute reorder, whitespace shuffle) must:
  - receive the same ``orbit_canonical_key`` in their metadata,
  - get ``orbit_status == "first"`` on the first emission and
    ``duplicate_downgraded`` thereafter,
  - have non-CRITICAL severities downgraded to INFO on the second and
    later emissions — CRITICAL/HIGH are preserved verbatim.

The test uses tiny fake collaborators so we can exercise the pipeline
without pulling in the full engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webfuzzer.fuzzer.engine import _DefaultDeduplicator
from webfuzzer.fuzzer.finding_pipeline import FindingProcessor
from webfuzzer.fuzzer.protocols import (
    ExecutionResult,
    Finding,
    Input,
    Severity,
)


# ── fakes ────────────────────────────────────────────────────────

class _FakeDeduplicator:
    def __init__(self) -> None:
        self.registered: list[Finding] = []
        self._counter = 0

    def fingerprint(self, finding: Finding) -> str:
        self._counter += 1
        # Distinct fingerprint per call so the dedup check never fires —
        # we want to isolate the orbit hook from the existing fingerprint
        # dedup layer.
        return f"fp-{self._counter}"

    def is_duplicate(self, finding: Finding) -> bool:
        return False

    def register(self, finding: Finding) -> None:
        self.registered.append(finding)


class _DuplicateOnSecondDedup:
    def __init__(self) -> None:
        self._registered = False

    def fingerprint(self, finding: Finding) -> str:
        return "same-fp"

    def is_duplicate(self, finding: Finding) -> bool:
        return self._registered

    def register(self, finding: Finding) -> None:
        self._registered = True


class _CoarseThenFineDedup:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def fingerprint(self, finding: Finding) -> str:
        fine = str(finding.metadata.get("fine_fingerprint", "") or "fine-default")
        finding.metadata.setdefault(
            "fingerprint_components",
            {
                "mode": "birkhoff_bitvector",
                "bitvector_atoms": ["host", "path"],
            },
        )
        finding.metadata.setdefault("fine_fingerprint", fine)
        return "same-coarse-fp"

    def is_duplicate(self, finding: Finding) -> bool:
        return finding.fingerprint in self._seen

    def register(self, finding: Finding) -> None:
        self._seen.add(finding.fingerprint)


class _PatternThenFineDedup:
    def __init__(self) -> None:
        self._seen: set[str] = set()

    def fingerprint(self, finding: Finding) -> str:
        fine = str(finding.metadata.get("fine_fingerprint", "") or "fine-default")
        finding.metadata.setdefault(
            "fingerprint_components",
            {
                "mode": "diff_pattern_hash",
                "diff_pattern_hash": "hash-a",
            },
        )
        finding.metadata.setdefault("fine_fingerprint", fine)
        return "same-pattern-fp"

    def is_duplicate(self, finding: Finding) -> bool:
        return finding.fingerprint in self._seen

    def register(self, finding: Finding) -> None:
        self._seen.add(finding.fingerprint)


@dataclass
class _FakePublisher:
    emitted: list[dict] = field(default_factory=list)

    def publish_finding(self, **kwargs: Any) -> None:
        self.emitted.append(kwargs)


@dataclass
class _FakeStats:
    recorded: list[tuple[Finding, str]] = field(default_factory=list)
    observed: list[Finding] = field(default_factory=list)
    selection_drops: list[str] = field(default_factory=list)
    orbit_downgrades: list[str] = field(default_factory=list)

    def record_observed_finding(self, finding: Finding) -> None:
        self.observed.append(finding)

    def record_selection_drop(self, reason: str) -> None:
        self.selection_drops.append(reason)

    def record_orbit_downgrade(self, reason: str) -> None:
        self.orbit_downgrades.append(reason)

    def record_finding(self, finding: Finding, mutator_name: str = "") -> None:
        self.recorded.append((finding, mutator_name))


class _StaticOracle:
    oracle_name = "static"

    def __init__(self, finding: Finding) -> None:
        self._finding = finding

    def check(self, inp: Input, result: ExecutionResult) -> Finding:
        return self._finding


def _make_finding(body: bytes, severity: Severity) -> Finding:
    return Finding(
        title="test",
        severity=severity,
        input=Input(data=body),
        result=ExecutionResult(),
        oracle_name="static",
        metadata={},
    )


def _make_processor() -> tuple[FindingProcessor, _FakePublisher]:
    publisher = _FakePublisher()
    processor = FindingProcessor(
        oracles=[],  # populated per-call below
        deduplicator=_FakeDeduplicator(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
    )
    return processor, publisher


def _make_processor_with_drop_sink(sink) -> tuple[FindingProcessor, _FakePublisher]:
    publisher = _FakePublisher()
    processor = FindingProcessor(
        oracles=[],
        deduplicator=_DuplicateOnSecondDedup(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
        selection_drop_sink=sink,
    )
    return processor, publisher


def _make_processor_with_shadow_sink(drop_sink, shadow_sink) -> tuple[FindingProcessor, _FakePublisher]:
    publisher = _FakePublisher()
    processor = FindingProcessor(
        oracles=[],
        deduplicator=_CoarseThenFineDedup(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
        selection_drop_sink=drop_sink,
        selection_shadow_sink=shadow_sink,
    )
    return processor, publisher


def _make_processor_with_default_dedup() -> tuple[FindingProcessor, _FakePublisher]:
    publisher = _FakePublisher()
    processor = FindingProcessor(
        oracles=[],
        deduplicator=_DefaultDeduplicator(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
    )
    return processor, publisher


def _make_processor_with_pattern_shadow_sink(
    drop_sink, shadow_sink
) -> tuple[FindingProcessor, _FakePublisher]:
    publisher = _FakePublisher()
    processor = FindingProcessor(
        oracles=[],
        deduplicator=_PatternThenFineDedup(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
        selection_drop_sink=drop_sink,
        selection_shadow_sink=shadow_sink,
    )
    return processor, publisher


def _run(processor: FindingProcessor, finding: Finding) -> None:
    processor.oracles = [_StaticOracle(finding)]
    processor.check(finding.input, finding.result)


# ── tests ────────────────────────────────────────────────────────

_SAML_A = (
    b'<saml:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    b' ID="abc" Version="2.0">body</saml:Response>'
)
# Same document, attribute order flipped and whitespace between tags
# reshuffled — byte-distinct but orbit-equivalent.
_SAML_B = (
    b'<saml:Response   Version="2.0"  ID="abc"'
    b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">body</saml:Response>'
)
# Completely different document — should land in its own orbit.
_SAML_C = b'<x:Response xmlns:x="urn:x" Id="zzz">different</x:Response>'


def test_first_finding_in_orbit_is_not_downgraded():
    processor, publisher = _make_processor()
    finding = _make_finding(_SAML_A, Severity.MEDIUM)
    _run(processor, finding)

    assert len(publisher.emitted) == 1
    emitted = publisher.emitted[0]
    assert emitted["severity"] == "medium"
    meta = emitted["metadata"]
    assert meta["orbit_status"] == "first"
    assert "orbit_canonical_key" in meta
    assert "orbit_original_severity" not in meta


def test_second_finding_in_same_orbit_is_downgraded():
    processor, publisher = _make_processor()

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    _run(processor, second)

    assert len(publisher.emitted) == 2
    first_meta = publisher.emitted[0]["metadata"]
    second_meta = publisher.emitted[1]["metadata"]

    # Same orbit key → the transform chain agrees A and B are equivalent.
    assert first_meta["orbit_canonical_key"] == second_meta["orbit_canonical_key"]

    # Second emission is pinned to INFO with the original severity kept
    # for audit.
    assert second_meta["orbit_status"] == "duplicate_downgraded"
    assert second_meta["orbit_downgrade_reason"] == "same_orbit_same_pattern"
    assert second_meta["orbit_original_severity"] == "medium"
    assert publisher.emitted[1]["severity"] == "info"


def test_critical_is_never_downgraded_even_on_orbit_hit():
    processor, publisher = _make_processor()

    _run(processor, _make_finding(_SAML_A, Severity.INFO))
    _run(processor, _make_finding(_SAML_B, Severity.CRITICAL))

    assert publisher.emitted[1]["severity"] == "critical"
    second_meta = publisher.emitted[1]["metadata"]
    assert second_meta["orbit_status"] == "duplicate_downgraded"
    assert second_meta["orbit_downgrade_reason"] == "same_orbit_same_pattern"
    # CRITICAL was not rewritten, so no "original severity" shadow was
    # recorded — the current severity IS the original.
    assert "orbit_original_severity" not in second_meta


def test_distinct_orbits_are_independent():
    processor, publisher = _make_processor()

    _run(processor, _make_finding(_SAML_A, Severity.MEDIUM))
    _run(processor, _make_finding(_SAML_C, Severity.MEDIUM))

    a_key = publisher.emitted[0]["metadata"]["orbit_canonical_key"]
    c_key = publisher.emitted[1]["metadata"]["orbit_canonical_key"]
    assert a_key != c_key
    assert publisher.emitted[0]["severity"] == "medium"
    assert publisher.emitted[1]["severity"] == "medium"
    assert publisher.emitted[1]["metadata"]["orbit_status"] == "first"


def test_orbit_metadata_tracks_seen_count_and_downgrade_flag():
    processor, publisher = _make_processor()

    _run(processor, _make_finding(_SAML_A, Severity.MEDIUM))
    _run(processor, _make_finding(_SAML_B, Severity.MEDIUM))

    first_meta = publisher.emitted[0]["metadata"]
    second_meta = publisher.emitted[1]["metadata"]

    assert first_meta["orbit_seen_count"] == 1
    assert first_meta["orbit_downgraded"] is False
    assert second_meta["orbit_seen_count"] == 2
    assert second_meta["orbit_downgraded"] is True
    assert second_meta["orbit_downgrade_reason"] == "same_orbit_same_pattern"


def test_duplicate_fingerprint_is_recorded_in_selection_drop_sink():
    drops: list[dict[str, Any]] = []
    processor, publisher = _make_processor_with_drop_sink(drops.append)

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.metadata["category"] = "accept_reject"
    first.metadata["strategy"] = "output"
    first.metadata["diff_fields"] = ["host"]
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.metadata["category"] = "accept_reject"
    second.metadata["strategy"] = "output"
    second.metadata["diff_fields"] = ["host"]
    _run(processor, second)

    assert len(publisher.emitted) == 1
    assert len(drops) == 1
    drop = drops[0]
    assert drop["drop_stage"] == "dedup"
    assert drop["drop_reason"] == "duplicate_fingerprint"
    assert drop["fingerprint"] == "same-fp"
    assert drop["metadata"]["category"] == "accept_reject"
    assert drop["metadata"]["strategy"] == "output"
    assert drop["metadata"]["diff_fields"] == ["host"]


def test_same_orbit_different_pattern_is_preserved():
    processor, publisher = _make_processor()

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.metadata["diff_pattern_hash"] = "pattern-a"
    first.metadata["strategy"] = "output"
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.metadata["diff_pattern_hash"] = "pattern-b"
    second.metadata["strategy"] = "output"
    _run(processor, second)

    second_meta = publisher.emitted[1]["metadata"]
    assert second_meta["orbit_status"] == "variant_preserved"
    assert second_meta["orbit_downgraded"] is False
    assert second_meta["orbit_downgrade_reason"] == "same_orbit_diff_pattern"
    assert publisher.emitted[1]["severity"] == "medium"


def test_same_orbit_different_oracle_is_preserved():
    processor, publisher = _make_processor()

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.oracle_name = "oracle-a"
    first.metadata["diff_pattern_hash"] = "pattern"
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.oracle_name = "oracle-b"
    second.metadata["diff_pattern_hash"] = "pattern"
    _run(processor, second)

    second_meta = publisher.emitted[1]["metadata"]
    assert second_meta["orbit_status"] == "variant_preserved"
    assert second_meta["orbit_downgraded"] is False
    assert second_meta["orbit_downgrade_reason"] == "same_orbit_diff_oracle"
    assert publisher.emitted[1]["severity"] == "medium"


def test_published_finding_carries_multi_view_record():
    processor, publisher = _make_processor()

    finding = _make_finding(_SAML_A, Severity.MEDIUM)
    finding.input.metadata["session_key"] = "sess-published"
    finding.input.metadata["prefix_depth"] = 1
    finding.result.metadata["replay_context"] = {"phase": "live"}
    _run(processor, finding)

    emitted = publisher.emitted[0]
    meta = emitted["metadata"]
    assert meta["raw_view"]["state"] == "observed_candidate"
    assert meta["raw_view"]["session_key"] == "sess-published"
    assert meta["publish_view"]["state"] == "published"
    assert meta["historical_view"]["state"] == "persisted_finding"
    assert meta["historical_view"]["persisted"] is True


def test_duplicate_pattern_reason_is_more_specific_than_duplicate_fingerprint():
    class _PatternDedup(_DuplicateOnSecondDedup):
        def fingerprint(self, finding: Finding) -> str:
            finding.metadata["fingerprint_components"] = {
                "mode": "diff_pattern_hash",
                "diff_pattern_hash": "hash-a",
            }
            finding.metadata["fine_fingerprint"] = "fine-a"
            return "same-pattern-fp"

    publisher = _FakePublisher()
    drops: list[dict[str, Any]] = []
    processor = FindingProcessor(
        oracles=[],
        deduplicator=_PatternDedup(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
        selection_drop_sink=drops.append,
    )

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    _run(processor, first)
    second = _make_finding(_SAML_B, Severity.MEDIUM)
    _run(processor, second)

    assert len(drops) == 1
    assert drops[0]["drop_reason"] == "duplicate_exact_pattern"


def test_fine_preserve_bucket_keeps_one_new_fine_variant():
    drops: list[dict[str, Any]] = []
    shadows: list[dict[str, Any]] = []
    processor, publisher = _make_processor_with_shadow_sink(drops.append, shadows.append)

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.metadata["strategy"] = "output"
    first.metadata["fine_fingerprint"] = "fine-a"
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.metadata["strategy"] = "output"
    second.metadata["fine_fingerprint"] = "fine-b"
    _run(processor, second)

    assert len(publisher.emitted) == 2
    second_meta = publisher.emitted[1]["metadata"]
    assert second_meta["selection_branch"] == "fine_preserve_bucket"
    assert second_meta["selection_preserved_from_duplicate"] is True
    assert second_meta["coarse_fingerprint"] == "same-coarse-fp"
    assert second_meta["selection_policy"]["branch"] == "fine_preserve_bucket"
    assert second_meta["selection_policy"]["contract_ok"] is True
    assert second_meta["selection_policy"]["evidence"]["has_preservation_witness"] is True
    assert drops == []
    assert shadows == []


def test_shadow_queue_review_preserves_drop_in_shadow_sink():
    drops: list[dict[str, Any]] = []
    shadows: list[dict[str, Any]] = []
    processor, publisher = _make_processor_with_shadow_sink(drops.append, shadows.append)

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.oracle_name = "oracle-a"
    first.metadata["strategy"] = "output"
    first.metadata["fine_fingerprint"] = "fine-a"
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.oracle_name = "oracle-b"
    second.metadata["strategy"] = "structural"
    second.metadata["fine_fingerprint"] = "fine-b"
    _run(processor, second)

    assert len(publisher.emitted) == 1
    assert len(drops) == 1
    assert drops[0]["recommended_branch"] == "shadow_queue_review"
    assert drops[0]["metadata"]["selection_policy"]["contract_ok"] is True
    assert drops[0]["metadata"]["selection_policy"]["evidence"]["has_shadow_witness"] is True
    assert len(shadows) == 1
    assert shadows[0]["shadow_reason"] == "shadow_queue_review"
    assert shadows[0]["metadata"]["fine_fingerprint"] == "fine-b"


def test_waf_block_status_family_prefers_preserve_over_shadow_queue():
    drops: list[dict[str, Any]] = []
    shadows: list[dict[str, Any]] = []
    processor, publisher = _make_processor_with_pattern_shadow_sink(drops.append, shadows.append)

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.oracle_name = "oracle-a"
    first.metadata["strategy"] = "output"
    first.metadata["fine_fingerprint"] = "fine-a"
    first.metadata["waf_witness_family"] = "body_headers+block_status"
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.oracle_name = "oracle-b"
    second.metadata["strategy"] = "structural"
    second.metadata["fine_fingerprint"] = "fine-b"
    second.metadata["waf_witness_family"] = "body_headers+block_status"
    _run(processor, second)

    assert len(publisher.emitted) == 2
    second_meta = publisher.emitted[1]["metadata"]
    assert second_meta["selection_branch"] == "fine_preserve_bucket"
    assert second_meta["selection_preserved_from_duplicate"] is True
    assert drops == []
    assert shadows == []


def test_duplicate_drop_record_carries_session_context():
    drops: list[dict[str, Any]] = []
    processor, publisher = _make_processor_with_drop_sink(drops.append)

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.input.metadata["session_key"] = "sess-b"
    second.input.metadata["prefix_depth"] = 3
    second.result.metadata["replay_context"] = {"phase": "history-replay"}
    _run(processor, second)

    assert len(publisher.emitted) == 1
    assert len(drops) == 1
    assert drops[0]["metadata"]["session_key"] == "sess-b"
    assert drops[0]["metadata"]["prefix_depth"] == 3
    assert drops[0]["metadata"]["replay_context"] == {"phase": "history-replay"}
    assert drops[0]["metadata"]["raw_view"]["state"] == "observed_candidate"
    assert drops[0]["metadata"]["publish_view"]["state"] == "selection_drop"
    assert drops[0]["metadata"]["historical_view"]["state"] == "not_persisted"


def test_shadow_queue_record_carries_session_context():
    drops: list[dict[str, Any]] = []
    shadows: list[dict[str, Any]] = []
    processor, publisher = _make_processor_with_shadow_sink(drops.append, shadows.append)

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.oracle_name = "oracle-a"
    first.metadata["strategy"] = "output"
    first.metadata["fine_fingerprint"] = "fine-a"
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.oracle_name = "oracle-b"
    second.metadata["strategy"] = "structural"
    second.metadata["fine_fingerprint"] = "fine-b"
    second.input.metadata["session_key"] = "sess-shadow"
    second.input.metadata["prefix_depth"] = 2
    second.result.metadata["replay_context"] = {"phase": "shadow-review"}
    _run(processor, second)

    assert len(publisher.emitted) == 1
    assert len(drops) == 1
    assert len(shadows) == 1
    assert shadows[0]["metadata"]["session_key"] == "sess-shadow"
    assert shadows[0]["metadata"]["prefix_depth"] == 2
    assert shadows[0]["metadata"]["replay_context"] == {"phase": "shadow-review"}
    assert shadows[0]["metadata"]["raw_view"]["state"] == "observed_candidate"
    assert shadows[0]["metadata"]["publish_view"]["state"] == "shadow_queue"
    assert shadows[0]["metadata"]["historical_view"]["state"] == "shadow_only"


def test_default_dedup_populates_waf_fine_fingerprint():
    dedup = _DefaultDeduplicator()
    finding = _make_finding(_SAML_A, Severity.MEDIUM)
    finding.oracle_name = "differential"
    finding.metadata.update(
        {
            "diff_pattern_hash": "waf-shared-hash",
            "diff_fields": [
                "response_status",
                "waf_block_status",
                "response_body_length",
            ],
            "response_status": 200,
            "waf_block_status": None,
            "waf_blocked": False,
            "response_body_length": 128,
            "response_headers": "server: waf-a",
            "waf_headers": "x-waf: allow",
            "duration_ms": 18.0,
            "path_raw": "/probe",
        }
    )

    fingerprint = dedup.fingerprint(finding)

    assert fingerprint == "differential|waf-shared-hash"
    assert finding.metadata["fine_fingerprint"]
    assert finding.metadata["waf_witness_family"] == "body_headers+block_status"
    assert finding.metadata["fingerprint_components"]["mode"] == "diff_pattern_hash"
    assert finding.metadata["fingerprint_components"]["fine_variant"] == "waf_differential"


def test_default_dedup_preserves_new_waf_fine_variant_inside_same_coarse_bucket():
    processor, publisher = _make_processor_with_default_dedup()

    first = _make_finding(_SAML_A, Severity.MEDIUM)
    first.oracle_name = "differential"
    first.metadata.update(
        {
            "diff_pattern_hash": "waf-shared-hash",
            "diff_fields": [
                "response_status",
                "waf_block_status",
                "response_body_length",
            ],
            "response_status": 200,
            "waf_block_status": None,
            "waf_blocked": False,
            "response_body_length": 128,
            "response_headers": "server: waf-a",
            "waf_headers": "x-waf: allow",
            "duration_ms": 18.0,
            "path_raw": "/probe",
        }
    )
    _run(processor, first)

    second = _make_finding(_SAML_B, Severity.MEDIUM)
    second.oracle_name = "differential"
    second.metadata.update(
        {
            "diff_pattern_hash": "waf-shared-hash",
            "diff_fields": [
                "response_status",
                "waf_block_status",
                "response_body_length",
            ],
            "response_status": 403,
            "waf_block_status": 403,
            "waf_blocked": True,
            "response_body_length": 64,
            "response_headers": "server: waf-b",
            "waf_headers": "x-waf: block",
            "duration_ms": 86.0,
            "path_raw": "/probe",
        }
    )
    _run(processor, second)

    assert len(publisher.emitted) == 2
    second_meta = publisher.emitted[1]["metadata"]
    assert second_meta["selection_branch"] == "fine_preserve_bucket"
    assert second_meta["selection_preserved_from_duplicate"] is True
    assert second_meta["coarse_fingerprint"] == "differential|waf-shared-hash"


def test_default_dedup_uses_fallback_error_skeleton_for_timeout_crash_duplicates():
    drops: list[dict[str, Any]] = []
    publisher = _FakePublisher()
    processor = FindingProcessor(
        oracles=[],
        deduplicator=_DefaultDeduplicator(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
        selection_drop_sink=drops.append,
    )

    first = _make_finding(b"GET /slow?id=1", Severity.MEDIUM)
    first.oracle_name = "crash"
    first.result.exit_code = -1
    first.result.stderr = b"Persistent target read timed out after 2.0s"
    first.result.metadata["error_type"] = "TimeoutError"
    first.metadata["timeout"] = True
    first.metadata["error_type"] = "TimeoutError"
    _run(processor, first)

    second = _make_finding(b"GET /slow?id=2", Severity.MEDIUM)
    second.oracle_name = "crash"
    second.result.exit_code = -1
    second.result.stderr = b"Persistent target read timed out after 2.0s"
    second.result.metadata["error_type"] = "TimeoutError"
    second.metadata["timeout"] = True
    second.metadata["error_type"] = "TimeoutError"
    _run(processor, second)

    assert len(publisher.emitted) == 1
    assert len(drops) == 1
    assert drops[0]["drop_reason"] == "duplicate_fallback_signature"
    assert drops[0]["metadata"]["fingerprint_components"]["mode"] == "fallback_error_skeleton"
