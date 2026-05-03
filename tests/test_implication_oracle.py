"""Unit tests for Phase 2C: ImplicationSoftOracle.

Tests that the oracle:
 - delegates check() to the inner oracle unchanged
 - emits violation findings for conf=1.0 premise-but-not-conclusion patterns
 - skips implications where confidence < 1.0
 - drain_violations() returns and clears the buffer
 - no violation when diff_fields fully satisfy conclusion
 - no violation when premise not satisfied
 - violations have INFO severity and correct metadata
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from webfuzzer.fuzzer.protocols import Finding, Input, ExecutionResult, Severity
from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle
from webfuzzer.fuzzer.oracles.implication_oracle import ImplicationSoftOracle


def _make_finding(diff_fields: list[str] | None = None, fp: str = "fp0") -> Finding:
    f = Finding(
        title="test finding",
        severity=Severity.MEDIUM,
        oracle_name="diff",
        input=Input(data=b"x"),
        result=ExecutionResult(),
        fingerprint=fp,
        metadata={"diff_fields": diff_fields} if diff_fields is not None else {},
    )
    return f


def _inner_oracle(finding: Finding | None) -> MagicMock:
    m = MagicMock()
    m.name = "inner"
    m.check.return_value = finding
    return m


IMPLICATIONS = [
    {"premise": ["a"], "conclusion": ["b"], "confidence": 1.0},
    {"premise": ["c", "d"], "conclusion": ["e"], "confidence": 1.0},
    {"premise": ["x"], "conclusion": ["y"], "confidence": 0.8},  # excluded
]


# ── Delegation tests ─────────────────────────────────────────────────────────

def test_check_returns_inner_finding():
    primary = _make_finding(["a", "b"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    result = oracle.check(Input(data=b"x"), ExecutionResult())
    assert result is primary


def test_check_returns_none_when_inner_returns_none():
    oracle = ImplicationSoftOracle(_inner_oracle(None), IMPLICATIONS)
    result = oracle.check(Input(data=b"x"), ExecutionResult())
    assert result is None


def test_no_violations_when_inner_returns_none():
    oracle = ImplicationSoftOracle(_inner_oracle(None), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    assert oracle.drain_violations() == []


# ── Violation detection ──────────────────────────────────────────────────────

def test_violation_when_premise_satisfied_conclusion_missing():
    """diff_fields has "a" (premise) but not "b" (conclusion) → violation."""
    primary = _make_finding(diff_fields=["a", "c"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    violations = oracle.drain_violations()
    assert len(violations) == 1
    v = violations[0]
    assert v.severity == Severity.INFO
    assert v.oracle_name == "implication_violation"
    assert "a" in v.metadata["premise"]
    assert "b" in v.metadata["conclusion"]
    assert "b" in v.metadata["missing_conclusion_fields"]


def test_no_violation_when_conclusion_fully_satisfied():
    """diff_fields has both "a" and "b" → no violation for first implication."""
    primary = _make_finding(diff_fields=["a", "b"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    # First implication: premise={a}, conclusion={b} → satisfied, no violation
    violations = oracle.drain_violations()
    assert all("a" not in v.metadata.get("premise", []) for v in violations)


def test_no_violation_when_premise_not_satisfied():
    """diff_fields does not contain premise → no violation."""
    primary = _make_finding(diff_fields=["z", "w"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    assert oracle.drain_violations() == []


def test_multifield_premise_violation():
    """Premise requires both "c" and "d"; finding has both but not "e"."""
    primary = _make_finding(diff_fields=["c", "d", "a"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    violations = oracle.drain_violations()
    multi_viols = [v for v in violations if set(v.metadata["premise"]) == {"c", "d"}]
    assert len(multi_viols) == 1
    assert "e" in multi_viols[0].metadata["missing_conclusion_fields"]


def test_partial_premise_not_enough():
    """Only "c" present, but not "d" → premise not satisfied → no violation."""
    primary = _make_finding(diff_fields=["c"])  # missing "d"
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    violations = oracle.drain_violations()
    multi_viols = [v for v in violations if "c" in v.metadata.get("premise", [])]
    assert len(multi_viols) == 0


# ── Confidence filtering ─────────────────────────────────────────────────────

def test_low_confidence_implication_excluded():
    """conf=0.8 implication must never fire."""
    # diff_fields has "x" but not "y"
    primary = _make_finding(diff_fields=["x"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    violations = oracle.drain_violations()
    x_viols = [v for v in violations if "x" in v.metadata.get("premise", [])]
    assert len(x_viols) == 0


# ── drain_violations clears the buffer ──────────────────────────────────────

def test_drain_clears_buffer():
    primary = _make_finding(diff_fields=["a"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    first_drain = oracle.drain_violations()
    assert len(first_drain) >= 1
    second_drain = oracle.drain_violations()
    assert second_drain == []


# ── Empty diff_fields ────────────────────────────────────────────────────────

def test_no_diff_fields_no_violations():
    primary = _make_finding(diff_fields=[])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    assert oracle.drain_violations() == []


def test_missing_diff_fields_key_no_violations():
    primary = _make_finding(diff_fields=None)
    oracle = ImplicationSoftOracle(_inner_oracle(primary), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    assert oracle.drain_violations() == []


# ── Fingerprint stability ────────────────────────────────────────────────────

def test_same_violation_produces_same_fingerprint():
    """Two identical violations for the same implication share a fingerprint."""
    primary1 = _make_finding(diff_fields=["a"], fp="fp1")
    primary2 = _make_finding(diff_fields=["a"], fp="fp2")
    oracle = ImplicationSoftOracle(_inner_oracle(primary1), IMPLICATIONS)
    oracle.check(Input(data=b"x"), ExecutionResult())
    v1 = oracle.drain_violations()[0]

    oracle2 = ImplicationSoftOracle(_inner_oracle(primary2), IMPLICATIONS)
    oracle2.check(Input(data=b"x"), ExecutionResult())
    v2 = oracle2.drain_violations()[0]

    assert v1.fingerprint == v2.fingerprint


# ── Empty implication list ───────────────────────────────────────────────────

def test_empty_implications_no_violations():
    primary = _make_finding(diff_fields=["a", "b"])
    oracle = ImplicationSoftOracle(_inner_oracle(primary), [])
    oracle.check(Input(data=b"x"), ExecutionResult())
    assert oracle.drain_violations() == []


# ── Real WAF implication base smoke test ────────────────────────────────────

# ── List-return inner oracle ─────────────────────────────────────────────────

def test_check_handles_list_return():
    """Inner oracle returning list[Finding] must not crash; violations are collected."""
    findings = [
        _make_finding(diff_fields=["a"], fp="fp1"),
        _make_finding(diff_fields=["c", "d"], fp="fp2"),
    ]
    m = MagicMock()
    m.name = "inner"
    m.check.return_value = findings
    oracle = ImplicationSoftOracle(m, IMPLICATIONS)
    result = oracle.check(Input(data=b"x"), ExecutionResult())
    assert result is findings
    violations = oracle.drain_violations()
    # "a" → missing "b", "c"+"d" → missing "e"
    assert len(violations) == 2


def test_wrapped_diff_oracle_list_return_does_not_crash():
    """Regression for the Apr 12, 2026 wrapper bug.

    DiffOracle returns list[Finding] in differential mode. The implication
    wrapper must accept that shape instead of assuming a single Finding.
    """

    class _RefTarget:
        def execute(self, inp: Input) -> ExecutionResult:
            return ExecutionResult(stdout=b"{}")

    class _ListStrategy:
        name = "list_strategy"

        def compare(
            self,
            inp: Input,
            primary: ExecutionResult,
            reference: ExecutionResult,
            ref_index: int,
        ) -> list[Finding]:
            first = _make_finding(diff_fields=["a"], fp=f"fp{ref_index}_0")
            first.metadata["category"] = "cat_a"
            second = _make_finding(diff_fields=["c", "d"], fp=f"fp{ref_index}_1")
            second.metadata["category"] = "cat_cd"
            return [first, second]

    inner = DiffOracle(reference_targets=[_RefTarget()], strategies=[_ListStrategy()])
    oracle = ImplicationSoftOracle(inner, IMPLICATIONS)
    result = oracle.check(Input(data=b"x"), ExecutionResult(stdout=b"{}"))
    assert isinstance(result, list)
    assert len(result) == 2
    violations = oracle.drain_violations()
    assert len(violations) == 2


def test_check_with_refs_delegates_to_inner():
    """check_with_refs delegates and populates violations."""
    primary = _make_finding(diff_fields=["a"])
    inner = MagicMock()
    inner.name = "inner"
    inner.check_with_refs = MagicMock(return_value=primary)
    oracle = ImplicationSoftOracle(inner, IMPLICATIONS)
    result = oracle.check_with_refs(Input(data=b"x"), ExecutionResult(), [ExecutionResult()])
    assert result is primary
    inner.check_with_refs.assert_called_once()
    violations = oracle.drain_violations()
    assert len(violations) == 1


# ── Real WAF implication base smoke test ────────────────────────────────────

def test_real_waf_implication_base_loads():
    """Smoke: loads actual waf_v61 implication_base.json without error."""
    import json
    import os
    from pathlib import Path

    root = Path(os.environ.get("DIFFSPACE_RESEARCH_DIR", "../diffspace-research"))
    p = root / "experiments/diffspace_geometry/outputs/waf_v61_20260407/e4_fca/implication_base.json"
    if not p.exists():
        pytest.skip("waf implication_base.json not present")
    implications = json.loads(p.read_text(encoding="utf-8"))
    inner = _inner_oracle(_make_finding(diff_fields=["waf_headers"]))
    oracle = ImplicationSoftOracle(inner, implications)
    # waf_headers → response_headers (implication exists in the file)
    oracle.check(Input(data=b"x"), ExecutionResult())
    # diff_fields has "waf_headers" but not "response_headers" → violation expected
    violations = oracle.drain_violations()
    assert len(violations) >= 1
