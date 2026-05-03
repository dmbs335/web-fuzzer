from __future__ import annotations

import hashlib

from webfuzzer.fuzzer.dedup.structural_dedup import StructuralDeduplicator
from webfuzzer.fuzzer.engine import _DefaultDeduplicator
from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle
from webfuzzer.fuzzer.oracles.implication_oracle import ImplicationSoftOracle
from webfuzzer.fuzzer.protocols import ExecutionResult, Finding, Input, Severity


class _AliasStrategy:
    name = "alias_strategy"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        fields = ["encoding"] if ref_index == 0 else ["reflection"]
        return Finding(
            title=f"alias-{ref_index}",
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "alias_category",
                "difference_fields": fields,
                "accepting_side": "primary",
                "ref_index": ref_index,
            },
        )


def _finding_with_alias(fields: list[str]) -> Finding:
    return Finding(
        title="alias",
        severity=Severity.MEDIUM,
        input=Input(data=b"x"),
        result=ExecutionResult(),
        oracle_name="differential",
        metadata={
            "difference_fields": fields,
            "diff_pattern_hash": "hash-alias",
        },
    )


def test_diff_oracle_groups_on_difference_fields_alias():
    oracle = DiffOracle(reference_targets=[], strategies=[_AliasStrategy()])
    findings = oracle.check_with_refs(
        Input(data=b"x"),
        ExecutionResult(),
        [ExecutionResult(), ExecutionResult()],
    )
    assert findings is not None
    assert len(findings) == 2

    expected = hashlib.sha256(
        b"r0:encoding:primary|r1:reflection:primary"
    ).hexdigest()[:12]
    assert {f.metadata["diff_pattern_hash"] for f in findings} == {expected}
    assert findings[0].metadata["affected_refs"] == [0, 1]


def test_default_deduplicator_accepts_difference_fields_alias():
    dedup = _DefaultDeduplicator()
    alias = _finding_with_alias(["encoding", "reflection"])
    canonical = Finding(
        title="canonical",
        severity=Severity.MEDIUM,
        input=alias.input,
        result=alias.result,
        oracle_name=alias.oracle_name,
        metadata={
            "diff_fields": ["encoding", "reflection"],
            "diff_pattern_hash": "hash-alias",
        },
    )
    assert dedup.fingerprint(alias) == dedup.fingerprint(canonical)


def test_structural_deduplicator_accepts_difference_fields_alias():
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["encoding", "reflection"])
    alias = _finding_with_alias(["encoding", "reflection"])
    canonical = Finding(
        title="canonical",
        severity=Severity.MEDIUM,
        input=alias.input,
        result=alias.result,
        oracle_name=alias.oracle_name,
        metadata={
            "diff_fields": ["encoding", "reflection"],
            "diff_pattern_hash": "other-hash",
        },
    )
    assert dedup.fingerprint(alias) == dedup.fingerprint(canonical)


def test_implication_oracle_accepts_difference_fields_alias():
    inner_finding = Finding(
        title="alias",
        severity=Severity.MEDIUM,
        input=Input(data=b"x"),
        result=ExecutionResult(),
        oracle_name="differential",
        metadata={"difference_fields": ["encoding"]},
    )

    class _InnerOracle:
        name = "inner"

        def check(self, inp: Input, result: ExecutionResult) -> Finding:
            return inner_finding

    oracle = ImplicationSoftOracle(
        _InnerOracle(),
        [{"premise": ["encoding"], "conclusion": ["reflection"], "confidence": 1.0}],
    )
    oracle.check(Input(data=b"x"), ExecutionResult())
    violations = oracle.drain_violations()
    assert len(violations) == 1
    assert violations[0].metadata["diff_fields"] == ["encoding"]
    assert violations[0].metadata["difference_fields"] == ["encoding"]
