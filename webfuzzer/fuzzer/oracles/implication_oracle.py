"""FCA implication soft oracle (Phase 2C).

Wraps any inner :class:`~webfuzzer.fuzzer.protocols.Oracle` and emits
additional INFO-severity findings whenever a new observation violates a
historically conf=1.0 Duquenne–Guigues implication from the E4 FCA
pipeline.

An *implication violation* occurs when a finding's ``diff_fields`` contain
every attribute in an implication's premise but NOT every attribute in its
conclusion.  Because every implication in the base was satisfied by 100% of
historical observations, a violation represents a diff-field pattern that
has never been seen before — a strong signal for a novel bug class.

Violations are collected in an internal list and drained via
:meth:`drain_violations`.  They are **not** passed through
:meth:`check` so they never enter the main dedup corpus or influence the
scheduler's energy model.  The CLI writes them to ``violations.jsonl``
alongside the main findings log.

Usage::

    from webfuzzer.fuzzer.oracles.implication_oracle import ImplicationSoftOracle

    import json
    implications = json.loads(Path("implication_base.json").read_text())
    oracle = ImplicationSoftOracle(inner_oracle, implications)

    # In the run loop:
    finding = oracle.check(inp, result)        # primary finding (unchanged)
    extras = oracle.drain_violations()         # list[Finding], may be empty
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from ..protocols import Finding, Input, Severity

if TYPE_CHECKING:
    from ..protocols import ExecutionResult, Oracle


class ImplicationSoftOracle:
    """Decorator oracle that flags FCA implication violations as INFO findings.

    Parameters
    ----------
    inner:
        The wrapped oracle.  Its :meth:`check` return value is passed through
        unchanged.
    implications:
        List of implication dicts as produced by
        ``experiments/diffspace_geometry/e4_fca/duquenne_guigues.py``.
        Each dict must have ``"premise"`` and ``"conclusion"`` keys whose
        values are lists of attribute (diff-field) names.  Only
        ``confidence=1.0`` implications are used; others are silently skipped
        so that the JSON produced by the E4 pipeline can be supplied directly
        without pre-filtering.
    """

    name: str = "implication_violation"

    def __init__(
        self,
        inner: Oracle,
        implications: list[dict[str, Any]],
    ) -> None:
        self._inner = inner
        # Keep only conf=1.0 implications (or those without a confidence key,
        # which the Duquenne–Guigues base guarantees are all sound).
        self._implications: list[tuple[frozenset[str], frozenset[str]]] = [
            (frozenset(imp["premise"]), frozenset(imp["conclusion"]))
            for imp in implications
            if float(imp.get("confidence", 1.0)) >= 1.0
            and imp.get("premise")
            and imp.get("conclusion")
        ]
        self._pending: list[Finding] = []

    # ── Oracle protocol ───────────────────────────────────────────

    def check(self, inp: Input, result: ExecutionResult) -> Finding | list[Finding] | None:
        """Delegate to inner oracle; side-effect: populate violation buffer."""
        primary = self._inner.check(inp, result)
        self._check_violations_any(primary)
        return primary

    def check_with_refs(
        self,
        inp: Input,
        result: ExecutionResult,
        ref_results: list,
    ) -> Finding | list[Finding] | None:
        """Delegate to inner oracle check_with_refs if available."""
        if hasattr(self._inner, "check_with_refs"):
            primary = self._inner.check_with_refs(inp, result, ref_results)
        else:
            primary = self._inner.check(inp, result)
        self._check_violations_any(primary)
        return primary

    def setup(self) -> None:
        if hasattr(self._inner, "setup"):
            self._inner.setup()

    def teardown(self) -> None:
        if hasattr(self._inner, "teardown"):
            self._inner.teardown()

    # ── Violation drain ───────────────────────────────────────────

    def drain_violations(self) -> list[Finding]:
        """Return and clear all pending implication-violation findings."""
        out = self._pending
        self._pending = []
        return out

    # ── Internal ─────────────────────────────────────────────────

    def _check_violations_any(self, primary: Finding | list[Finding] | None) -> None:
        """Dispatch to _check_violations for Finding or list[Finding]."""
        if primary is None:
            return
        if isinstance(primary, list):
            for f in primary:
                self._check_violations(f)
        else:
            self._check_violations(primary)

    def _check_violations(self, finding: Finding) -> None:
        diff_fields = frozenset(finding.metadata.get("diff_fields") or [])
        if not diff_fields:
            return
        for premise, conclusion in self._implications:
            if premise.issubset(diff_fields) and not conclusion.issubset(diff_fields):
                self._pending.append(
                    self._make_violation(finding, premise, conclusion),
                )

    def _make_violation(
        self,
        source: Finding,
        premise: frozenset[str],
        conclusion: frozenset[str],
    ) -> Finding:
        """Construct an INFO-severity violation finding."""
        prem_str = ",".join(sorted(premise))
        conc_str = ",".join(sorted(conclusion))
        fp = hashlib.sha256(
            f"impl_viol:{source.oracle_name}:{prem_str}:{conc_str}".encode()
        ).hexdigest()[:16]
        missing = conclusion - frozenset(source.metadata.get("diff_fields") or [])
        f = Finding(
            title=f"implication_violation: {{{prem_str}}} -> {{{conc_str}}}",
            severity=Severity.INFO,
            oracle_name=self.name,
            input=source.input,
            result=source.result,
            fingerprint=fp,
            metadata={
                "premise": sorted(premise),
                "conclusion": sorted(conclusion),
                "missing_conclusion_fields": sorted(missing),
                "source_oracle": source.oracle_name,
                "source_fingerprint": source.fingerprint,
                "diff_fields": list(source.metadata.get("diff_fields") or []),
            },
        )
        return f
