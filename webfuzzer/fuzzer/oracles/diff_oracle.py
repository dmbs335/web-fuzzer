"""Differential testing oracle.

Runs the same input against multiple Target implementations
and detects divergences in behavior.

Architecture:
  - DiffStrategy Protocol: pluggable comparison strategies
  - Built-in strategies: exit code, output content, semantic, timing
  - DiffOracle composes strategies and reference targets

Divergence types:
  - exit code differs (accept/reject mismatch)
  - stdout content differs (after normalization)
  - semantic equivalence check (user-provided comparator)
  - timing anomaly (one target much slower than others)

References:
  - CSmith (PLDI'11): differential testing of C compilers
  - DPIFuzz (S&P'22): differential testing of protocol implementations
  - Nezha (S&P'17): efficient differential testing via delta-diversity
"""

from __future__ import annotations

import hashlib
import re
from typing import Protocol, runtime_checkable

from ..domain import get_merged_field_category_map, get_merged_field_priority
from ..protocols import ExecutionResult, Finding, Input, Severity, Target


# ── DiffStrategy Protocol ────────────────────────────────────────

@runtime_checkable
class DiffStrategy(Protocol):
    """Pluggable comparison strategy for differential testing.

    Implement this to define custom divergence detection logic.
    Return a Finding if divergence is detected, None otherwise.
    """

    name: str

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        """Compare primary result against a single reference result."""
        ...


# ── Built-in strategies ──────────────────────────────────────────

class ExitCodeStrategy:
    """Detect accept/reject mismatches via exit code.

    When one parser accepts and the other rejects, classifies the
    finding based on the accepting side's parsed output (if available).
    """

    name = "exit_code"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        primary_ok = primary.exit_code == 0
        ref_ok = reference.exit_code == 0

        if primary_ok != ref_ok:
            # Try to classify based on accepting side's output
            category = "accept_reject"
            accepting_stdout = primary.stdout if primary_ok else reference.stdout
            try:
                import json as _json
                parsed = _json.loads(accepting_stdout.strip())
                if isinstance(parsed, dict):
                    host = str(parsed.get("host", "")).lower().strip()
                    scheme = str(parsed.get("scheme", "")).lower().strip()
                    if host:
                        category = "accept_reject_host"
                    elif scheme:
                        category = "accept_reject_scheme"
            except Exception:
                pass

            return Finding(
                title=f"Differential: accept/reject mismatch (ref[{ref_index}])",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": category,
                    "primary_exit": primary.exit_code,
                    "ref_exit": reference.exit_code,
                    "ref_index": ref_index,
                    "ref_result": _result_summary(reference),
                },
            )
        return None


class OutputStrategy:
    """Detect output content divergences with field-level JSON diff.

    When both outputs are valid JSON objects, computes which fields
    differ and includes ``diff_fields`` in metadata for richer
    deduplication.  Falls back to normalized byte comparison for
    non-JSON outputs.

    Assigns a ``category`` based on which output fields differ,
    using the merged DomainProfile field_category_map. Works for
    URL, SAML, and any registered domain automatically.
    """

    name = "output"

    def __init__(self, normalize: bool = True) -> None:
        self.normalize = normalize
        # Resolve from domain registry (cached, computed once)
        self._field_category_map = get_merged_field_category_map()
        self._field_priority = get_merged_field_priority()

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        # Only compare when both succeed
        if primary.exit_code != 0 or reference.exit_code != 0:
            return None

        p_out = self._norm(primary.stdout) if self.normalize else primary.stdout
        r_out = self._norm(reference.stdout) if self.normalize else reference.stdout

        if p_out == r_out:
            return None

        # Try JSON field-level diff for richer metadata
        diff_fields = self._json_diff_fields(primary.stdout, reference.stdout)

        # Classify based on diff_fields (highest-priority field wins)
        category = None
        severity = Severity.MEDIUM
        if diff_fields:
            for field_name in self._field_priority:
                if field_name in diff_fields and field_name in self._field_category_map:
                    category, severity = self._field_category_map[field_name]
                    break

        meta: dict = {
            "strategy": self.name,
            "primary_output_prefix": primary.stdout[:200],
            "ref_output_prefix": reference.stdout[:200],
            "ref_index": ref_index,
            "ref_result": _result_summary(reference),
        }
        if diff_fields:
            meta["diff_fields"] = sorted(diff_fields)
        if category:
            meta["category"] = category

        return Finding(
            title=(
                f"Differential: output mismatch "
                f"[{','.join(sorted(diff_fields))}] (ref[{ref_index}])"
                if diff_fields else
                f"Differential: output mismatch (ref[{ref_index}])"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata=meta,
        )

    @staticmethod
    def _norm(data: bytes) -> bytes:
        return b" ".join(data.lower().split())

    @staticmethod
    def _json_diff_fields(a: bytes, b: bytes) -> list[str]:
        """Return list of JSON keys whose values differ between a and b.

        Returns empty list if either side is not valid JSON.
        """
        try:
            import json
            a_obj = json.loads(a.strip())
            b_obj = json.loads(b.strip())
            if not isinstance(a_obj, dict) or not isinstance(b_obj, dict):
                return []
            all_keys = set(a_obj.keys()) | set(b_obj.keys())
            return [
                k for k in all_keys
                if str(a_obj.get(k, "")).strip().lower() != str(b_obj.get(k, "")).strip().lower()
            ]
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return []


class StatusCodeStrategy:
    """Detect HTTP status code divergences (for web targets)."""

    name = "status_code"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p_status = primary.metadata.get("status_code")
        r_status = reference.metadata.get("status_code")

        if p_status is None or r_status is None:
            return None

        # Same class = same behavior (2xx, 3xx, 4xx, 5xx)
        p_class = p_status // 100
        r_class = r_status // 100

        if p_class != r_class:
            severity = Severity.HIGH if (p_class == 5 or r_class == 5) else Severity.MEDIUM
            return Finding(
                title=f"Differential: status {p_status} vs {r_status} (ref[{ref_index}])",
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "primary_status": p_status,
                    "ref_status": r_status,
                    "ref_index": ref_index,
                    "ref_result": _result_summary(reference),
                },
            )
        return None


class TimingStrategy:
    """Detect timing divergences — one target much slower than reference."""

    name = "timing"

    def __init__(self, ratio_threshold: float = 10.0) -> None:
        self.ratio_threshold = ratio_threshold

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        if reference.duration_ms <= 0:
            return None

        ratio = primary.duration_ms / max(reference.duration_ms, 0.1)

        if ratio >= self.ratio_threshold:
            return Finding(
                title=(
                    f"Differential: timing anomaly — primary {primary.duration_ms:.0f}ms "
                    f"vs ref[{ref_index}] {reference.duration_ms:.0f}ms "
                    f"({ratio:.1f}x)"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "primary_ms": primary.duration_ms,
                    "ref_ms": reference.duration_ms,
                    "ratio": ratio,
                    "ref_index": ref_index,
                },
            )
        return None


class ErrorPatternStrategy:
    """Detect when one target produces error patterns the other doesn't."""

    name = "error_pattern"

    _ERROR_PATTERNS = [
        re.compile(rb"segmentation fault", re.I),
        re.compile(rb"stack overflow", re.I),
        re.compile(rb"buffer overflow", re.I),
        re.compile(rb"out of memory", re.I),
        re.compile(rb"assertion.+failed", re.I),
        re.compile(rb"undefined behavior", re.I),
        re.compile(rb"heap-use-after-free", re.I),
        re.compile(rb"AddressSanitizer", re.I),
    ]

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p_errors = self._find_errors(primary)
        r_errors = self._find_errors(reference)

        # Primary has critical errors that reference doesn't
        primary_only = p_errors - r_errors
        if primary_only:
            return Finding(
                title=(
                    f"Differential: primary-only error patterns "
                    f"{primary_only} (ref[{ref_index}])"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "primary_errors": sorted(primary_only),
                    "ref_errors": sorted(r_errors),
                    "ref_index": ref_index,
                },
            )
        return None

    def _find_errors(self, result: ExecutionResult) -> set[str]:
        combined = result.stderr + result.stdout
        found: set[str] = set()
        for pat in self._ERROR_PATTERNS:
            if pat.search(combined):
                found.add(pat.pattern.decode("utf-8", errors="replace"))
        return found


# ── DiffOracle ───────────────────────────────────────────────────

DEFAULT_STRATEGIES: list[DiffStrategy] = [
    ExitCodeStrategy(),
    OutputStrategy(),
    StatusCodeStrategy(),
    TimingStrategy(),
    ErrorPatternStrategy(),
]

# Extended strategies for XSS sanitizer fuzzing — imported lazily
# to avoid circular dependencies when not used.
def get_xss_strategies() -> list[DiffStrategy]:
    """Return default strategies + XSS bypass strategy."""
    from .xss_diff_strategy import XssBypassStrategy
    return DEFAULT_STRATEGIES + [XssBypassStrategy()]


class DiffOracle:
    """Differential testing oracle — compares outputs across targets.

    Supports pluggable comparison strategies via the DiffStrategy Protocol.
    Reference targets are executed internally on each check() call.

    Usage:
        # Minimal — uses all default strategies
        oracle = DiffOracle(reference_targets=[target_b, target_c])

        # Custom strategies only
        oracle = DiffOracle(
            reference_targets=[target_b],
            strategies=[ExitCodeStrategy(), MyCustomStrategy()],
        )
    """

    name = "differential"

    def __init__(
        self,
        reference_targets: list[Target],
        strategies: list[DiffStrategy] | None = None,
        normalize: bool = True,
    ) -> None:
        self.targets = reference_targets
        self.strategies: list[DiffStrategy] = strategies or list(DEFAULT_STRATEGIES)

    # Severity rank for comparison (higher = more severe)
    _SEV_RANK = {
        Severity.INFO: 0, Severity.LOW: 1, Severity.MEDIUM: 2,
        Severity.HIGH: 3, Severity.CRITICAL: 4,
    }

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        """Compare primary result against all reference targets.

        Returns highest-severity finding (Oracle Protocol compliance).
        Use check_all() or check_with_refs() for multi-finding mode.
        """
        findings = self.check_all(inp, result)
        return findings[0] if findings else None

    def check_all(self, inp: Input, result: ExecutionResult) -> list[Finding]:
        """Compare primary result against all reference targets.

        Returns ALL findings from ALL strategies × ALL references,
        sorted by severity (highest first).  Each strategy can
        independently contribute findings, so port/query/fragment
        confusion is no longer shadowed by host confusion.
        """
        ref_results: list[ExecutionResult] = []
        for target in self.targets:
            try:
                ref_results.append(target.execute(inp))
            except Exception as e:
                ref_results.append(ExecutionResult(
                    exit_code=-999,
                    stderr=str(e).encode("utf-8", errors="replace"),
                ))
        return self._collect_all(inp, result, ref_results)

    def check_with_refs(
        self, inp: Input, result: ExecutionResult,
        ref_results: list[ExecutionResult],
    ) -> list[Finding]:
        """Compare using pre-computed reference results (no re-execution).

        Returns ALL findings from ALL strategies × ALL references,
        sorted by severity (highest first).
        """
        return self._collect_all(inp, result, ref_results)

    def _collect_all(
        self, inp: Input, result: ExecutionResult,
        ref_results: list[ExecutionResult],
    ) -> list[Finding]:
        """Collect all findings from all (strategy × ref) combinations.

        Per-strategy-per-ref: for each (strategy, ref_index) pair, keeps the
        highest-severity finding.  Different strategies and different
        reference targets always contribute independently.
        """
        # (strategy_name, ref_index) → best Finding
        best: dict[tuple[str, int], Finding] = {}
        for i, ref_result in enumerate(ref_results):
            for strategy in self.strategies:
                finding = strategy.compare(inp, result, ref_result, i)
                if finding:
                    key = (strategy.name, i)
                    prev = best.get(key)
                    if prev is None or self._sev_rank(finding) > self._sev_rank(prev):
                        best[key] = finding
        # Sort by severity descending
        findings = sorted(
            best.values(),
            key=lambda f: self._sev_rank(f),
            reverse=True,
        )
        return findings

    def _sev_rank(self, f: Finding) -> int:
        return self._SEV_RANK.get(f.severity, 0)


# ── Utilities ────────────────────────────────────────────────────

def _result_summary(result: ExecutionResult) -> dict:
    """Create a serializable summary of an ExecutionResult."""
    return {
        "exit_code": result.exit_code,
        "stdout_len": len(result.stdout),
        "stderr_len": len(result.stderr),
        "duration_ms": result.duration_ms,
        "stdout_prefix": result.stdout[:100].decode("utf-8", errors="replace"),
        "stderr_prefix": result.stderr[:100].decode("utf-8", errors="replace"),
    }
