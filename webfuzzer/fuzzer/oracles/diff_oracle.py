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

from ..domain import (
    get_merged_field_category_map,
    get_merged_field_priority,
    get_profile,
    DomainProfile,
)
from ..diff_fields import get_diff_fields
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
    ) -> Finding | list[Finding] | None:
        """Compare primary result against a single reference result.

        May return a single Finding, a list of Findings, or None.
        Returning a list allows strategies to report multiple
        independent divergences from a single comparison (e.g.,
        host confusion AND query confusion in the same URL).
        """
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
            severity = Severity.HIGH
            accepting_stdout = primary.stdout if primary_ok else reference.stdout
            rejecting_stdout = reference.stdout if primary_ok else primary.stdout
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

            # Downgrade to LOW when the rejecting side failed due to
            # malformed input (e.g. havoc-corrupted JSON) rather than a
            # real semantic disagreement.  Heuristic: rejecting side has
            # no meaningful stdout (empty or very short error text).
            if len(rejecting_stdout.strip()) < 10 and category == "accept_reject":
                severity = Severity.LOW

            # Downgrade to LOW when the "accepting" side (exit_code=0)
            # actually reports semantic rejection (e.g. signature_valid=false).
            # Many wrappers return exit_code=0 with a JSON body that says
            # the input was rejected — this is NOT a real accept/reject
            # divergence.  Without this check, timeout/crash on one side
            # vs "valid=false" on the other generates false HIGH findings.
            if severity != Severity.LOW:
                try:
                    import json as _json2
                    acc_obj = _json2.loads(accepting_stdout.strip())
                    if isinstance(acc_obj, dict):
                        _REJECT_FIELDS = (
                            "signature_valid", "valid", "verified",
                            "redirect_match", "sig_valid",
                        )
                        for rf in _REJECT_FIELDS:
                            v = acc_obj.get(rf)
                            if v is False or v == "false":
                                severity = Severity.LOW
                                break
                except Exception:
                    pass

            accepting_side = "primary" if primary_ok else "ref"
            return Finding(
                title=f"Differential: accept/reject mismatch (ref[{ref_index}])",
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": category,
                    "accepting_side": accepting_side,
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

    Emits one Finding per divergent category (not just the highest-
    priority field).  Uses domain-specific field_category_map when a
    domain name is provided, falling back to merged global maps.
    """

    name = "output"

    def __init__(
        self, normalize: bool = True, domain: str | None = None,
    ) -> None:
        self.normalize = normalize
        # Use domain-specific maps if available, else merged global
        profile = get_profile(domain) if domain else None
        if profile and profile.field_category_map:
            self._field_category_map = dict(profile.field_category_map)
            self._field_priority = list(profile.field_priority)
        else:
            self._field_category_map = get_merged_field_category_map()
            self._field_priority = get_merged_field_priority()

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> list[Finding] | None:
        # Only compare when both succeed
        if primary.exit_code != 0 or reference.exit_code != 0:
            return None

        p_out = self._norm(primary.stdout) if self.normalize else primary.stdout
        r_out = self._norm(reference.stdout) if self.normalize else reference.stdout

        if p_out == r_out:
            return None

        # Skip cross-type comparisons: if both outputs are JSON with
        # different input_type values (e.g. "pkce" vs "redirect_uri"),
        # the divergence is trivially expected and not meaningful.
        if self._input_type_mismatch(primary.stdout, reference.stdout):
            return None

        # Try JSON field-level diff for richer metadata
        diff_fields = self._json_diff_fields(primary.stdout, reference.stdout)

        if not diff_fields:
            # No JSON field-level diff — outputs differ only in
            # serialization (key order, formatting).  Low signal.
            return [Finding(
                title=f"Differential: output mismatch (ref[{ref_index}])",
                severity=Severity.LOW,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "ref_index": ref_index,
                    "ref_result": _result_summary(reference),
                },
            )]

        # Emit one finding per divergent category (not just first match)
        seen_categories: set[str] = set()
        all_findings: list[Finding] = []
        for field_name in self._field_priority:
            if field_name not in diff_fields:
                continue
            if field_name not in self._field_category_map:
                continue
            category, severity = self._field_category_map[field_name]
            if category in seen_categories:
                continue
            seen_categories.add(category)

            # Collect which fields map to this category
            cat_fields = [
                f for f in diff_fields
                if f in self._field_category_map
                and self._field_category_map[f][0] == category
            ]
            all_findings.append(Finding(
                title=(
                    f"Differential: output mismatch "
                    f"[{','.join(sorted(cat_fields))}] (ref[{ref_index}])"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": category,
                    "diff_fields": sorted(cat_fields),
                    "all_diff_fields": sorted(diff_fields),
                    "ref_index": ref_index,
                    "ref_result": _result_summary(reference),
                },
            ))

        # Any remaining diff_fields not in category map → uncategorized finding
        categorized_fields = set()
        for f in diff_fields:
            if f in self._field_category_map:
                categorized_fields.add(f)
        uncategorized = set(diff_fields) - categorized_fields
        if uncategorized and not all_findings:
            all_findings.append(Finding(
                title=(
                    f"Differential: output mismatch "
                    f"[{','.join(sorted(uncategorized))}] (ref[{ref_index}])"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "diff_fields": sorted(uncategorized),
                    "all_diff_fields": sorted(diff_fields),
                    "ref_index": ref_index,
                    "ref_result": _result_summary(reference),
                },
            ))

        return all_findings or None

    @staticmethod
    def _norm(data: bytes) -> bytes:
        return b" ".join(data.lower().split())

    @staticmethod
    def _input_type_mismatch(a: bytes, b: bytes) -> bool:
        """Return True if both are JSON with different input_type values."""
        try:
            import json
            a_obj = json.loads(a.strip())
            b_obj = json.loads(b.strip())
            if not isinstance(a_obj, dict) or not isinstance(b_obj, dict):
                return False
            a_type = a_obj.get("input_type")
            b_type = b_obj.get("input_type")
            # Only skip when both explicitly declare different types
            return (
                a_type is not None
                and b_type is not None
                and a_type != b_type
            )
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return False

    @staticmethod
    def _json_diff_fields(a: bytes, b: bytes) -> list[str]:
        """Return list of JSON keys whose values differ between a and b.

        Returns empty list if either side is not valid JSON.
        Skips fields where either side is None/null — these indicate the
        target does not handle this input type (e.g. redirect fields are
        null for a PKCE input), so divergence is trivially expected.
        """
        try:
            import json
            a_obj = json.loads(a.strip())
            b_obj = json.loads(b.strip())
            if not isinstance(a_obj, dict) or not isinstance(b_obj, dict):
                return []
            all_keys = set(a_obj.keys()) | set(b_obj.keys())
            diff = []
            for k in all_keys:
                a_val = a_obj.get(k)
                b_val = b_obj.get(k)
                # Skip fields where either side is null (not applicable)
                if a_val is None or b_val is None:
                    continue
                if str(a_val).strip().lower() != str(b_val).strip().lower():
                    diff.append(k)
            return diff
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
                severity=Severity.LOW,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "timing",
                    "mechanism": "slow_primary",
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

    _ERROR_LABELS = [
        b"segmentation fault",
        b"stack overflow",
        b"buffer overflow",
        b"out of memory",
        b"assertion.+failed",
        b"undefined behavior",
        b"heap-use-after-free",
        b"AddressSanitizer",
    ]
    # Single combined regex for O(1) scan instead of 8 separate searches
    _ERROR_COMBINED = re.compile(
        rb"(?:" + b"|".join(_ERROR_LABELS) + rb")", re.I,
    )
    _ERROR_PATTERNS = [re.compile(p, re.I) for p in _ERROR_LABELS]

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
        # Fast path: single combined regex pre-check avoids 8 scans per call
        if not self._ERROR_COMBINED.search(combined):
            return set()
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

    def check(self, inp: Input, result: ExecutionResult) -> list[Finding] | None:
        """Compare primary result against all reference targets.

        Returns ALL findings sorted by severity (highest first).
        """
        findings = self.check_all(inp, result)
        return findings or None

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

        After collection, computes a *diff_pattern_hash* for each
        (strategy, category) group.  The hash encodes which refs diverged
        and on which fields — a data-driven proxy for the root cause.
        This replaces metadata-label fingerprinting in the deduplicator.
        """
        # (strategy_name, ref_index, category) → best Finding
        # Keying on category allows a single strategy to contribute
        # multiple independent findings (e.g., host confusion AND
        # query confusion from the same URL comparison).
        best: dict[tuple[str, int, str], Finding] = {}
        for i, ref_result in enumerate(ref_results):
            for strategy in self.strategies:
                result_or_list = strategy.compare(inp, result, ref_result, i)
                if result_or_list is None:
                    continue
                items = result_or_list if isinstance(result_or_list, list) else [result_or_list]
                for finding in items:
                    cat = finding.metadata.get("category", "")
                    key = (strategy.name, i, cat)
                    prev = best.get(key)
                    if prev is None or self._sev_rank(finding) > self._sev_rank(prev):
                        best[key] = finding

        # ── Compute diff_pattern_hash per (strategy, category) ──
        # Group findings by (strategy, category), then build a pattern
        # from the set of (ref_index, frozenset(diff_fields)) tuples.
        from collections import defaultdict
        import hashlib

        groups: dict[tuple[str, str], list[tuple[int, Finding]]] = defaultdict(list)
        for (strat_name, ref_idx, cat), finding in best.items():
            groups[(strat_name, cat)].append((ref_idx, finding))

        for (strat_name, cat), members in groups.items():
            # Build pattern: which refs diverged, on which fields
            pattern_parts: list[str] = []
            for ref_idx, finding in sorted(members, key=lambda x: x[0]):
                meta = finding.metadata or {}
                diff_fields = sorted(get_diff_fields(meta))
                # Include accepting_side to distinguish "primary accepts" vs
                # "ref accepts" — these are fundamentally different bugs
                aside = meta.get("accepting_side", "")
                pattern_parts.append(
                    f"r{ref_idx}:{','.join(diff_fields)}:{aside}"
                )
            pattern_str = "|".join(pattern_parts)
            # Short stable hash — 12 hex chars = 48 bits, collision-free
            # for the ~1000s of patterns we expect
            pattern_hash = hashlib.sha256(
                pattern_str.encode()
            ).hexdigest()[:12]

            # Attach to all findings in this group
            affected_refs = sorted(r for r, _ in members)
            for _, finding in members:
                finding.metadata["diff_pattern_hash"] = pattern_hash
                finding.metadata["affected_refs"] = affected_refs

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
