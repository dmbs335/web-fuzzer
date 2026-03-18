"""Extract coverage features from per-library execution bitmaps.

Reads ``metadata["target_coverage"]`` from ``ExecutionResult`` objects
produced by the persistent wrappers (Python sys.settrace / Node V8 Profiler).
Computes per-iteration delta and summary features for CorrelationTracker.
"""

from __future__ import annotations

from typing import Any

TARGET_COV_SIZE = 16384  # 16KB bitmap (must match persistent wrappers)
NUM_COV_FEATURES = 10


class CoverageFeatureExtractor:
    """Extract coverage features from ExecutionResult metadata.

    Maintains per-library cumulative bitmaps to compute deltas.
    """

    def __init__(self) -> None:
        # lib_idx → cumulative bitmap
        self._cumulative: dict[int, bytearray] = {}

    def extract_delta(
        self,
        lib_idx: int,
        result: Any,
    ) -> tuple[int, int, frozenset[int]]:
        """Extract (total_branches_hit, new_branches, new_branch_indices).

        ``result`` is an ExecutionResult with optional
        ``metadata["target_coverage"]``.

        Returns (0, 0, frozenset()) if no coverage data.
        """
        raw = None
        if hasattr(result, "metadata"):
            raw = result.metadata.get("target_coverage")
        if not raw:
            return (0, 0, frozenset())

        if lib_idx not in self._cumulative:
            self._cumulative[lib_idx] = bytearray(TARGET_COV_SIZE)

        cum = self._cumulative[lib_idx]
        new_indices: set[int] = set()
        total = 0
        scan_len = min(len(raw), TARGET_COV_SIZE)

        for i in range(scan_len):
            if raw[i]:
                total += 1
                if not cum[i]:
                    cum[i] = 1
                    new_indices.add(i)

        return (total, len(new_indices), frozenset(new_indices))

    def coverage_features(
        self,
        primary_result: Any,
        ref_results: list[Any],
    ) -> list[float]:
        """Extract ~10 coverage-based features for CorrelationTracker.

        Returns a fixed-length list of NUM_COV_FEATURES floats:
          [0] primary_branches_hit (normalized)
          [1] primary_new_branches (normalized)
          [2] avg_ref_branches_hit (normalized)
          [3] avg_ref_new_branches (normalized)
          [4] branch_divergence_ratio
          [5] max_ref_new_branches (normalized)
          [6] libs_with_new_coverage (normalized)
          [7] primary_coverage_density
          [8] coverage_variance
          [9] any_new_branch (binary)
        """
        v = [0.0] * NUM_COV_FEATURES

        # Primary (lib_idx=0)
        p_total, p_new, _ = self.extract_delta(0, primary_result)
        v[0] = min(p_total / 500.0, 1.0)
        v[1] = min(p_new / 20.0, 1.0)

        # Refs
        ref_totals: list[int] = []
        ref_news: list[int] = []
        libs_with_new = 0
        has_any_new = p_new > 0

        for i, ref in enumerate(ref_results):
            r_total, r_new, _ = self.extract_delta(i + 1, ref)
            ref_totals.append(r_total)
            ref_news.append(r_new)
            if r_new > 0:
                libs_with_new += 1
                has_any_new = True

        n_refs = max(len(ref_results), 1)
        v[2] = min(sum(ref_totals) / n_refs / 500.0, 1.0) if ref_totals else 0.0
        v[3] = min(sum(ref_news) / n_refs / 20.0, 1.0) if ref_news else 0.0

        # Branch divergence: how much primary coverage differs from refs
        if p_total > 0 and ref_totals:
            avg_ref = sum(ref_totals) / n_refs
            v[4] = min(abs(p_total - avg_ref) / max(p_total, avg_ref, 1), 1.0)

        v[5] = min(max(ref_news) / 20.0, 1.0) if ref_news else 0.0
        v[6] = min((libs_with_new + (1 if p_new > 0 else 0)) / (n_refs + 1), 1.0)

        # Primary density: ratio of hit branches to bitmap size
        if lib_idx_0_cum := self._cumulative.get(0):
            total_set = sum(1 for b in lib_idx_0_cum if b)
            v[7] = min(total_set / 1000.0, 1.0)

        # Coverage variance across all libs
        all_totals = [p_total] + ref_totals
        if len(all_totals) > 1:
            mean = sum(all_totals) / len(all_totals)
            variance = sum((x - mean) ** 2 for x in all_totals) / len(all_totals)
            v[8] = min(variance / 10000.0, 1.0)

        v[9] = 1.0 if has_any_new else 0.0

        return v

    def get_stats(self) -> dict[str, Any]:
        """Return stats for reporting."""
        lib_stats = {}
        for lib_idx, cum in self._cumulative.items():
            total = sum(1 for b in cum if b)
            lib_stats[f"lib_{lib_idx}"] = total
        return {
            "libraries_tracked": len(self._cumulative),
            "cumulative_branches": lib_stats,
        }


COV_FEATURE_NAMES: tuple[str, ...] = (
    "cov_primary_branches",
    "cov_primary_new",
    "cov_avg_ref_branches",
    "cov_avg_ref_new",
    "cov_branch_divergence",
    "cov_max_ref_new",
    "cov_libs_with_new",
    "cov_primary_density",
    "cov_variance",
    "cov_any_new_branch",
)

assert len(COV_FEATURE_NAMES) == NUM_COV_FEATURES
