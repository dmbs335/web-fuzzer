"""Hybrid coverage — combines behavioral divergence with per-target code coverage.

Wraps an existing DiffCoverageCollector (or AdaptiveDiffCoverage) and augments
its novelty signal with optional per-target structural code coverage bitmaps.

When --target-coverage is disabled, this module is never imported and the
existing coverage pipeline is completely unchanged.

Design:
  - The existing diff bitmap (65536 bytes) is untouched.
  - Target code coverage is tracked in a separate 16384-byte bitmap.
  - An input is "novel" if it triggers new diff features OR new target code paths.
  - edge_count reports the sum of both bitmaps for status display.
"""

from __future__ import annotations

from ..corpus import CoverageMap


# Size of the per-target code coverage bitmap.
TARGET_COV_SIZE = 16384


class HybridCoverageCollector:
    """Wraps a diff coverage collector + optional per-target code coverage.

    When target_coverage_enabled is False, all methods delegate directly
    to the wrapped collector with zero overhead.
    """

    def __init__(self, inner, target_coverage_enabled: bool = False) -> None:
        self.inner = inner
        self.target_cov_enabled = target_coverage_enabled
        # Global target coverage bitmap — tracks all code paths ever seen.
        self._target_bitmap = bytearray(TARGET_COV_SIZE)
        self._target_edge_count = 0

    # ── Delegate attributes to inner collector ────────────────────

    @property
    def reference_targets(self):
        return self.inner.reference_targets

    @property
    def map_size(self):
        return self.inner.map_size

    @property
    def default_level(self):
        return self.inner.default_level

    # ── Core coverage interface ───────────────────────────────────

    def collect(self, result):
        return self.inner.collect(result)

    def collect_diff(self, inp, primary_result, ref_results=None, **kwargs):
        """Collect diff coverage, then merge target coverage if available."""
        cov = self.inner.collect_diff(
            inp, primary_result, ref_results=ref_results, **kwargs,
        )

        if not self.target_cov_enabled:
            return cov

        # Merge target coverage bitmaps from execution results.
        # Each result's metadata may contain "target_coverage" → bytes.
        has_new = False
        all_results = [primary_result] + (ref_results or [])
        for r in all_results:
            tcov = r.metadata.get("target_coverage")
            if tcov:
                has_new |= self._merge_target_bitmap(tcov)

        if has_new:
            # Do NOT add _target_edge_count to cov.edge_count here — the
            # edge_count property already sums inner + target counts.
            # Adding here double-counts and inflates growth metrics.
            cov = CoverageMap(
                bitmap=cov.bitmap,
                edge_count=cov.edge_count,
                danger_lvl=cov.danger_lvl,
            )
            # Set a flag so is_novel can detect target-only novelty.
            cov._has_new_target_cov = True
        else:
            cov._has_new_target_cov = False

        return cov

    def merge(self, a, b):
        return self.inner.merge(a, b)

    def is_novel(self, existing, new) -> bool:
        """Novel if inner says novel OR if target coverage has new bits."""
        inner_novel = self.inner.is_novel(existing, new)
        if inner_novel:
            return True
        if self.target_cov_enabled and getattr(new, '_has_new_target_cov', False):
            return True
        return False

    def diff(self, old, new):
        return self.inner.diff(old, new)

    # ── AdaptiveDiffCoverage passthrough ──────────────────────────

    def notify_execution(self):
        if hasattr(self.inner, 'notify_execution'):
            self.inner.notify_execution()

    def notify_new_coverage(self, iteration):
        if hasattr(self.inner, 'notify_new_coverage'):
            self.inner.notify_new_coverage(iteration)

    def check_and_adapt(self, corpus):
        if hasattr(self.inner, 'check_and_adapt'):
            return self.inner.check_and_adapt(corpus)
        return False

    # ── Internal ──────────────────────────────────────────────────

    def _merge_target_bitmap(self, bitmap_data: bytes) -> bool:
        """OR a target coverage bitmap into the global target bitmap.

        Returns True if any new bits were set.
        """
        has_new = False
        n = min(len(bitmap_data), TARGET_COV_SIZE)
        for i in range(n):
            b = bitmap_data[i]
            if b and not self._target_bitmap[i]:
                self._target_bitmap[i] = 1
                self._target_edge_count += 1
                has_new = True
        return has_new

    @property
    def edge_count(self):
        """Total edges: diff + target coverage."""
        inner_count = getattr(self.inner, 'edge_count', 0)
        return inner_count + self._target_edge_count
