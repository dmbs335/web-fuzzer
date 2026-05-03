"""Experimental adaptive feature granularity for differential fuzzing.

Monitors corpus growth rate and coverage plateau signals, then
automatically adjusts the abstraction level of the differential
feature set:

- **Refine**  (level + 1) when corpus grows fast (interesting region found).
- **Coarsen** (level − 1) when coverage stagnates (escape local optimum).

This is inspired by CEGAR-style refinement/coarsening, but it is not a formal
CEGAR loop with counterexample validation.

Rationale for security fuzzing:
  Rapid corpus growth signals an interesting region being explored —
  refining increases resolution to distinguish valuable variants.
  Stagnation signals a local optimum — coarsening merges similar
  seeds and opens exploration to new regions.

After each transition, the existing corpus is re-hashed from stored raw
feature data — no re-execution needed.

Refinement levels (coarsest → finest):

  L0  exit_vec + div_bucket{0,1+} only
  L1  + per-pair cdiff hash (current default)
  L2  + per-component bits + element-class divergence (ecat)
  L3  + raw element/attribute set hashes + value hashes
  L4  + status_vec + error_divergence
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..corpus import MAP_SIZE, CoverageMap
from .diff_coverage import DiffCoverageCollector, _NATIVE
from .feature_store import FeatureRecord, FeatureStore

if _NATIVE:
    from .diff_coverage import _n_bitmap_count

if TYPE_CHECKING:
    from ..corpus import Corpus
    from ..protocols import ExecutionResult, Input, Target

logger = logging.getLogger(__name__)


class RefinementLevel(enum.IntEnum):
    L0_MINIMAL = 0
    L1_COARSE = 1
    L2_COMPONENT = 2
    L3_VALUES = 3
    L4_FULL = 4


@dataclass
class AdaptiveConfig:
    initial_level: RefinementLevel = RefinementLevel.L1_COARSE
    check_interval: int = 5000
    upper_corpus_pct: float = 5.0
    lower_growth_rate: float = 0.0001
    stagnation_window: int = 10000
    cooldown_iterations: int = 10000
    min_level: RefinementLevel = RefinementLevel.L0_MINIMAL
    max_level: RefinementLevel = RefinementLevel.L4_FULL

    # Safety: minimum edge count after coarsening.  If a coarsen would
    # drop below this threshold the transition is rolled back.
    min_edge_floor: int = 30

    # Safety: maximum consecutive coarsen transitions before forcing a
    # cooldown (prevents cascading collapse L2→L1→L0 within minutes).
    max_consecutive_coarsen: int = 2


# Namespace prefixes active at each level.
#
# L2 uses "ecat" (element-class divergence) — security-category membership
# bits that prevent corpus explosion from unique element-set combinations.
# The raw elem_div/attr_div hashes (per-element-set SHA256) are deferred
# to L3 where fine-grained resolution is appropriate.
_LEVEL_PREFIXES: dict[int, set[str]] = {
    0: {"exit_vec", "div_exit", "parse", "danger", "escalation"},
    1: {"exit_vec", "div_exit", "parse", "cdiff", "danger", "escalation", "surv", "sig", "phase_status"},
    2: {"exit_vec", "div_exit", "parse", "cdiff", "ecat", "comp", "nst", "depth", "danger", "escalation", "surv", "sig", "r", "near", "new", "dcat", "p", "phase", "uri_confusion", "fn_confusion", "handler_confusion", "phase_status"},
    3: {"exit_vec", "div_exit", "parse", "cdiff", "ecat", "comp", "nst", "depth", "elem_div", "attr_div", "val", "danger", "escalation", "surv", "sig", "r", "near", "new", "dcat", "p", "phase", "uri_confusion", "fn_confusion", "handler_confusion", "phase_status"},
    4: {"exit_vec", "div_exit", "parse", "cdiff", "ecat", "comp", "nst", "depth", "elem_div", "attr_div", "val", "status_vec", "div_err", "danger", "escalation", "surv", "sig", "r", "near", "new", "dcat", "p", "phase", "uri_confusion", "fn_confusion", "handler_confusion", "phase_status"},
}


class AdaptiveDiffCoverage:
    """Wraps :class:`DiffCoverageCollector` with automatic level management."""

    def __init__(
        self,
        reference_targets: list[Target],
        config: AdaptiveConfig | None = None,
        map_size: int = MAP_SIZE,
    ) -> None:
        self.config = config or AdaptiveConfig()
        self.level = self.config.initial_level
        self._collector = DiffCoverageCollector(
            reference_targets=reference_targets,
            map_size=map_size,
        )
        self._feature_store = FeatureStore()
        self._map_size = map_size

        # Monitoring state.
        self._total_execs: int = 0
        self._last_check_iter: int = 0
        self._last_transition_iter: int = 0
        self._last_new_coverage_iter: int = 0
        self._corpus_size_at_last_check: int = 0
        self._execs_at_last_check: int = 0
        self._transition_history: list[tuple[int, RefinementLevel, str]] = []
        self._consecutive_coarsen: int = 0

    # ── CoverageCollector-compatible interface ────────────────────

    def collect(self, result: ExecutionResult) -> CoverageMap:
        return self._collector.collect(result)

    def collect_diff(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult] | None = None,
        seed_id: int | None = None,
    ) -> CoverageMap:
        """Collect diff coverage at the current level.

        Always captures *all* raw features into the :class:`FeatureStore`
        (at L4 granularity) so we can re-hash at any level later.
        """
        raw_record = FeatureRecord(seed_id=seed_id or 0) if seed_id is not None else None
        cov = self._collector.collect_diff(
            inp, primary_result, ref_results=ref_results,
            level=int(self.level), raw_record=raw_record,
        )
        if raw_record is not None and seed_id is not None:
            self._feature_store.store(seed_id, raw_record)
        return cov

    def merge(self, a: CoverageMap, b: CoverageMap) -> CoverageMap:
        return self._collector.merge(a, b)

    def is_novel(self, existing: CoverageMap, new: CoverageMap) -> bool:
        return self._collector.is_novel(existing, new)

    def diff(self, old: CoverageMap, new: CoverageMap) -> set[int]:
        return self._collector.diff(old, new)

    # ── Monitoring hooks (called from engine) ────────────────────

    def notify_execution(self) -> None:
        self._total_execs += 1

    def notify_new_coverage(self, iteration: int) -> None:
        self._last_new_coverage_iter = iteration

    # ── Adaptive logic ───────────────────────────────────────────

    def check_and_adapt(self, corpus: Corpus) -> bool:
        """Check whether abstraction level should change.

        Returns ``True`` if a transition occurred.

        Strategy (experimental adaptive feature granularity):
          - Rapid corpus growth => REFINE (increase detail to distinguish
            valuable variants in the interesting region).
          - Stagnation => COARSEN (reduce detail to merge similar seeds
            and escape local optima).
        """
        if (self._total_execs - self._last_check_iter) < self.config.check_interval:
            return False
        if (self._total_execs - self._last_transition_iter) < self.config.cooldown_iterations:
            self._last_check_iter = self._total_execs
            return False

        # Signal 1: corpus growing fast → refine (more detail).
        if self._is_rapid_growth(corpus):
            if self.level < self.config.max_level:
                new_level = RefinementLevel(self.level + 1)
                corpus_pct = (len(corpus) / max(self._total_execs, 1)) * 100
                self._transition(
                    corpus, new_level,
                    f"rapid_growth: corpus_pct={corpus_pct:.2f}% > {self.config.upper_corpus_pct}% => refine",
                )
                self._consecutive_coarsen = 0  # Reset on refine
                return True

        # Signal 2: coverage stagnating → coarsen (escape local optimum).
        if self._is_stagnating(corpus):
            if self.level > self.config.min_level:
                # Safety: block cascading coarsen
                if self._consecutive_coarsen >= self.config.max_consecutive_coarsen:
                    logger.info(
                        "CEGAR: coarsen blocked — %d consecutive coarsens reached limit %d",
                        self._consecutive_coarsen, self.config.max_consecutive_coarsen,
                    )
                    self._last_check_iter = self._total_execs
                    self._last_new_coverage_iter = self._total_execs
                    return False

                new_level = RefinementLevel(self.level - 1)
                stag = self._total_execs - self._last_new_coverage_iter
                did_transition = self._transition(
                    corpus, new_level,
                    f"stagnation={stag} iters => coarsen",
                )
                if did_transition:
                    self._consecutive_coarsen += 1
                return did_transition

        self._last_check_iter = self._total_execs
        self._corpus_size_at_last_check = len(corpus)
        self._execs_at_last_check = self._total_execs
        return False

    # ── Private helpers ──────────────────────────────────────────

    def _is_rapid_growth(self, corpus: Corpus) -> bool:
        """Detect when corpus is growing rapidly (interesting region)."""
        if self._total_execs < 1000:
            return False
        corpus_pct = (len(corpus) / self._total_execs) * 100
        return corpus_pct > self.config.upper_corpus_pct

    def _is_stagnating(self, corpus: Corpus) -> bool:
        """Detect when coverage has stagnated (stuck in local optimum)."""
        iters_since = self._total_execs - self._last_new_coverage_iter
        if iters_since < self.config.stagnation_window:
            return False
        if self._execs_at_last_check == 0:
            return False
        window_execs = self._total_execs - self._execs_at_last_check
        window_new = len(corpus) - self._corpus_size_at_last_check
        if window_execs == 0:
            return False
        return (window_new / window_execs) < self.config.lower_growth_rate

    def _transition(
        self, corpus: Corpus, new_level: RefinementLevel, reason: str,
    ) -> bool:
        """Attempt a level transition. Returns False if rolled back."""
        old_level = self.level

        # Snapshot corpus state for rollback
        is_coarsen = new_level < old_level
        snapshot_seeds = None
        snapshot_coverage = None
        snapshot_edge_freq = None
        if is_coarsen:
            snapshot_seeds = list(corpus.seeds)
            snapshot_coverage = corpus.global_coverage.clone()
            snapshot_edge_freq = dict(corpus.edge_freq)

        self.level = new_level
        self._last_transition_iter = self._total_execs
        self._last_check_iter = self._total_execs

        old_size = len(corpus)
        logger.info(
            "CEGAR transition: L%d -> L%d at iter %d (%s). Rebuilding...",
            old_level, new_level, self._total_execs, reason,
        )

        self._rebuild_coverage(corpus)

        new_edges = corpus.global_coverage.edge_count

        # Safety: rollback if coarsening dropped edges below floor
        if is_coarsen and new_edges < self.config.min_edge_floor:
            logger.warning(
                "CEGAR rollback: L%d -> L%d would give %d edges (floor=%d). "
                "Reverting to L%d.",
                old_level, new_level, new_edges,
                self.config.min_edge_floor, old_level,
            )
            self.level = old_level
            corpus.seeds = snapshot_seeds
            corpus._id_index = {s.id: s for s in snapshot_seeds}
            corpus.global_coverage = snapshot_coverage
            corpus.edge_freq = snapshot_edge_freq
            # Extend cooldown to prevent immediate retry
            self._last_new_coverage_iter = self._total_execs
            return False

        self._transition_history.append((self._total_execs, new_level, reason))
        logger.info(
            "Rebuild complete: %d -> %d seeds, %d edges",
            old_size, len(corpus), new_edges,
        )

        # Reset monitoring for next window.
        self._corpus_size_at_last_check = len(corpus)
        self._execs_at_last_check = self._total_execs
        self._last_new_coverage_iter = self._total_execs
        return True

    def _rebuild_coverage(self, corpus: Corpus) -> None:
        """Re-hash all seeds at the new level using stored raw features."""
        # Reset global coverage.
        corpus.global_coverage = CoverageMap(bitmap=bytearray(self._map_size))
        corpus.edge_freq.clear()

        kept: list = []
        for seed in corpus.seeds:
            record = self._feature_store.get(seed.id)
            if record is None:
                # No raw data (imported seed) — keep unconditionally.
                if seed.coverage is not None:
                    corpus.global_coverage.update(seed.coverage)
                kept.append(seed)
                continue

            new_cov = self._compute_features_at_level(record, self.level)
            if not kept or corpus.global_coverage.has_new_bits(new_cov):
                new_edges = corpus.global_coverage.update(new_cov)
                seed.coverage = new_cov
                # Store ALL edges this seed covers, not just the delta.
                # Using only new_edges corrupts edge_freq and makes
                # compaction/scheduling decisions unreliable.
                seed.feature_set = new_cov.edges()
                kept.append(seed)
                for edge in seed.feature_set:
                    corpus.edge_freq[edge] = corpus.edge_freq.get(edge, 0) + 1

        corpus.seeds = kept
        corpus._id_index = {s.id: s for s in kept}
        corpus._total_bytes = sum(len(s.input.data) for s in kept)

    def _compute_features_at_level(
        self, record: FeatureRecord, level: RefinementLevel,
    ) -> CoverageMap:
        """Reconstruct a CoverageMap by selectively hashing stored features."""
        bitmap = bytearray(self._map_size)
        active = _LEVEL_PREFIXES.get(int(level), _LEVEL_PREFIXES[1])

        for namespace, value in record.features:
            # Extract prefix: "cdiff_0_1" → "cdiff", "exit_vec" → "exit_vec"
            prefix = namespace.split("_")[0] if "_" in namespace else namespace
            # Special case: multi-word prefixes
            if namespace.startswith("div_exit"):
                prefix = "div_exit"
            elif namespace.startswith("div_err"):
                prefix = "div_err"
            elif namespace.startswith("status_vec"):
                prefix = "status_vec"
            elif namespace.startswith("elem_div"):
                prefix = "elem_div"
            elif namespace.startswith("attr_div"):
                prefix = "attr_div"
            elif namespace.startswith("ecat"):
                prefix = "ecat"
            elif namespace.startswith("nst"):
                prefix = "nst"
            elif namespace.startswith("depth"):
                prefix = "depth"
            elif namespace.startswith("danger"):
                prefix = "danger"
            elif namespace.startswith("escalation"):
                prefix = "escalation"
            elif namespace.startswith("surv"):
                prefix = "surv"
            elif namespace.startswith("sig"):
                prefix = "sig"
            elif namespace.startswith("r_sig"):
                prefix = "r"
            elif namespace.startswith("near_miss"):
                prefix = "near"
            elif namespace.startswith("new_elems"):
                prefix = "new"
            elif namespace.startswith("dcat"):
                prefix = "dcat"
            elif namespace.startswith("p_"):
                prefix = "p"

            if prefix in active:
                self._collector._set_feature(bitmap, namespace, value)

        # Recompute div_bucket at correct granularity.
        dc = record.div_count
        if int(level) <= 1:
            bucket = "0" if dc == 0 else "1+"
        elif int(level) <= 3:
            bucket = "0" if dc == 0 else "1" if dc == 1 else "2-3" if dc <= 3 else "4+"
        else:
            bucket = str(min(dc, 5)) if dc <= 5 else "5+"
        self._collector._set_feature(bitmap, "div_bucket", bucket)

        edge_count = _n_bitmap_count(bitmap) if _NATIVE else sum(1 for b in bitmap if b)
        return CoverageMap(bitmap=bitmap, edge_count=edge_count)

    @property
    def transition_history(self) -> list[tuple[int, RefinementLevel, str]]:
        return list(self._transition_history)
