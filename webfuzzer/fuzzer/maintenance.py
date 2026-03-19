"""Iteration feedback and runtime maintenance helpers for the fuzzing engine."""

from __future__ import annotations

import gc
import logging
import sys

from .coverage.adaptive_coverage import AdaptiveDiffCoverage
from .protocols import (
    CleanupAwareSeedScheduler,
    GuidanceWeightedMutator,
    ResettableMutatorWeights,
    ScheduleFeedbackInputSource,
)

logger = logging.getLogger(__name__)


class RuntimeMaintenanceService:
    """Handle post-execution feedback and periodic runtime housekeeping."""

    STALL_WINDOW_ITERS = 50_000
    RECYCLE_EVERY = 10_000

    def __init__(
        self,
        *,
        corpus,
        coverage,
        stats,
        mutators: list,
        input_source,
        seed_scheduler,
        danger_booster,
        guidance_hooks,
        all_targets: list,
        max_corpus_size: int,
    ) -> None:
        self.corpus = corpus
        self.coverage = coverage
        self.stats = stats
        self.mutators = mutators
        self.input_source = input_source
        self.seed_scheduler = seed_scheduler
        self.danger_booster = danger_booster
        self.guidance_hooks = guidance_hooks
        self.all_targets = all_targets
        self.max_corpus_size = max_corpus_size

        self._last_edge_count = 0
        self._edge_growth_window = 0
        self._last_finding_iter = 0
        self._stall_resets = 0
        self._total_target_execs = 0

    def apply_guidance_weights(self, weights: dict[str, float]) -> None:
        """Apply field-level guidance weights to compatible mutators."""
        applied = False
        for mutator in self.mutators:
            if isinstance(mutator, GuidanceWeightedMutator):
                mutator.apply_guidance_weights(weights)
                applied = True
        if applied:
            logger.info(
                "Guidance weights applied: %d fields -- %s",
                len(weights),
                ", ".join(
                    f"{key}={value:.1f}"
                    for key, value in sorted(weights.items(), key=lambda item: -item[1])[:5]
                ),
            )

    def handle_feedback(
        self,
        *,
        seed,
        mutated_input,
        schedule_result,
        is_novel: bool,
        found_crash: bool,
        child_danger: int,
    ) -> None:
        """Apply post-execution feedback that can influence later iterations."""
        self._maybe_reset_stalled_mutators(found_crash)
        self._maybe_refresh_guidance()

        if self.danger_booster and child_danger >= 2:
            self.danger_booster.on_execution(seed, child_danger, self.corpus)

        if (
            isinstance(self.input_source, ScheduleFeedbackInputSource)
            and (is_novel or found_crash)
        ):
            self.input_source.update(mutated_input, schedule_result)

        self._maybe_adapt_coverage(is_novel)

    def handle_periodic_maintenance(self, *, ref_result_count: int) -> None:
        """Run periodic housekeeping that is independent from a single mutator."""
        if self.danger_booster and self.stats.total_iterations % 2000 == 0:
            self.danger_booster.apply_decay(self.corpus)

        self._maybe_compact_corpus()
        self._maybe_recycle_persistent_targets(ref_result_count)

    def _maybe_reset_stalled_mutators(self, found_crash: bool) -> None:
        if found_crash:
            self._last_finding_iter = self.stats.total_iterations

        iters_since_finding = self.stats.total_iterations - self._last_finding_iter
        if iters_since_finding <= 0:
            return
        if iters_since_finding % self.STALL_WINDOW_ITERS != 0:
            return

        self._stall_resets += 1
        logger.warning(
            "STALL: %d iters since last finding (reset #%d) -- shuffling mutator weights",
            iters_since_finding,
            self._stall_resets,
        )
        for mutator in self.mutators:
            if isinstance(mutator, ResettableMutatorWeights):
                mutator.reset_weights(boost_zero_finds=True)

    def _maybe_refresh_guidance(self) -> None:
        if not self.guidance_hooks or not self.guidance_hooks.active:
            return

        self.guidance_hooks.on_iteration()
        if not self.guidance_hooks.should_refresh_weights():
            return

        weights = self.guidance_hooks.get_current_weights()
        if weights:
            self.apply_guidance_weights(weights)

    def _maybe_adapt_coverage(self, is_novel: bool) -> None:
        inner = getattr(self.coverage, "inner", self.coverage)
        if not isinstance(inner, AdaptiveDiffCoverage):
            return

        self.coverage.notify_execution()
        if is_novel:
            self.coverage.notify_new_coverage(self.stats.total_iterations)
        if self.coverage.check_and_adapt(self.corpus):
            self.stats.update_corpus(len(self.corpus), self.corpus.total_bytes)
            self.stats.record_new_coverage(self.corpus.global_coverage.edge_count)

    def _maybe_compact_corpus(self) -> None:
        max_cap = self._effective_corpus_cap()
        should_compact = (
            self.stats.total_iterations % 5000 == 0 or len(self.corpus) > max_cap
        )
        if not should_compact or len(self.corpus) <= 200:
            return

        removed_ids = self.corpus.compact(min_seeds=100, max_seeds=max_cap)
        if not removed_ids:
            return

        inner = getattr(self.coverage, "inner", self.coverage)
        if isinstance(inner, AdaptiveDiffCoverage):
            for seed_id in removed_ids:
                inner._feature_store.remove(seed_id)
        if self.danger_booster:
            self.danger_booster.cleanup_removed(removed_ids)
        if isinstance(self.seed_scheduler, CleanupAwareSeedScheduler):
            self.seed_scheduler.cleanup_removed(removed_ids)

        logger.info(
            "Corpus compacted: %d seeds removed, %d remaining",
            len(removed_ids),
            len(self.corpus),
        )
        self.stats.update_corpus(len(self.corpus), self.corpus.total_bytes)

    def _effective_corpus_cap(self) -> int:
        max_cap = self.max_corpus_size
        if self.stats.total_iterations % 5000 != 0:
            return max_cap
        if not hasattr(self.corpus, "global_coverage"):
            return max_cap

        cur_edges = self.corpus.global_coverage.edge_count
        if cur_edges > self._last_edge_count:
            self._edge_growth_window = min(self._edge_growth_window + 1, 5)
            self._last_edge_count = cur_edges
        else:
            self._edge_growth_window = max(self._edge_growth_window - 1, 0)
        if self._edge_growth_window >= 3:
            max_cap *= 2
        return max_cap

    def _maybe_recycle_persistent_targets(self, ref_result_count: int) -> None:
        self._total_target_execs += 1 + ref_result_count
        if self._total_target_execs < self.RECYCLE_EVERY:
            return
        self._recycle_persistent_targets()
        self._total_target_execs = 0

    def _recycle_persistent_targets(self) -> None:
        """Kill and restart all persistent target child processes."""
        from .targets.persistent_target import PersistentTarget

        recycled = 0
        for target in self.all_targets:
            if isinstance(target, PersistentTarget):
                try:
                    target.reset()
                    recycled += 1
                except Exception as exc:
                    logger.warning(
                        "Failed to recycle target %s: %s",
                        target.command[:60],
                        exc,
                    )
        if recycled:
            gc.collect()
            msg = (
                f"[recycle] {recycled} targets recycled at "
                f"exec={self.stats.total_executions}"
            )
            logger.info(msg)
            print(msg, file=sys.stderr, flush=True)
