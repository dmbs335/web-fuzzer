"""Targeted follow-up mutation service for the fuzzing loop."""

from __future__ import annotations

from .protocols import LearnedWeightMutator, StrategyWeightProvider


class TargetedMutationService:
    """Run optional targeted follow-up inputs outside the main engine loop."""

    def __init__(self, coordinator) -> None:
        self.coordinator = coordinator

    @property
    def enabled(self) -> bool:
        return self.coordinator is not None

    def handle_differential_result(
        self,
        *,
        mutated_input,
        result,
        ref_results,
        found_crash: bool,
        mutator,
        seed,
        stats,
        corpus,
        coverage,
        seed_scheduler,
        rotate_primary,
        execute_on,
        execute_on_refs,
        collect_coverage,
        check_oracles,
    ) -> None:
        """Generate, execute, and learn from targeted follow-up inputs."""
        if self.coordinator is None or not ref_results:
            return

        targeted = self.coordinator.on_differential_result(
            mutated_input,
            result,
            ref_results,
            found_crash,
        )
        for targeted_input in targeted:
            targeted_input.metadata["mutator"] = "concolic"
            primary, refs = rotate_primary()
            targeted_result = execute_on(primary, targeted_input)
            targeted_ref_results = execute_on_refs(refs, targeted_input)
            targeted_coverage = collect_coverage(
                targeted_input,
                targeted_result,
                ref_results=targeted_ref_results,
            )
            if coverage and targeted_coverage:
                is_novel = coverage.is_novel(
                    corpus.global_coverage,
                    targeted_coverage,
                )
                if is_novel:
                    targeted_seed = corpus.add(
                        targeted_input,
                        targeted_coverage,
                        parent_id=seed.id,
                        depth=seed.depth + 1,
                    )
                    if targeted_seed:
                        targeted_seed.coverage = None
                        stats.record_new_coverage(
                            corpus.global_coverage.edge_count,
                            "concolic",
                        )
            check_oracles(
                targeted_input,
                targeted_result,
                "concolic",
                ref_results=targeted_ref_results,
            )
            stats.record_execution("concolic")
            targeted_result.metadata.pop("target_coverage", None)
            for ref_result in targeted_ref_results or []:
                ref_result.metadata.pop("target_coverage", None)

        self._apply_learned_weights(
            mutator=mutator,
            seed_scheduler=seed_scheduler,
            stats=stats,
        )

    def _apply_learned_weights(self, *, mutator, seed_scheduler, stats) -> None:
        if not isinstance(self.coordinator, StrategyWeightProvider):
            return
        learned_weights = self.coordinator.get_strategy_weights()
        if not learned_weights or not isinstance(mutator, LearnedWeightMutator):
            return
        stopping_signal = getattr(seed_scheduler, "_stopping_signal", None)
        alpha = stats.alpha_estimate or getattr(stopping_signal, "pareto_alpha", None)
        mutator.apply_learned_weights(learned_weights, alpha=alpha)
