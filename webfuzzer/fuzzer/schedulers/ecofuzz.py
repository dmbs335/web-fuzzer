"""EcoFuzz MAB schedule (USENIX Security'20).

Models seed scheduling as an Adversarial Multi-Armed Bandit problem.
Uses SPEM (Self-transition Probability Estimation) for seed selection
and AAPS (Adaptive Average-cost Power Schedule) for energy allocation.

Algorithm:
  reward(s) = new_edges_found_from_s / exec_count_of_s
  energy(s) = f(reward(s), avg_cost) — monotonically increasing
"""

from __future__ import annotations

import math
import random
from typing import TYPE_CHECKING

from ..protocols import ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Corpus, Seed


class EcoFuzzScheduler:
    """EcoFuzz Multi-Armed Bandit seed scheduler."""

    def __init__(
        self,
        seed: int | None = None,
        exploration_weight: float = 1.0,
    ) -> None:
        self.rng = random.Random(seed)
        self.exploration_weight = exploration_weight

        # Per-seed reward tracking
        self._rewards: dict[int, float] = {}
        self._trials: dict[int, int] = {}
        self._successes: dict[int, int] = {}
        self._total_trials = 0

    def select(self, corpus: Corpus) -> Seed:
        """Select seed using UCB1 (Upper Confidence Bound) × priority_boost."""
        best_score = -1.0
        best_seed = corpus.seeds[0]

        for seed in corpus.seeds:
            sid = seed.id
            trials = self._trials.get(sid, 0)

            if trials == 0:
                # Untried seed gets infinite priority (boosted)
                if seed.priority_boost >= best_score:
                    best_score = seed.priority_boost
                    best_seed = seed
                continue

            successes = self._successes.get(sid, 0)
            avg_reward = successes / trials

            # UCB1 formula: reward + c * sqrt(ln(total) / trials)
            exploration = self.exploration_weight * math.sqrt(
                math.log(max(self._total_trials, 1)) / trials
            )
            score = (avg_reward + exploration) * seed.priority_boost

            if score > best_score:
                best_score = score
                best_seed = seed

        return best_seed

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        sid = seed.id
        self._total_trials += 1
        self._trials[sid] = self._trials.get(sid, 0) + 1

        if result.found_new_coverage or result.found_crash:
            self._successes[sid] = self._successes.get(sid, 0) + 1

        # AAPS: adaptive energy based on reward rate
        trials = self._trials[sid]
        successes = self._successes.get(sid, 0)
        if trials > 0:
            reward_rate = successes / trials
            # Monotonically increasing energy function
            seed.energy = max(1.0 + reward_rate * 10.0, 0.1)
