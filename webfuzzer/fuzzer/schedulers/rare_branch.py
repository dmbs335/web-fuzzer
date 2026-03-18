"""FairFuzz rare branch targeting (ASE'18).

Prioritizes seeds that hit rarely-exercised branches.
A branch is "rare" if fewer seeds in the corpus hit it
than a threshold fraction.

Algorithm:
  branch_freq[edge] = number of seeds hitting edge
  rare_threshold = median(branch_freq) * rare_factor
  seed.rare_branches = {e for e in seed.edges if freq[e] < threshold}
  Selection: seeds with more rare branches get higher priority.
"""

from __future__ import annotations

import random
import statistics
from typing import TYPE_CHECKING

from ..protocols import ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Corpus, Seed


class RareBranchScheduler:
    """FairFuzz-style rare branch targeting scheduler."""

    def __init__(
        self,
        seed: int | None = None,
        rare_factor: float = 0.1,
    ) -> None:
        self.rng = random.Random(seed)
        self.rare_factor = rare_factor

    def select(self, corpus: Corpus) -> Seed:
        """Select seed weighted by rare branch count × priority_boost."""
        self._update_rare_branches(corpus)

        # Weight by number of rare branches (minimum 1) × external priority boost
        weights = [max(len(s.rare_branches), 1) * s.priority_boost for s in corpus.seeds]
        chosen = self.rng.choices(corpus.seeds, weights=weights, k=1)[0]
        return chosen

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        if result.found_new_coverage:
            seed.energy *= 2.0
        elif seed.energy > 0.1:
            seed.energy *= 0.95

    def _update_rare_branches(self, corpus: Corpus) -> None:
        """Recompute which branches are rare and update seeds."""
        edge_freq = corpus.edge_freq
        if not edge_freq:
            return

        # Compute threshold from median frequency
        freqs = list(edge_freq.values())
        if not freqs:
            return

        median_freq = statistics.median(freqs)
        threshold = max(median_freq * self.rare_factor, 1)

        rare_edges = {e for e, f in edge_freq.items() if f < threshold}

        for seed in corpus.seeds:
            seed.rare_branches = (seed.feature_set & rare_edges) if seed.feature_set else set()
