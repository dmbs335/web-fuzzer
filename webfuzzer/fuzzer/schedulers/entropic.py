"""Entropic power schedule (LibFuzzer default, FSE'20).

Uses Shannon entropy to allocate energy to seeds. Seeds that discover
rarer features get exponentially more energy.

Algorithm:
  For each feature f discovered by seed s:
    freq(f) = number of seeds that also hit f
    I(f) = -log2(freq(f) / total_seeds)

  entropy(s) = Σ I(f) for f in s.feature_set where freq(f) < θ
  s.energy = normalized_entropy * base_energy

  θ (abundance_threshold): features hit by ≥ θ seeds are ignored.
"""

from __future__ import annotations

import math
import random
from typing import TYPE_CHECKING

from ..protocols import ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Corpus, Seed

# Native acceleration (optional)
try:
    from webfuzzer.native import AVAILABLE as _NATIVE
    if _NATIVE:
        from webfuzzer.native import entropic_compute as _n_entropic
    else:
        _NATIVE = False
except ImportError:
    _NATIVE = False


class EntropicScheduler:
    """Entropic seed scheduler — information-theoretic energy allocation."""

    def __init__(
        self,
        seed: int | None = None,
        abundance_threshold: int = 256,
        base_energy: float = 1.0,
    ) -> None:
        self.rng = random.Random(seed)
        self.theta = abundance_threshold
        self.base_energy = base_energy

    def select(self, corpus: Corpus) -> Seed:
        """Select seed weighted by entropy-based energy × priority_boost."""
        self._update_energies(corpus)

        weights = [max(s.energy * s.priority_boost, 0.01) for s in corpus.seeds]
        chosen = self.rng.choices(corpus.seeds, weights=weights, k=1)[0]
        return chosen

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        if result.found_new_coverage:
            seed.energy *= 1.5
        else:
            seed.energy *= 0.99

    def _update_energies(self, corpus: Corpus) -> None:
        """Recompute entropy-based energy for all seeds."""
        total_seeds = len(corpus.seeds)
        if total_seeds == 0:
            return

        if _NATIVE:
            feature_sets = [s.feature_set or None for s in corpus.seeds]
            energies = _n_entropic(
                feature_sets, corpus.edge_freq,
                total_seeds, self.theta, self.base_energy,
            )
            for seed, energy in zip(corpus.seeds, energies):
                seed.energy = energy
            return

        edge_freq = corpus.edge_freq

        for seed in corpus.seeds:
            if not seed.feature_set:
                seed.energy = self.base_energy
                continue

            entropy = 0.0
            for f in seed.feature_set:
                freq = edge_freq.get(f, 1)
                if freq >= self.theta:
                    continue  # abundant feature — skip
                p = freq / total_seeds
                if p > 0:
                    entropy += -math.log2(p)

            seed.energy = max(entropy * self.base_energy, 0.01)
