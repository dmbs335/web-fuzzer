"""Entropic power schedule (LibFuzzer default, FSE'20).

Uses Shannon entropy to allocate energy to seeds. Seeds that discover
rarer features get exponentially more energy.

Algorithm:
  For each feature f discovered by seed s:
    freq(f) = number of seeds that also hit f
    I(f) = -log2(freq(f) / total_seeds)

  entropy(s) = Σ I(f) for f in s.feature_set where freq(f) < θ
  s.energy = normalized_entropy * base_energy * productivity_mod

  θ (abundance_threshold): features hit by ≥ θ seeds are ignored.

  productivity_mod tracks per-seed execution history:
    - ×1.5 on coverage-producing execution (reward productive seeds)
    - ×0.99 on non-productive execution (decay stale seeds)
    - Clamped to [MOD_FLOOR, MOD_CEIL] to prevent total starvation
      or unbounded amplification.
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

# Productivity modifier bounds.
# Floor 0.1 ≈ 0.99^230 — a seed that hasn't found coverage in ~230 execs
# still retains 10% of its entropy-based energy, preserving rediscovery chance.
# Ceil 10.0 ≈ 1.5^6 — prevents a lucky streak from dominating the corpus.
_MOD_FLOOR = 0.1
_MOD_CEIL = 10.0


class EntropicScheduler:
    """Entropic seed scheduler — information-theoretic energy allocation.

    Energy = entropy_score × productivity_mod × priority_boost.

    ``_update_energies`` recomputes the entropy component from feature rarity.
    ``update`` adjusts a persistent per-seed productivity modifier that
    survives across entropy recomputations.
    """

    def __init__(
        self,
        seed: int | None = None,
        abundance_threshold: int = 256,
        base_energy: float = 1.0,
    ) -> None:
        self.rng = random.Random(seed)
        self.theta = abundance_threshold
        self.base_energy = base_energy
        # Per-seed productivity modifier: seed_id → float.
        # Persists across _update_energies() calls so that the ×1.5/×0.99
        # feedback from update() is not lost.
        self._prod_mod: dict[int, float] = {}
        # Cache: skip full energy recomputation when corpus hasn't changed.
        self._last_corpus_gen: int = -1

    def select(self, corpus: Corpus) -> Seed:
        """Select seed weighted by entropy-based energy × priority_boost."""
        self._update_energies(corpus)

        weights = [max(s.energy * s.priority_boost, 0.01) for s in corpus.seeds]
        chosen = self.rng.choices(corpus.seeds, weights=weights, k=1)[0]
        return chosen

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        mod = self._prod_mod.get(seed.id, 1.0)
        if result.found_new_coverage:
            mod *= 1.5
        else:
            mod *= 0.99
        self._prod_mod[seed.id] = max(_MOD_FLOOR, min(mod, _MOD_CEIL))

    def cleanup_removed(self, removed_ids: set[int]) -> None:
        """Free tracking state for evicted seeds."""
        for sid in removed_ids:
            self._prod_mod.pop(sid, None)

    def _update_energies(self, corpus: Corpus) -> None:
        """Recompute entropy-based energy for all seeds.

        Final energy = max(entropy × base_energy × prod_mod, 0.01).

        Skips full recomputation when the corpus hasn't changed (no adds/removes)
        since the last call — the productivity modifier is applied incrementally
        in update() and only affects the single seed that was just executed.
        """
        gen = getattr(corpus, 'generation', len(corpus.seeds))
        if gen == self._last_corpus_gen:
            return  # corpus unchanged, energies still valid
        self._last_corpus_gen = gen

        total_seeds = len(corpus.seeds)
        if total_seeds == 0:
            return

        prod = self._prod_mod

        if _NATIVE:
            feature_sets = [s.feature_set or None for s in corpus.seeds]
            energies = _n_entropic(
                feature_sets, corpus.edge_freq,
                total_seeds, self.theta, self.base_energy,
            )
            for seed, energy in zip(corpus.seeds, energies):
                seed.energy = max(energy * prod.get(seed.id, 1.0), 0.01)
            return

        edge_freq = corpus.edge_freq

        for seed in corpus.seeds:
            mod = prod.get(seed.id, 1.0)

            if not seed.feature_set:
                seed.energy = max(self.base_energy * mod, 0.01)
                continue

            entropy = 0.0
            for f in seed.feature_set:
                freq = edge_freq.get(f, 1)
                if freq >= self.theta:
                    continue  # abundant feature — skip
                p = freq / total_seeds
                if p > 0:
                    entropy += -math.log2(p)

            seed.energy = max(entropy * self.base_energy * mod, 0.01)
