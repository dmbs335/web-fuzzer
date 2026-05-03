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

import bisect
import math
import random
from collections import defaultdict
from itertools import accumulate
from typing import TYPE_CHECKING

from ..protocols import ScheduleResult, StoppingSignal

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

# Maximum fraction of total corpus energy a single technique family may hold.
# Prevents a dominant family (e.g. lt_mixed_crlf at 58%) from starving others.
_FAMILY_CAP = 0.30

# Class-saturation penalty parameters (Phase 4 feedback hook).
# A seed most-recently observed producing pattern h is scaled by
#   (1 - min(p_hat(h), _CLASS_SAT_CEIL))
# where p_hat(h) is the empirical probability of h in the pre-dedup
# observation stream emitted by the differential oracle.
# _CLASS_SAT_CEIL bounds the penalty so a pathological monoculture can't
# zero out the entire corpus.
# _CLASS_SAT_MIN_N prevents the estimator from firing on tiny samples
# where one observation would dominate.
_CLASS_SAT_CEIL = 0.95
_CLASS_SAT_MIN_N = 32


def _family_from_bytes(data: bytes) -> str:
    """Extract X-WF-Family header value from the first 256 bytes of wire data."""
    prefix = data[:256]
    marker = b'x-wf-family:'
    idx = prefix.lower().find(marker)
    if idx == -1:
        return ''
    fragment = prefix[idx + len(marker): idx + len(marker) + 64]
    end = fragment.find(b'\r')
    if end == -1:
        end = fragment.find(b'\n')
    return (fragment[:end] if end >= 0 else fragment).strip().decode('ascii', errors='replace')


# Productivity modifier bounds.
# Floor 0.1 ≈ 0.99^230 — a seed that hasn't found coverage in ~230 execs
# still retains 10% of its entropy-based energy, preserving rediscovery chance.
# Ceil 10.0 ≈ 1.5^6 — prevents a lucky streak from dominating the corpus.
_MOD_FLOOR = 0.1
_MOD_CEIL = 10.0

# Exploitation-phase dampening (DG018 stopping-signal hook).
# When a ``StoppingSignal(phase="exploitation")`` is attached to the
# scheduler, entropy contributions are scaled by this factor and the
# class-saturation penalty is raised to this power. The effect is
# continuous w.r.t. novelty (0.3× reduction, not zero) so rare
# features still get *some* attention in case the lint bound was
# loose, while saturation pressure is amplified (penalty∈(0,1] raised
# to a >1 power shrinks). When no signal is attached or the phase is
# "discovery", neither transform fires and behaviour is byte-identical
# to the pre-signal scheduler.
_EXPLOIT_NOVELTY_FACTOR = 0.3
_EXPLOIT_PENALTY_POWER = 1.5


class EntropicScheduler:
    """Entropic seed scheduler — information-theoretic energy allocation.

    Energy = entropy_score × productivity_mod × priority_boost.

    ``_update_energies`` recomputes the entropy component from feature rarity.
    ``update`` adjusts a persistent per-seed productivity modifier that
    survives across entropy recomputations.

    Selection uses pre-computed cumulative weights + bisect for O(log N)
    per-call rather than O(N) (random.choices recomputes cumulative weights
    internally on every call).
    """

    def __init__(
        self,
        seed: int | None = None,
        abundance_threshold: int = 256,
        base_energy: float = 1.0,
        stopping_signal: StoppingSignal | None = None,
    ) -> None:
        self.rng = random.Random(seed)
        self.theta = abundance_threshold
        self.base_energy = base_energy
        # Optional offline PAC stopping signal (see DG018 in the external
        # fuzzing-formal-research workspace). When present and in
        # exploitation phase, _update_energies dampens the novelty
        # component and amplifies the class-saturation penalty.
        self._stopping_signal: StoppingSignal | None = stopping_signal
        # Per-seed productivity modifier: seed_id → float.
        # Persists across _update_energies() calls so that the ×1.5/×0.99
        # feedback from update() is not lost.
        self._prod_mod: dict[int, float] = {}
        # Class-saturation census (Phase 4 feedback hook).
        # ``_class_counts[h]`` tallies every pre-dedup observation of
        # pattern h that the differential oracle has emitted, and
        # ``_class_total`` counts the grand total of divergent observations.
        # ``_seed_last_class[seed_id]`` records the pattern the seed was
        # most recently credited with so _update_energies can penalise it.
        self._class_counts: dict[str, int] = {}
        self._class_total: int = 0
        self._seed_last_class: dict[int, str] = {}
        # Cache: skip full energy recomputation when corpus hasn't changed.
        self._last_corpus_gen: int = -1
        # Cached weights array — rebuilt only when corpus structure changes.
        self._cached_weights: list[float] = []
        # Pre-computed cumulative weights for O(log N) bisect selection.
        self._cum_weights: list[float] = []
        # Generation tag for the weights/cum_weights cache.
        self._weights_gen: int = -1
        # seed_id → index in corpus.seeds — enables O(1) in-place weight update.
        # Valid only when _weights_gen matches corpus.generation.
        self._seed_idx: dict[int, int] = {}

    def _rebuild_weights(self, corpus: Corpus) -> None:
        """Rebuild _cached_weights, _cum_weights, and _seed_idx from corpus."""
        self._cached_weights = [
            max(s.energy * s.priority_boost, 0.01) for s in corpus.seeds
        ]
        self._cum_weights = list(accumulate(self._cached_weights))
        self._seed_idx = {s.id: i for i, s in enumerate(corpus.seeds)}
        gen = getattr(corpus, 'generation', len(corpus.seeds))
        self._weights_gen = gen

    def select(self, corpus: Corpus) -> Seed:
        """Select seed weighted by entropy-based energy × priority_boost.

        O(log N) per call: cumulative weights are pre-computed; selection uses
        bisect rather than random.choices (which recomputes cumsum each call).
        """
        self._update_energies(corpus)

        # Rebuild only when corpus structure changes (seeds added/removed).
        gen = getattr(corpus, 'generation', len(corpus.seeds))
        if gen != self._weights_gen or len(self._cached_weights) != len(corpus.seeds):
            self._rebuild_weights(corpus)

        total = self._cum_weights[-1]
        rnd = self.rng.random() * total
        idx = bisect.bisect(self._cum_weights, rnd, 0, len(self._cum_weights) - 1)
        return corpus.seeds[idx]

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        old_mod = self._prod_mod.get(seed.id, 1.0)
        if result.found_new_coverage:
            new_mod = min(old_mod * 1.5, _MOD_CEIL)
        else:
            new_mod = max(old_mod * 0.99, _MOD_FLOOR)
        self._prod_mod[seed.id] = new_mod

        # Class-saturation census bookkeeping.
        # Every pre-dedup pattern hash observed this execution increments
        # the census. The *last* hash credited to this seed becomes its
        # representative class label for penalty computation — the engine
        # evaluates oracles after mutation, so the most recent hash is the
        # one causally attributable to mutating this seed.
        hashes = result.diff_pattern_hashes
        if hashes:
            counts = self._class_counts
            for h in hashes:
                counts[h] = counts.get(h, 0) + 1
            self._class_total += len(hashes)
            self._seed_last_class[seed.id] = hashes[-1]

        # Update seed.energy in-place via ratio: energy = entropy × base × mod,
        # so new_energy = old_energy × (new_mod / old_mod). This is O(1) and
        # avoids triggering a full O(N×F) entropy recomputation from update().
        # _MOD_FLOOR = 0.1 ensures old_mod is always >> 1e-9 in practice, so
        # the ratio path is always taken. Keep the guard for safety.
        if old_mod > 1e-9:
            ratio = new_mod / old_mod
            seed.energy = max(seed.energy * ratio, 0.01)
            # Update the cached weight and cumulative weights in-place.
            # This avoids triggering an O(N) full rebuild on every iteration.
            cache_idx = self._seed_idx.get(seed.id)
            if cache_idx is not None and cache_idx < len(self._cached_weights):
                new_w = max(seed.energy * seed.priority_boost, 0.01)
                old_w = self._cached_weights[cache_idx]
                delta = new_w - old_w
                self._cached_weights[cache_idx] = new_w
                # Incrementally update cumulative weights from cache_idx onwards.
                for i in range(cache_idx, len(self._cum_weights)):
                    self._cum_weights[i] += delta
        else:
            self._last_corpus_gen = -1  # force full recomputation next select
            self._weights_gen = -1      # force weights rebuild next select

    def _apply_family_cap(self, corpus: Corpus) -> None:
        """Scale down seeds whose technique family exceeds _FAMILY_CAP of total energy.

        Called at the end of _update_energies so the cap is applied on the same
        cadence as entropy recomputation (every K=5 corpus generations).
        After scaling, forces a weights-cache rebuild on the next select().
        """
        groups: dict[str, list] = defaultdict(list)
        for seed in corpus.seeds:
            meta = seed.input.metadata
            fam = (
                meta.get('variant_family')
                or meta.get('technique_family')
                or _family_from_bytes(seed.input.data)
                or 'unknown'
            )
            groups[fam].append(seed)

        total = sum(s.energy for s in corpus.seeds)
        if total <= 0 or len(groups) <= 1:
            return

        capped = False
        for seeds in groups.values():
            fam_total = sum(s.energy for s in seeds)
            limit = _FAMILY_CAP * total
            if fam_total > limit:
                scale = limit / fam_total
                for s in seeds:
                    s.energy = max(s.energy * scale, 0.01)
                capped = True

        if capped:
            # Energies changed outside the normal update() path — cached
            # cumulative weights are stale, force a full rebuild next select().
            self._weights_gen = -1

    def set_stopping_signal(
        self, signal: StoppingSignal | None,
    ) -> None:
        """Attach (or clear) an offline PAC stopping signal.

        Called by the CLI after the scheduler is constructed when the
        user passes ``--stopping-signal PATH``. Forces a full energy
        recomputation on the next ``select`` so the new phase takes
        effect immediately rather than waiting for the deferral window
        in :meth:`_update_energies`.
        """
        self._stopping_signal = signal
        # Invalidate caches so the next select() recomputes energies
        # under the new phase factors.
        self._last_corpus_gen = -1
        self._weights_gen = -1

    def cleanup_removed(self, removed_ids: set[int]) -> None:
        """Free tracking state for evicted seeds."""
        for sid in removed_ids:
            self._prod_mod.pop(sid, None)
            self._seed_last_class.pop(sid, None)

    def _class_saturation_penalty(self, seed_id: int) -> float:
        """Return a multiplicative penalty in (0, 1] for ``seed_id``.

        The penalty equals ``1 - min(p_hat(h), _CLASS_SAT_CEIL)`` where
        ``h`` is the seed's last-observed pattern hash and ``p_hat`` is
        its empirical frequency in the pre-dedup observation stream.
        Seeds that have not yet been credited with a divergence get the
        neutral 1.0 (no penalty).
        """
        total = self._class_total
        if total < _CLASS_SAT_MIN_N:
            return 1.0
        h = self._seed_last_class.get(seed_id)
        if not h:
            return 1.0
        count = self._class_counts.get(h, 0)
        if count <= 0:
            return 1.0
        p_hat = count / total
        if p_hat >= _CLASS_SAT_CEIL:
            p_hat = _CLASS_SAT_CEIL
        return 1.0 - p_hat

    def _update_energies(self, corpus: Corpus) -> None:
        """Recompute entropy-based energy for all seeds.

        Final energy = max(entropy × base_energy × prod_mod, 0.01).

        Full recomputation is O(N × |feature_set|). To avoid paying this cost
        on every new-seed addition, recomputation is deferred until at least 5
        corpus generation changes have accumulated since the last recomputation.
        Skips entirely when no changes have occurred.
        """
        gen = getattr(corpus, 'generation', len(corpus.seeds))
        diff = gen - self._last_corpus_gen
        if diff == 0:
            return  # corpus unchanged, energies still valid
        # Defer: skip until 5 seed-adds have accumulated.
        # New seeds keep their default energy; existing seeds' entropy is slightly
        # stale but recalculates on the next batch boundary.
        if 0 < diff < 5:
            return
        self._last_corpus_gen = gen

        total_seeds = len(corpus.seeds)
        if total_seeds == 0:
            return

        prod = self._prod_mod

        # DG018 stopping-signal phase gate. Default (no signal, or
        # discovery phase) leaves both factors at their identity values
        # so the loop below is byte-identical to the pre-signal version.
        signal = self._stopping_signal
        in_exploit = signal is not None and signal.phase == "exploitation"
        novelty_factor = _EXPLOIT_NOVELTY_FACTOR if in_exploit else 1.0
        penalty_power = _EXPLOIT_PENALTY_POWER if in_exploit else 1.0

        if _NATIVE:
            feature_sets = [s.feature_set or None for s in corpus.seeds]
            energies = _n_entropic(
                feature_sets, corpus.edge_freq,
                total_seeds, self.theta, self.base_energy,
            )
            for seed, energy in zip(corpus.seeds, energies):
                penalty = self._class_saturation_penalty(seed.id)
                if in_exploit:
                    energy *= novelty_factor
                    penalty = penalty ** penalty_power
                seed.energy = max(
                    energy * prod.get(seed.id, 1.0) * penalty, 0.01
                )
            self._apply_family_cap(corpus)
            return

        edge_freq = corpus.edge_freq

        for seed in corpus.seeds:
            mod = prod.get(seed.id, 1.0)
            penalty = self._class_saturation_penalty(seed.id)
            if in_exploit:
                penalty = penalty ** penalty_power

            if not seed.feature_set:
                seed.energy = max(self.base_energy * mod * penalty, 0.01)
                continue

            entropy = 0.0
            for f in seed.feature_set:
                freq = edge_freq.get(f, 1)
                if freq >= self.theta:
                    continue  # abundant feature — skip
                p = freq / total_seeds
                if p > 0:
                    entropy += -math.log2(p)

            if in_exploit:
                entropy *= novelty_factor

            seed.energy = max(
                entropy * self.base_energy * mod * penalty, 0.01
            )

        self._apply_family_cap(corpus)
