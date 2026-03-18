"""Danger-weighted seed priority booster.

Adjusts seed.priority_boost based on the danger level of offspring,
creating a positive feedback loop: high-danger regions get more
mutation budget, increasing the chance of reaching danger=5,6.

Works with ALL existing schedulers via the priority_boost multiplier.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..corpus import Corpus, Seed

logger = logging.getLogger(__name__)


@dataclass
class DangerBoostConfig:
    """Configuration for danger-weighted boosting."""

    # Multiplicative boost per danger level (applied to parent seed).
    # danger 0-1: baseline (no boost)
    # danger 2: namespace element survived → mild interest
    # danger 3: structural mXSS → strong interest
    # danger 4: browser-confirmed → very strong
    # danger 5: dangerous pattern after reparse → critical
    # danger 6: sanitizer bypassed → maximum priority
    boost_table: dict[int, float] = field(default_factory=lambda: {
        0: 1.0, 1: 1.0, 2: 1.5, 3: 3.0, 4: 5.0, 5: 10.0, 6: 20.0,
    })

    # Priority halves every N execs without new danger escalation.
    decay_halflife_execs: int = 200

    min_boost: float = 0.5
    max_boost: float = 50.0

    # Fraction of boost propagated to ancestors (geometric decay per depth).
    ancestor_decay: float = 0.5
    max_propagation_depth: int = 2

    enabled: bool = True


class DangerBooster:
    """Adjusts seed priority_boost based on offspring danger levels.

    Called from the engine loop after each execution. Only boosts on
    danger *escalation* (not repeated same-level results), preventing
    runaway amplification.

    Usage::

        booster = DangerBooster()
        # In engine loop, after coverage collection:
        booster.on_execution(parent_seed, child_danger_lvl, corpus)
        # Periodically:
        booster.apply_decay(corpus)
    """

    def __init__(self, config: DangerBoostConfig | None = None) -> None:
        self.config = config or DangerBoostConfig()
        # Per-seed: max danger level that triggered a boost
        self._seed_max_danger: dict[int, int] = {}
        # Per-seed: exec_count at last boost (for decay calculation)
        self._seed_last_boost_exec: dict[int, int] = {}

    def on_execution(
        self, parent: Seed, child_danger: int, corpus: Corpus,
    ) -> None:
        """Boost parent seed if offspring produced higher danger than before."""
        if not self.config.enabled or child_danger < 2:
            return

        prev_max = self._seed_max_danger.get(parent.id, 0)
        if child_danger <= prev_max:
            return  # No escalation — skip

        # Record new max danger for this seed
        self._seed_max_danger[parent.id] = child_danger
        self._seed_last_boost_exec[parent.id] = parent.exec_count

        # Compute boost from table
        boost = self.config.boost_table.get(child_danger, 1.0)
        if boost <= 1.0:
            return

        # Apply to parent
        new_boost = min(parent.priority_boost * boost, self.config.max_boost)
        corpus.set_priority(parent.id, new_boost)

        logger.debug(
            "DangerBoost: seed %d danger %d→%d, priority %.1f→%.1f",
            parent.id, prev_max, child_danger,
            parent.priority_boost, new_boost,
        )

        # Propagate upward to ancestors
        self._propagate_to_ancestors(parent, boost, corpus, depth=0)

    def _propagate_to_ancestors(
        self, seed: Seed, boost: float, corpus: Corpus, depth: int,
    ) -> None:
        """Propagate attenuated boost to parent seeds."""
        if depth >= self.config.max_propagation_depth:
            return
        if seed.parent_id is None:
            return

        ancestor = corpus.get_by_id(seed.parent_id)
        if ancestor is None:
            return

        frac_boost = boost * (self.config.ancestor_decay ** (depth + 1))
        if frac_boost < 1.05:
            return  # Too small to matter

        new_boost = min(ancestor.priority_boost * frac_boost, self.config.max_boost)
        corpus.set_priority(ancestor.id, new_boost)

        self._propagate_to_ancestors(ancestor, boost, corpus, depth + 1)

    def apply_decay(self, corpus: Corpus) -> None:
        """Execution-based exponential decay for all boosted seeds.

        Seeds that haven't produced higher danger signals decay toward 1.0.
        Call periodically (e.g. every 2000 iterations).
        """
        halflife = self.config.decay_halflife_execs
        if halflife <= 0:
            return

        for seed in corpus.seeds:
            if seed.priority_boost <= 1.0:
                continue

            last_exec = self._seed_last_boost_exec.get(seed.id, 0)
            execs_since = seed.exec_count - last_exec
            if execs_since <= 0:
                continue

            # Exponential decay: boost * 0.5^(execs_since / halflife)
            decay_factor = 0.5 ** (execs_since / halflife)
            decayed = 1.0 + (seed.priority_boost - 1.0) * decay_factor
            decayed = max(decayed, self.config.min_boost)
            corpus.set_priority(seed.id, decayed)

    def cleanup_removed(self, removed_ids: set[int]) -> None:
        """Clean up tracking state for removed seeds."""
        for sid in removed_ids:
            self._seed_max_danger.pop(sid, None)
            self._seed_last_boost_exec.pop(sid, None)
