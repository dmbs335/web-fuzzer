"""Composite scheduler — mixes multiple scheduling strategies.

Enables MAP-Elites + Entropic composition: on each ``select()`` call,
with probability *p_secondary*, use the secondary scheduler (e.g.
MAP-Elites frontier); otherwise use the primary (e.g. Entropic).
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from ..protocols import ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Corpus, Seed


class CompositeScheduler:
    """Compose two :class:`SeedScheduler` implementations.

    Args:
        primary: Main scheduler (e.g. EntropicScheduler).
        secondary: Exploratory scheduler (e.g. MapElitesScheduler).
        p_secondary: Probability of using *secondary* per ``select()``.
        seed: Random seed.
    """

    def __init__(
        self,
        primary,       # SeedScheduler
        secondary,     # SeedScheduler
        p_secondary: float = 0.3,
        seed: int | None = None,
    ) -> None:
        self.primary = primary
        self.secondary = secondary
        self.p_secondary = p_secondary
        self.rng = random.Random(seed)

    def select(self, corpus: Corpus) -> Seed:
        if self.rng.random() < self.p_secondary:
            return self.secondary.select(corpus)
        return self.primary.select(corpus)

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        self.primary.update(seed, result)
        self.secondary.update(seed, result)
