"""Random seed and mutator schedulers — simplest baseline."""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from ..protocols import Mutator, ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Corpus, Seed


class RandomSeedScheduler:
    """Uniformly random seed selection from corpus."""

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def select(self, corpus: Corpus) -> Seed:
        weights = [s.priority_boost for s in corpus.seeds]
        return self.rng.choices(corpus.seeds, weights=weights, k=1)[0]

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        pass


class RandomMutatorScheduler:
    """Uniformly random mutator selection."""

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def select(self, mutators: list[Mutator], seed: Seed) -> Mutator:
        return self.rng.choice(mutators)

    def update(self, mutator: Mutator, result: ScheduleResult) -> None:
        pass
