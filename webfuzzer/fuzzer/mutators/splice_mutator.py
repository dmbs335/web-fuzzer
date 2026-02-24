"""Cross-seed splicing mutator (Superion/AFL style).

Selects two seeds from the corpus and splices them at a random
boundary. Can operate at both byte level and grammar tree level.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed


class SpliceMutator:
    """Cross-seed byte-level splicing."""

    name = "splice"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        if not corpus:
            return inp

        data_a = bytearray(inp.data)
        other = self.rng.choice(corpus)
        data_b = bytearray(other.input.data)

        if not data_a or not data_b:
            return inp

        # Pick splice points
        split_a = self.rng.randint(0, len(data_a))
        split_b = self.rng.randint(0, len(data_b))

        # Choose splice direction
        if self.rng.random() < 0.5:
            result = bytes(data_a[:split_a]) + bytes(data_b[split_b:])
        else:
            result = bytes(data_b[:split_b]) + bytes(data_a[split_a:])

        return Input(
            data=result,
            metadata={**inp.metadata, "mutator": self.name},
        )
