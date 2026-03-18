"""MAP-Elites quality-diversity scheduler for differential fuzzing.

Maintains a behaviour archive indexed by ``(category, ref_index)`` where
each cell holds the "best" seed — the one with the richest coverage.

Frontier exploration: preferentially selects seeds from cells adjacent
to empty cells in the grid, driving exploration toward undiscovered
parser disagreement patterns.

References:
  Mouret & Clune, "Illuminating search spaces by mapping elites",
  IEEE TEC 2015.
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from ..domain import get_all_categories as _get_all_categories
from ..protocols import ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Corpus, Seed

# Dynamic CATEGORIES — built from all registered DomainProfiles.
# New domains auto-extend this list by calling domain.register().
CATEGORIES: list[str] = _get_all_categories()

MAX_REF_INDEX = 8

# Cell coordinates: (category_idx, ref_idx)
CellKey = tuple[int, int]


class MapElitesArchive:
    """Behaviour archive: 2-D grid of (category, ref_index) → best Seed.

    Grid size: ``len(CATEGORIES) × MAX_REF_INDEX`` = 80 cells.
    """

    def __init__(self) -> None:
        self._grid: dict[CellKey, Seed] = {}
        self._cat_idx = {c: i for i, c in enumerate(CATEGORIES)}

    def try_insert(self, seed: Seed, category: str, ref_index: int) -> bool:
        """Insert if cell empty or seed is richer than occupant.

        "Richer" = larger ``feature_set`` (more coverage features).
        """
        key = self._to_key(category, ref_index)
        existing = self._grid.get(key)
        if existing is None or len(seed.feature_set or ()) > len(existing.feature_set or ()):
            self._grid[key] = seed
            return True
        return False

    def frontier_seeds(self) -> list[Seed]:
        """Seeds in cells that have at least one empty neighbour.

        These are the most promising for discovering new behaviours —
        they sit on the boundary of the explored region.
        """
        frontier: list[Seed] = []
        for key, seed in self._grid.items():
            if self._has_empty_neighbour(key):
                frontier.append(seed)
        return frontier if frontier else list(self._grid.values())

    def all_seeds(self) -> list[Seed]:
        return list(self._grid.values())

    @property
    def filled_cells(self) -> int:
        return len(self._grid)

    @property
    def total_cells(self) -> int:
        return len(CATEGORIES) * MAX_REF_INDEX

    def coverage_ratio(self) -> float:
        return self.filled_cells / self.total_cells if self.total_cells else 0.0

    # ── Internal ──────────────────────────────────────────────────

    def _to_key(self, category: str, ref_index: int) -> CellKey:
        cat_i = self._cat_idx.get(category, len(CATEGORIES) - 1)
        ref_i = min(max(ref_index, 0), MAX_REF_INDEX - 1)
        return (cat_i, ref_i)

    def _has_empty_neighbour(self, key: CellKey) -> bool:
        cat_i, ref_i = key
        for dc in (-1, 0, 1):
            for dr in (-1, 0, 1):
                if dc == 0 and dr == 0:
                    continue
                nb = (cat_i + dc, ref_i + dr)
                if self._is_valid(nb) and nb not in self._grid:
                    return True
        return False

    @staticmethod
    def _is_valid(key: CellKey) -> bool:
        return 0 <= key[0] < len(CATEGORIES) and 0 <= key[1] < MAX_REF_INDEX


class MapElitesScheduler:
    """MAP-Elites seed scheduler — quality-diversity for diff fuzzing.

    Works best when composed with ``EntropicScheduler`` via
    :class:`CompositeScheduler`.
    """

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self.archive = MapElitesArchive()

    def select(self, corpus: Corpus) -> Seed:
        """Select from frontier seeds (adjacent to empty cells)."""
        frontier = self.archive.frontier_seeds()
        if frontier:
            weights = [max(s.energy * s.priority_boost, 0.01) for s in frontier]
            return self.rng.choices(frontier, weights=weights, k=1)[0]
        # Fallback: random from corpus
        if corpus.seeds:
            return self.rng.choice(corpus.seeds)
        raise RuntimeError("MapElitesScheduler: empty corpus")

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        """Update archive from finding metadata carried in ScheduleResult."""
        finding_metas: list[dict] = getattr(result, "finding_metadata", [])

        if finding_metas:
            for meta in finding_metas:
                self.archive.try_insert(
                    seed,
                    category=meta.get("category", "no_finding"),
                    ref_index=meta.get("ref_index", 0),
                )
        else:
            # No finding — bucket by coverage hash into no_finding row.
            cov_bucket = hash(frozenset(seed.feature_set or ())) % MAX_REF_INDEX
            self.archive.try_insert(seed, "no_finding", cov_bucket)
