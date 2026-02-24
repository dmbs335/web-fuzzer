"""Seed corpus and coverage map management."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .protocols import Input

# AFL-style bitmap size
MAP_SIZE = 1 << 16  # 65536

# Hit-count bucketing (AFL convention)
_COUNT_BUCKETS = [1, 2, 3, 4, 8, 16, 32, 128]

# Native acceleration (optional — falls back to pure Python)
try:
    from webfuzzer.native import AVAILABLE as _NATIVE
    if _NATIVE:
        from webfuzzer.native import bitmap_has_new_bits as _n_has_new
        from webfuzzer.native import bitmap_update as _n_update
        from webfuzzer.native import bitmap_count as _n_count
    else:
        _NATIVE = False
except ImportError:
    _NATIVE = False


def _bucket(count: int) -> int:
    """Bucket a raw hit count into AFL-style classes."""
    for b in _COUNT_BUCKETS:
        if count < b:
            return b
    return 128


@dataclass
class CoverageMap:
    """Generalised coverage bitmap — AFL-style edge coverage."""

    bitmap: bytearray = field(default_factory=lambda: bytearray(MAP_SIZE))
    edge_count: int = 0

    def has_new_bits(self, other: CoverageMap) -> bool:
        """Return True if *other* contains any edge not in *self*."""
        if _NATIVE:
            return _n_has_new(self.bitmap, other.bitmap)
        for i in range(MAP_SIZE):
            if other.bitmap[i] and not self.bitmap[i]:
                return True
            if other.bitmap[i] and _bucket(other.bitmap[i]) != _bucket(self.bitmap[i]):
                return True
        return False

    def update(self, other: CoverageMap) -> set[int]:
        """Merge *other* into *self*. Return set of newly discovered edge indices."""
        if _NATIVE:
            new_edges, self.edge_count = _n_update(self.bitmap, other.bitmap)
            return new_edges
        new_edges: set[int] = set()
        for i in range(MAP_SIZE):
            if other.bitmap[i]:
                old_bucket = _bucket(self.bitmap[i]) if self.bitmap[i] else 0
                new_bucket = _bucket(other.bitmap[i])
                if old_bucket != new_bucket:
                    new_edges.add(i)
                self.bitmap[i] = max(self.bitmap[i], other.bitmap[i])
        self.edge_count = sum(1 for b in self.bitmap if b)
        return new_edges

    def edges(self) -> set[int]:
        """Return the set of edge indices that have been hit."""
        return {i for i, b in enumerate(self.bitmap) if b}

    def clone(self) -> CoverageMap:
        return CoverageMap(bitmap=bytearray(self.bitmap), edge_count=self.edge_count)


@dataclass
class Seed:
    """A single entry in the fuzzing corpus."""

    id: int
    input: Input
    coverage: CoverageMap | None = None

    # Scheduling metadata
    energy: float = 1.0
    priority_boost: float = 1.0  # External priority multiplier (AFLFast-style power schedule overlay)
    exec_count: int = 0
    finding_count: int = 0
    depth: int = 0
    parent_id: int | None = None

    # Timing
    created_at: float = field(default_factory=time.time)
    last_mutated_at: float = 0.0

    # Entropic: features discovered by this seed
    feature_set: set[int] = field(default_factory=set)

    # FairFuzz: rare branches hit by this seed
    rare_branches: set[int] = field(default_factory=set)


class Corpus:
    """Manages the seed corpus with global coverage tracking."""

    def __init__(self, map_size: int = MAP_SIZE) -> None:
        self.seeds: list[Seed] = []
        self.global_coverage = CoverageMap(bitmap=bytearray(map_size))
        self._next_id = 0
        self._id_index: dict[int, Seed] = {}
        # Per-edge frequency: how many seeds hit each edge
        self.edge_freq: dict[int, int] = {}

    def __len__(self) -> int:
        return len(self.seeds)

    def add(self, inp: Input, coverage: CoverageMap | None = None,
            parent_id: int | None = None, depth: int = 0) -> Seed | None:
        """Add a new seed. Returns the Seed if novel, None if not."""
        if coverage is not None:
            if not self.global_coverage.has_new_bits(coverage):
                return None
            new_edges = self.global_coverage.update(coverage)
        else:
            new_edges = set()

        seed = Seed(
            id=self._next_id,
            input=inp,
            coverage=coverage.clone() if coverage else None,
            parent_id=parent_id,
            depth=depth,
            feature_set=new_edges,
        )
        self._next_id += 1
        self.seeds.append(seed)
        self._id_index[seed.id] = seed

        # Update edge frequency
        for edge in new_edges:
            self.edge_freq[edge] = self.edge_freq.get(edge, 0) + 1

        return seed

    def force_add(self, inp: Input, coverage: CoverageMap | None = None) -> Seed:
        """Add a seed unconditionally (for initial seeding)."""
        if coverage is not None:
            new_edges = self.global_coverage.update(coverage)
        else:
            new_edges = set()

        seed = Seed(
            id=self._next_id,
            input=inp,
            coverage=coverage.clone() if coverage else None,
            feature_set=new_edges,
        )
        self._next_id += 1
        self.seeds.append(seed)
        self._id_index[seed.id] = seed

        for edge in new_edges:
            self.edge_freq[edge] = self.edge_freq.get(edge, 0) + 1

        return seed

    def remove(self, seed_id: int) -> None:
        seed = self._id_index.pop(seed_id, None)
        if seed:
            self.seeds = [s for s in self.seeds if s.id != seed_id]

    def get_by_id(self, seed_id: int) -> Seed | None:
        return self._id_index.get(seed_id)

    def set_priority(self, seed_id: int, boost: float) -> bool:
        """Set external priority boost for a seed. Returns True if seed found."""
        seed = self._id_index.get(seed_id)
        if seed is None:
            return False
        seed.priority_boost = max(0.01, min(boost, 100.0))
        return True

    def reset_priorities(self) -> None:
        """Reset all seeds' priority_boost to 1.0."""
        for seed in self.seeds:
            seed.priority_boost = 1.0

    def minimize(self) -> None:
        """Greedy corpus minimization — keep minimum set covering all edges."""
        if not self.seeds:
            return

        all_edges = self.global_coverage.edges()
        covered: set[int] = set()
        kept: list[Seed] = []

        # Sort seeds by number of unique edges (descending)
        ranked = sorted(
            self.seeds,
            key=lambda s: len(s.feature_set) if s.feature_set else 0,
            reverse=True,
        )

        for seed in ranked:
            seed_edges = seed.feature_set or set()
            if seed_edges - covered:
                kept.append(seed)
                covered |= seed_edges
            if covered >= all_edges:
                break

        self.seeds = kept
        self._id_index = {s.id: s for s in kept}

    def save(self, path: Path) -> None:
        """Save corpus to directory (one file per seed)."""
        path.mkdir(parents=True, exist_ok=True)
        for seed in self.seeds:
            seed_file = path / f"id_{seed.id:06d}"
            seed_file.write_bytes(seed.input.data)

            meta_file = path / f"id_{seed.id:06d}.meta"
            meta = {
                "id": seed.id,
                "parent_id": seed.parent_id,
                "depth": seed.depth,
                "energy": seed.energy,
                "exec_count": seed.exec_count,
                "finding_count": seed.finding_count,
                "metadata": seed.input.metadata,
            }
            meta_file.write_text(json.dumps(meta, default=str), encoding="utf-8")

    def load(self, path: Path) -> None:
        """Load corpus from directory."""
        if not path.is_dir():
            return

        for seed_file in sorted(path.glob("id_*")):
            if seed_file.suffix == ".meta":
                continue
            data = seed_file.read_bytes()
            meta_file = seed_file.with_suffix(".meta")
            metadata: dict[str, Any] = {}
            if meta_file.exists():
                raw = json.loads(meta_file.read_text(encoding="utf-8"))
                metadata = raw.get("metadata", {})
            inp = Input(data=data, metadata=metadata)
            self.force_add(inp)
