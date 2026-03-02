"""Raw feature storage for CEGAR-style adaptive coverage refinement.

Stores pre-hash feature data per seed so the coverage bitmap can be
rebuilt at a different abstraction level without re-executing targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FeatureRecord:
    """Raw feature data for a single seed, before hashing.

    Memory estimate: ~15 (namespace, value) tuples of short strings
    plus parsed JSON dicts ≈ 2 KB per seed.
    """

    seed_id: int
    # Every (namespace, value) pair that _set_feature was called with
    # at the *maximum* level (L4).  We always capture everything so
    # any lower level can be reconstructed by filtering.
    features: list[tuple[str, str]] = field(default_factory=list)
    # Parsed JSON outputs for all targets (primary + refs).
    parsed_outputs: list[dict[str, Any] | None] = field(default_factory=list)
    # Number of divergent parser pairs.
    div_count: int = 0


class FeatureStore:
    """In-memory mapping from seed_id → :class:`FeatureRecord`."""

    def __init__(self) -> None:
        self._records: dict[int, FeatureRecord] = {}

    def store(self, seed_id: int, record: FeatureRecord) -> None:
        self._records[seed_id] = record

    def get(self, seed_id: int) -> FeatureRecord | None:
        return self._records.get(seed_id)

    def remove(self, seed_id: int) -> None:
        self._records.pop(seed_id, None)

    def all_records(self) -> list[FeatureRecord]:
        return list(self._records.values())

    def __len__(self) -> int:
        return len(self._records)
