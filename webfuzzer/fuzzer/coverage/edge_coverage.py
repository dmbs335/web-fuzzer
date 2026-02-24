"""AFL-style edge coverage collector.

Uses a 64KB bitmap where each byte represents an edge
(source_block XOR dest_block). Supports hit-count bucketing.
"""

from __future__ import annotations

from ..corpus import MAP_SIZE, CoverageMap
from ..protocols import ExecutionResult


class EdgeCoverageCollector:
    """Collects edge coverage from raw bitmap data in ExecutionResult.

    Expects result.coverage_data to be a bytes/bytearray of length MAP_SIZE,
    typically populated by target instrumentation (shared memory bitmap).
    """

    def __init__(self, map_size: int = MAP_SIZE) -> None:
        self.map_size = map_size

    def collect(self, result: ExecutionResult) -> CoverageMap:
        raw = result.coverage_data
        if raw and isinstance(raw, (bytes, bytearray)):
            bitmap = bytearray(raw[:self.map_size])
            if len(bitmap) < self.map_size:
                bitmap.extend(bytearray(self.map_size - len(bitmap)))
        else:
            bitmap = bytearray(self.map_size)

        edge_count = sum(1 for b in bitmap if b)
        return CoverageMap(bitmap=bitmap, edge_count=edge_count)

    def merge(self, a: CoverageMap, b: CoverageMap) -> CoverageMap:
        merged = a.clone()
        merged.update(b)
        return merged

    def is_novel(self, existing: CoverageMap, new: CoverageMap) -> bool:
        return existing.has_new_bits(new)

    def diff(self, old: CoverageMap, new: CoverageMap) -> set[int]:
        result: set[int] = set()
        for i in range(min(len(old.bitmap), len(new.bitmap))):
            if new.bitmap[i] and not old.bitmap[i]:
                result.add(i)
        return result
