"""Protocol state coverage (AFLNet, ICST'20 style).

Tracks state transitions in stateful protocols.
State is identified by response code sequences.
Coverage = set of (prev_state, curr_state) transitions.
"""

from __future__ import annotations

import hashlib

from ..corpus import MAP_SIZE, CoverageMap
from ..protocols import ExecutionResult


class StateCoverageCollector:
    """Tracks protocol state transitions as coverage features."""

    def __init__(self, map_size: int = MAP_SIZE) -> None:
        self.map_size = map_size
        self._prev_state: int = 0

    def collect(self, result: ExecutionResult) -> CoverageMap:
        bitmap = bytearray(self.map_size)

        # Compute current state from response
        curr_state = self._compute_state(result)

        # Record state transition: (prev_state, curr_state)
        transition = f"{self._prev_state}:{curr_state}"
        h = hashlib.sha256(transition.encode()).digest()
        idx = int.from_bytes(h[:2], "little") % self.map_size
        bitmap[idx] = 1

        # Record individual state
        state_h = hashlib.sha256(f"state:{curr_state}".encode()).digest()
        state_idx = int.from_bytes(state_h[:2], "little") % self.map_size
        bitmap[state_idx] = 1

        self._prev_state = curr_state

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

    def reset(self) -> None:
        """Reset state tracking (call between independent sessions)."""
        self._prev_state = 0

    def _compute_state(self, result: ExecutionResult) -> int:
        """Compute state identifier from execution result."""
        status = result.metadata.get("status_code", result.exit_code)
        # Include response header signature for richer state
        headers_sig = ""
        headers = result.metadata.get("headers", {})
        if isinstance(headers, dict):
            # Key headers that indicate state changes
            for key in ["location", "set-cookie", "www-authenticate", "content-type"]:
                if key in headers:
                    headers_sig += f"{key}={headers[key]};"

        state_str = f"{status}:{headers_sig}"
        return hash(state_str) & 0xFFFFFFFF
