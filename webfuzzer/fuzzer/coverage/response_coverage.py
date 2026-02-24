"""Response-based pseudo-coverage for blackbox fuzzing.

When no instrumentation is available, uses response characteristics
as a proxy for code coverage:
  - HTTP status code
  - Content length bucket
  - Error signature hash
  - Response time bucket
"""

from __future__ import annotations

import hashlib

from ..corpus import MAP_SIZE, CoverageMap
from ..protocols import ExecutionResult

# Native acceleration (optional)
try:
    from webfuzzer.native import AVAILABLE as _NATIVE
    if _NATIVE:
        from webfuzzer.native import feature_set_bitmap as _n_set_feature
    else:
        _NATIVE = False
except ImportError:
    _NATIVE = False


# Content length buckets
_LENGTH_BUCKETS = [0, 64, 256, 1024, 4096, 16384, 65536, 262144]


def _bucket_length(length: int) -> int:
    for b in _LENGTH_BUCKETS:
        if length <= b:
            return b
    return 1 << 20


# Response time buckets (ms)
_TIME_BUCKETS = [10, 50, 100, 250, 500, 1000, 5000]


def _bucket_time(ms: float) -> int:
    for b in _TIME_BUCKETS:
        if ms <= b:
            return b
    return 10000


class ResponseCoverageCollector:
    """Blackbox coverage based on response characteristics.

    Each unique (status, length_bucket, error_sig, time_bucket) tuple
    maps to a "feature" in the coverage bitmap.
    """

    def __init__(self, map_size: int = MAP_SIZE) -> None:
        self.map_size = map_size

    def collect(self, result: ExecutionResult) -> CoverageMap:
        bitmap = bytearray(self.map_size)

        # Feature 1: status code
        status = result.metadata.get("status_code", result.exit_code)
        self._set_feature(bitmap, "status", str(status))

        # Feature 2: content length bucket
        body = result.stdout or result.metadata.get("body", b"")
        length_bucket = _bucket_length(len(body))
        self._set_feature(bitmap, "length", str(length_bucket))

        # Feature 3: error signature (first 64 bytes of stderr)
        if result.stderr:
            error_sig = result.stderr[:64]
            self._set_feature(bitmap, "error", error_sig.hex())

        # Feature 4: timing bucket
        time_bucket = _bucket_time(result.duration_ms)
        self._set_feature(bitmap, "time", str(time_bucket))

        # Feature 5: combined signature
        combined = f"{status}:{length_bucket}:{time_bucket}"
        self._set_feature(bitmap, "combined", combined)

        # Feature 6: content-type header if present
        ct = result.metadata.get("content_type", "")
        if ct:
            self._set_feature(bitmap, "content_type", str(ct))

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

    def _set_feature(self, bitmap: bytearray, namespace: str, value: str) -> None:
        """Hash a feature into the bitmap."""
        if _NATIVE:
            _n_set_feature(bitmap, namespace, value, self.map_size)
            return
        h = hashlib.sha256(f"{namespace}:{value}".encode()).digest()
        idx = int.from_bytes(h[:2], "little") % self.map_size
        bitmap[idx] = min(bitmap[idx] + 1, 255)
