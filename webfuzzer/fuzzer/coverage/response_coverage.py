"""Response-based pseudo-coverage for blackbox fuzzing.

When no instrumentation is available, uses response characteristics
as a proxy for code coverage:
  - HTTP status code
  - Content length bucket
  - Error signature hash
  - Response time bucket

For targets that emit structured JSON output (e.g., Java deserialization),
parses semantic fields to create richer coverage features:
  - chain_classes hash (different gadget chains = new coverage)
  - sink_reached type (reaching cmd_exec vs jndi vs reflection)
  - sink_depth bucket (how deep into the chain)
  - method_invocations hash (which methods were called)
  - danger_indicators flags (process_spawned, jndi_lookup, etc.)
  - deserialized success/failure

This implements the JDD-style sink-directed coverage guidance:
inputs that reach deeper into dangerous sinks get distinct coverage
features, providing gradient for the scheduler to prioritize them.
"""

from __future__ import annotations

import hashlib
import json as _json

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
        _danger_lvl = 0

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

        # Feature 7: Structured JSON output features (JDD-style sink-directed)
        # Parses target JSON to extract semantic coverage from chain structure,
        # sink reachability, and danger indicators. This provides gradient
        # toward deeper/more dangerous gadget chains.
        _danger_lvl = self._extract_structured_features(bitmap, result)

        edge_count = sum(1 for b in bitmap if b)
        return CoverageMap(bitmap=bitmap, edge_count=edge_count, danger_lvl=_danger_lvl)

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

    def _extract_structured_features(
        self, bitmap: bytearray, result: ExecutionResult,
    ) -> int:
        """Extract semantic coverage features from structured JSON output.

        Returns the computed danger level (0 if not applicable).

        Recognises targets that emit JSON with fields like:
            deserialized, chain_classes, sink_reached, sink_depth,
            method_invocations, filter_decision, danger_indicators, etc.
        Each distinct combination maps to a coverage feature, providing
        the fuzzer with gradient toward deeper/more dangerous chains.
        """
        parsed = result.parsed_json()
        if parsed is None:
            return 0

        # Only activate for outputs that look like deser targets
        if "deserialized" not in parsed and "sink_reached" not in parsed:
            return 0

        _sf = self._set_feature
        danger = 0

        # F7a: Deserialization success/failure
        deser = parsed.get("deserialized")
        if deser is not None:
            _sf(bitmap, "deser_ok", str(bool(deser)))
            if deser:
                danger = 1

        # F7b: Chain classes hash — each unique class combination = new coverage
        chain_classes = parsed.get("chain_classes")
        if chain_classes and isinstance(chain_classes, list):
            # Sort for determinism, hash to single feature
            cc_sig = ",".join(sorted(str(c) for c in chain_classes))
            _sf(bitmap, "chain_hash", hashlib.sha256(cc_sig.encode()).hexdigest()[:8])
            # Also track chain length bucket
            cc_len = len(chain_classes)
            cc_bucket = "1-5" if cc_len <= 5 else "6-10" if cc_len <= 10 else "11-20" if cc_len <= 20 else "20+"
            _sf(bitmap, "chain_len", cc_bucket)

        # F7c: Sink reached — each sink type is a distinct coverage feature
        sink = parsed.get("sink_reached")
        if sink:
            _sf(bitmap, "sink", str(sink))
            if sink in ("cmd_exec", "jndi_lookup", "script_exec"):
                danger = max(danger, 5)
            elif sink in ("file_write", "file_read", "network", "class_load"):
                danger = max(danger, 4)
            elif sink == "reflection":
                danger = max(danger, 3)

        # F7d: Sink depth bucket — deeper chains = more interesting
        sink_depth = parsed.get("sink_depth")
        if isinstance(sink_depth, (int, float)) and sink_depth > 0:
            depth_bucket = "1" if sink_depth <= 1 else "2-3" if sink_depth <= 3 else "4-6" if sink_depth <= 6 else "7+"
            _sf(bitmap, "sink_depth", depth_bucket)
            if sink_depth > 1 and danger < 2:
                danger = 2

        # F7e: Method invocations hash — different call chains = new coverage
        method_invocations = parsed.get("method_invocations")
        if method_invocations and isinstance(method_invocations, list):
            mi_sig = ",".join(str(m) for m in method_invocations)
            _sf(bitmap, "methods", hashlib.sha256(mi_sig.encode()).hexdigest()[:8])
            # Track count bucket
            mi_len = len(method_invocations)
            mi_bucket = "1-3" if mi_len <= 3 else "4-8" if mi_len <= 8 else "9+"
            _sf(bitmap, "method_cnt", mi_bucket)

        # F7f: Filter decision
        filter_dec = parsed.get("filter_decision")
        if filter_dec:
            _sf(bitmap, "filter", str(filter_dec).upper())

        # F7g: Danger indicators — individual boolean flags
        for indicator in (
            "process_spawned", "jndi_lookup", "class_loaded",
            "file_accessed", "network_connected", "thread_created",
        ):
            val = parsed.get(indicator)
            if val is None:
                # Check nested danger_indicators dict
                di = parsed.get("danger_indicators")
                if isinstance(di, dict):
                    val = di.get(indicator)
            if val:
                _sf(bitmap, f"di_{indicator}", "1")
                # Escalate danger for critical indicators
                if indicator == "process_spawned":
                    danger = max(danger, 6)
                elif indicator == "jndi_lookup":
                    danger = max(danger, 5)
                elif indicator == "class_loaded":
                    danger = max(danger, 3)

        # F7h: readObject call count bucket
        ro_calls = parsed.get("readObject_calls")
        if isinstance(ro_calls, (int, float)) and ro_calls > 0:
            ro_bucket = "1-3" if ro_calls <= 3 else "4-10" if ro_calls <= 10 else "11+"
            _sf(bitmap, "ro_calls", ro_bucket)

        # F7i: Exception type (different exceptions = different code paths)
        exc = parsed.get("exception")
        if exc and isinstance(exc, str):
            # Extract exception class name (last component)
            exc_class = exc.split(":")[0].strip().rsplit(".", 1)[-1] if "." in exc else exc[:40]
            _sf(bitmap, "exc_class", exc_class)

        # F7j: Danger level as coverage feature (provides gradient)
        if danger > 0:
            _sf(bitmap, "danger_lvl", str(danger))

        return danger

    def _set_feature(self, bitmap: bytearray, namespace: str, value: str) -> None:
        """Hash a feature into the bitmap."""
        if _NATIVE:
            _n_set_feature(bitmap, namespace, value, self.map_size)
            return
        h = hashlib.sha256(f"{namespace}:{value}".encode()).digest()
        idx = int.from_bytes(h[:2], "little") % self.map_size
        bitmap[idx] = min(bitmap[idx] + 1, 255)
