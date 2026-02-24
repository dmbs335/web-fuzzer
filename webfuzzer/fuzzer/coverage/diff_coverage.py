"""Differential coverage — uses output divergence as coverage signal.

Inspired by Nezha (IEEE S&P'17) delta-diversity:
  Instead of code coverage, track *behavioral* diversity across
  multiple implementations. An input is "interesting" if it produces
  different behaviors across reference targets.

Features hashed into the bitmap (coarse-grained to prevent corpus explosion):
  1. Exit code class vector: (primary_class, ref0_class, ref1_class, ...)
  2. Per-pair divergence signature: frozenset of differing components → single hash
  3. Status code vector (for HTTP targets)
  4. Error pattern divergence
  5. Divergence count bucket (0, 1, 2-3, 4+)

This guides the fuzzer toward inputs that trigger *differential*
behavior — exactly what differential fuzzing needs.
"""

from __future__ import annotations

import hashlib
import json as _json

from ..corpus import MAP_SIZE, CoverageMap
from ..protocols import ExecutionResult, Target, Input

# URL component keys used for structural diff hashing
_URL_KEYS = ("scheme", "userinfo", "host", "port", "path", "query", "fragment")

# Native acceleration (optional)
try:
    from webfuzzer.native import AVAILABLE as _NATIVE
    if _NATIVE:
        from webfuzzer.native import feature_set_bitmap as _n_set_feature
    else:
        _NATIVE = False
except ImportError:
    _NATIVE = False


class DiffCoverageCollector:
    """Coverage based on behavioral divergence across targets.

    Each unique divergence pattern maps to a feature in the bitmap.
    More divergence patterns = more coverage = more interesting inputs.

    Usage:
        collector = DiffCoverageCollector(reference_targets=[target_b, target_c])

        # In the engine loop:
        primary_result = primary_target.execute(inp)
        cov = collector.collect_diff(inp, primary_result)
    """

    def __init__(
        self,
        reference_targets: list[Target],
        map_size: int = MAP_SIZE,
    ) -> None:
        self.reference_targets = reference_targets
        self.map_size = map_size

    def collect(self, result: ExecutionResult) -> CoverageMap:
        """Standard collect — only uses primary result features.

        For full differential coverage, use collect_diff() instead.
        This exists to satisfy the CoverageCollector Protocol.
        """
        bitmap = bytearray(self.map_size)

        # Basic features from primary result
        status = result.metadata.get("status_code", result.exit_code)
        self._set_feature(bitmap, "primary_status", str(status))

        out_hash = hashlib.sha256(result.stdout[:1024]).hexdigest()[:8]
        self._set_feature(bitmap, "primary_out", out_hash)

        edge_count = sum(1 for b in bitmap if b)
        return CoverageMap(bitmap=bitmap, edge_count=edge_count)

    def collect_diff(
        self, inp: Input, primary_result: ExecutionResult,
        ref_results: list[ExecutionResult] | None = None,
    ) -> CoverageMap:
        """Collect coverage based on divergence across all targets.

        If ref_results is provided, uses cached results instead of
        re-executing reference targets.
        """
        bitmap = bytearray(self.map_size)

        # Use cached results or execute against all references
        if ref_results is None:
            ref_results = []
            for target in self.reference_targets:
                try:
                    ref = target.execute(inp)
                    ref_results.append(ref)
                except Exception:
                    ref_results.append(ExecutionResult(exit_code=-999))

        # Feature 1: Exit code class vector
        exit_classes = [self._exit_class(primary_result)]
        for ref in ref_results:
            exit_classes.append(self._exit_class(ref))
        exit_vec = ",".join(str(c) for c in exit_classes)
        self._set_feature(bitmap, "exit_vec", exit_vec)

        # Parse all outputs
        parsed = [self._parse_url_json(primary_result)]
        for ref in ref_results:
            parsed.append(self._parse_url_json(ref))

        n = len(ref_results)

        # Feature 2: Per-pair divergence signature (coarse)
        # Hash the SET of differing components per pair as ONE feature,
        # not one feature per component.  This collapses the feature space
        # from 7*n individual bits to n composite features.
        div_count = 0
        for i in range(n):
            p = parsed[0]
            r = parsed[i + 1]
            if p is not None and r is not None:
                diff_keys = sorted(
                    k for k in _URL_KEYS
                    if str(p.get(k, "")).strip().lower() != str(r.get(k, "")).strip().lower()
                )
                if diff_keys:
                    self._set_feature(bitmap, f"cdiff_0_{i}", ",".join(diff_keys))
                    div_count += 1
            elif p is None and r is not None:
                self._set_feature(bitmap, f"parse_0_{i}", "primary_fail")
                div_count += 1
            elif p is not None and r is None:
                self._set_feature(bitmap, f"parse_0_{i}", "ref_fail")
                div_count += 1

            # Exit code divergence
            if exit_classes[0] != exit_classes[i + 1]:
                self._set_feature(bitmap, f"div_exit_0_{i}", "1")
                if div_count == 0:
                    div_count += 1

        # Feature 3: Status code vector (HTTP targets)
        status_codes = [primary_result.metadata.get("status_code")]
        for ref in ref_results:
            status_codes.append(ref.metadata.get("status_code"))
        if any(s is not None for s in status_codes):
            status_vec = ",".join(str(s or "?") for s in status_codes)
            self._set_feature(bitmap, "status_vec", status_vec)

        # Feature 4: Error pattern divergence
        p_has_err = bool(primary_result.stderr)
        for i, ref in enumerate(ref_results):
            r_has_err = bool(ref.stderr)
            if p_has_err != r_has_err:
                self._set_feature(bitmap, f"div_err_0_{i}", "1")

        # Feature 5: Divergence count bucket (coarse)
        bucket = "0" if div_count == 0 else "1" if div_count == 1 else "2-3" if div_count <= 3 else "4+"
        self._set_feature(bitmap, "div_bucket", bucket)

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

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _exit_class(result: ExecutionResult) -> int:
        """Classify exit code: 0=ok, 1=error, -1=signal/crash."""
        if result.exit_code == 0:
            return 0
        if result.exit_code < 0:
            return -1
        return 1

    @staticmethod
    def _parse_url_json(result: ExecutionResult) -> dict | None:
        """Try to parse URL parser JSON output."""
        try:
            text = result.stdout.strip()
            if not text:
                return None
            return _json.loads(text)
        except (ValueError, UnicodeDecodeError):
            return None

    @staticmethod
    def _output_hash(result: ExecutionResult) -> str:
        """Hash output content (first 4KB) for comparison."""
        h = hashlib.sha256()
        h.update(result.stdout[:4096])
        return h.hexdigest()[:8]

    def _set_feature(self, bitmap: bytearray, namespace: str, value: str) -> None:
        if _NATIVE:
            _n_set_feature(bitmap, namespace, value, self.map_size)
            return
        h = hashlib.sha256(f"{namespace}:{value}".encode()).digest()
        idx = int.from_bytes(h[:2], "little") % self.map_size
        bitmap[idx] = 1  # Binary: feature present/absent (no increment)
