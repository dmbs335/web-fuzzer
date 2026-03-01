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
from typing import TYPE_CHECKING

from ..corpus import MAP_SIZE, CoverageMap
from ..domain import get_all_key_sets as _get_all_key_sets
from ..protocols import ExecutionResult, Target, Input

if TYPE_CHECKING:
    from .feature_store import FeatureRecord

# Backward-compat constant (external code may reference this).
_URL_KEYS = ("scheme", "userinfo", "host", "port", "path", "query", "fragment")


def _diff_keys_for(parsed_primary: dict | None, parsed_ref: dict | None) -> tuple[str, ...]:
    """Choose comparison keys based on what the output actually contains.

    Strategy:
      1. Check registered domain key sets (from DomainProfile registry).
      2. Fallback: union of all string-valued keys from both outputs (sorted
         for deterministic hashing). This makes diff coverage work for ANY
         domain without explicit registration.
    """
    sample = parsed_primary or parsed_ref
    if sample is None:
        return _URL_KEYS

    # Check registered domains (stable ordering per profile)
    for domain_keys in _get_all_key_sets():
        if any(k in sample for k in domain_keys):
            return domain_keys

    # Generic fallback: use all top-level keys present in either output.
    # Only consider keys with scalar values (str, int, float, bool)
    # to avoid comparing nested structures that hash poorly.
    all_keys: set[str] = set()
    for d in (parsed_primary, parsed_ref):
        if d is not None:
            for k, v in d.items():
                if isinstance(v, (str, int, float, bool)):
                    all_keys.add(k)
    if all_keys:
        return tuple(sorted(all_keys))
    return _URL_KEYS

# Native acceleration (optional)
try:
    from webfuzzer.native import AVAILABLE as _NATIVE
    if _NATIVE:
        from webfuzzer.native import feature_set_bitmap as _n_set_feature
        from webfuzzer.native import bitmap_count as _n_bitmap_count
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

        edge_count = _n_bitmap_count(bitmap) if _NATIVE else sum(1 for b in bitmap if b)
        return CoverageMap(bitmap=bitmap, edge_count=edge_count)

    def collect_diff(
        self, inp: Input, primary_result: ExecutionResult,
        ref_results: list[ExecutionResult] | None = None,
        level: int = 1,
        raw_record: "FeatureRecord | None" = None,
    ) -> CoverageMap:
        """Collect coverage based on divergence across all targets.

        Args:
            ref_results: Pre-computed reference results (skips re-execution).
            level: Refinement level (0–4) for CEGAR adaptive coverage.
                0 = minimal (exit_vec + div_bucket only)
                1 = coarse (+ per-pair cdiff hash) — default
                2 = component (+ per-component individual bits)
                3 = values (+ actual differing value hashes)
                4 = full (+ status_vec + error patterns)
            raw_record: If provided, ALL features at ALL levels are appended
                to it for later re-hashing by :class:`AdaptiveDiffCoverage`.
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

        # Feature 1: Exit code class vector (L0+, always)
        exit_classes = [self._exit_class(primary_result)]
        for ref in ref_results:
            exit_classes.append(self._exit_class(ref))
        exit_vec = ",".join(str(c) for c in exit_classes)
        self._set_feature(bitmap, "exit_vec", exit_vec)
        if raw_record is not None:
            raw_record.features.append(("exit_vec", exit_vec))

        # Parse all outputs and pre-normalise URL components
        parsed = [self._parse_url_json(primary_result)]
        for ref in ref_results:
            parsed.append(self._parse_url_json(ref))
        if raw_record is not None:
            raw_record.parsed_outputs = parsed

        # Detect which comparison keys to use (URL vs SAML)
        cmp_keys = _diff_keys_for(parsed[0], parsed[1] if len(parsed) > 1 else None)

        # Precompute normalised component values to avoid repeated
        # str().strip().lower() in the inner loop.
        normalised: list[dict[str, str] | None] = []
        for d in parsed:
            if d is None:
                normalised.append(None)
            else:
                normalised.append({k: str(d.get(k, "")).strip().lower() for k in cmp_keys})

        n = len(ref_results)
        _set = self._set_feature

        # Feature 2: Per-pair divergence signature
        div_count = 0
        p_norm = normalised[0]
        for i in range(n):
            r_norm = normalised[i + 1]
            if p_norm is not None and r_norm is not None:
                diff_keys = sorted(
                    k for k in cmp_keys if p_norm[k] != r_norm[k]
                )
                if diff_keys:
                    # L1+: cdiff hash (sorted key set → single feature)
                    ns_cdiff = f"cdiff_0_{i}"
                    val_cdiff = ",".join(diff_keys)
                    if level >= 1:
                        _set(bitmap, ns_cdiff, val_cdiff)
                    if raw_record is not None:
                        raw_record.features.append((ns_cdiff, val_cdiff))

                    # L2+: per-component individual bits
                    if level >= 2:
                        for k in diff_keys:
                            _set(bitmap, f"comp_0_{i}_{k}", "1")
                    if raw_record is not None:
                        for k in diff_keys:
                            raw_record.features.append((f"comp_0_{i}_{k}", "1"))

                    # L3+: actual differing value hashes
                    if level >= 3 or raw_record is not None:
                        for k in diff_keys:
                            vh = hashlib.sha256(
                                f"{p_norm[k]}|{r_norm[k]}".encode()
                            ).hexdigest()[:8]
                            if level >= 3:
                                _set(bitmap, f"val_0_{i}_{k}", vh)
                            if raw_record is not None:
                                raw_record.features.append((f"val_0_{i}_{k}", vh))

                    div_count += 1

            elif p_norm is None and r_norm is not None:
                ns_pf = f"parse_0_{i}"
                _set(bitmap, ns_pf, "primary_fail")
                if raw_record is not None:
                    raw_record.features.append((ns_pf, "primary_fail"))
                div_count += 1
            elif p_norm is not None and r_norm is None:
                ns_rf = f"parse_0_{i}"
                _set(bitmap, ns_rf, "ref_fail")
                if raw_record is not None:
                    raw_record.features.append((ns_rf, "ref_fail"))
                div_count += 1

            # Exit code divergence
            if exit_classes[0] != exit_classes[i + 1]:
                ns_de = f"div_exit_0_{i}"
                self._set_feature(bitmap, ns_de, "1")
                if raw_record is not None:
                    raw_record.features.append((ns_de, "1"))
                if div_count == 0:
                    div_count += 1

        # Feature 3: Status code vector (L4+ only)
        status_codes = [primary_result.metadata.get("status_code")]
        for ref in ref_results:
            status_codes.append(ref.metadata.get("status_code"))
        if any(s is not None for s in status_codes):
            status_vec = ",".join(str(s or "?") for s in status_codes)
            if level >= 4:
                self._set_feature(bitmap, "status_vec", status_vec)
            if raw_record is not None:
                raw_record.features.append(("status_vec", status_vec))

        # Feature 4: Error pattern divergence (L4+ only)
        p_has_err = bool(primary_result.stderr)
        for i, ref in enumerate(ref_results):
            r_has_err = bool(ref.stderr)
            if p_has_err != r_has_err:
                ns_err = f"div_err_0_{i}"
                if level >= 4:
                    self._set_feature(bitmap, ns_err, "1")
                if raw_record is not None:
                    raw_record.features.append((ns_err, "1"))

        # Feature 6: List-field set divergence (elements_kept, attributes_kept)
        # Provides richer coverage signal for sanitizer targets where
        # boolean comparison_keys saturate quickly.
        p_parsed = parsed[0]
        if p_parsed is not None and "elements_kept" in p_parsed:
            for i in range(n):
                r_parsed_i = parsed[i + 1]
                if r_parsed_i is None or "elements_kept" not in r_parsed_i:
                    continue
                # Element set divergence
                p_elems = frozenset(
                    str(e) for e in p_parsed.get("elements_kept", [])
                )
                r_elems = frozenset(
                    str(e) for e in r_parsed_i.get("elements_kept", [])
                )
                if p_elems != r_elems:
                    elem_sig = hashlib.sha256(
                        f"{sorted(p_elems)}|{sorted(r_elems)}".encode()
                    ).hexdigest()[:8]
                    if level >= 1:
                        _set(bitmap, f"elem_div_0_{i}", elem_sig)
                    if raw_record is not None:
                        raw_record.features.append(
                            (f"elem_div_0_{i}", elem_sig)
                        )
                # Attribute set divergence
                p_attrs = frozenset(
                    str(a) for a in p_parsed.get("attributes_kept", [])
                )
                r_attrs = frozenset(
                    str(a) for a in r_parsed_i.get("attributes_kept", [])
                )
                if p_attrs != r_attrs:
                    attr_sig = hashlib.sha256(
                        f"{sorted(p_attrs)}|{sorted(r_attrs)}".encode()
                    ).hexdigest()[:8]
                    if level >= 1:
                        _set(bitmap, f"attr_div_0_{i}", attr_sig)
                    if raw_record is not None:
                        raw_record.features.append(
                            (f"attr_div_0_{i}", attr_sig)
                        )

        # Feature 5: Divergence count bucket (L0+, granularity varies)
        if level <= 1:
            bucket = "0" if div_count == 0 else "1+"
        elif level <= 3:
            bucket = "0" if div_count == 0 else "1" if div_count == 1 else "2-3" if div_count <= 3 else "4+"
        else:
            bucket = str(min(div_count, 5)) if div_count <= 5 else "5+"
        self._set_feature(bitmap, "div_bucket", bucket)
        if raw_record is not None:
            raw_record.features.append(("div_bucket", bucket))
            raw_record.div_count = div_count

        edge_count = _n_bitmap_count(bitmap) if _NATIVE else sum(1 for b in bitmap if b)
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
