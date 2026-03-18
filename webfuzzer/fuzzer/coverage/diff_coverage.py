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
  6. Element/attribute set divergence for sanitizer targets:
     6a. Element-class divergence (L2+): security-relevant category membership
     6b. Raw element/attribute set divergence (L3+): full set hash

This guides the fuzzer toward inputs that trigger *differential*
behavior — exactly what differential fuzzing needs.
"""

from __future__ import annotations

import hashlib
import json as _json
from typing import TYPE_CHECKING

from ..corpus import MAP_SIZE, CoverageMap
from ..domain import (
    DomainProfile as _DomainProfile,
    all_profiles as _all_profiles,
    compute_danger as _compute_danger,
    get_all_key_sets as _get_all_key_sets,
)
from ..protocols import ExecutionResult, Target, Input

if TYPE_CHECKING:
    from .feature_store import FeatureRecord

# Backward-compat constant (external code may reference this).
_URL_KEYS = ("scheme", "userinfo", "host", "port", "path", "query", "fragment")

# Security-relevant element classes for sanitizer coverage (L2 ecat features).
# Classifying individual elements into categories prevents corpus explosion
# from unique element-set combinations while preserving security-meaningful
# divergence signals.
_ELEMENT_CLASSES: dict[str, frozenset[str]] = {
    "scripting": frozenset({
        "script", "noscript", "template",
    }),
    "namespace": frozenset({
        "svg", "math", "foreignobject", "annotation-xml",
        "desc", "title", "mtext", "mi", "mo", "mn", "mglyph",
    }),
    "dangerous": frozenset({
        "iframe", "object", "embed", "applet", "base", "form",
    }),
    "media": frozenset({
        "img", "video", "audio", "source", "picture", "canvas",
    }),
    "style": frozenset({
        "style", "link",
    }),
    "structural": frozenset({
        "div", "span", "p", "table", "tr", "td", "th",
        "li", "ul", "ol", "dl", "dt", "dd",
    }),
}


def _detect_domain(
    parsed_primary: dict | None, parsed_ref: dict | None,
) -> tuple[tuple[str, ...], _DomainProfile | None]:
    """Identify the domain and return (comparison_keys, matched_profile).

    Strategy:
      1. Check registered domain profiles — pick the one with highest
         overlap ratio between its comparison_keys and the sample output.
      2. Fallback: union of all string-valued keys (no matched profile).
    """
    sample = parsed_primary or parsed_ref
    if sample is None:
        return _URL_KEYS, None

    # Pick the profile with highest overlap ratio.
    best_profile: _DomainProfile | None = None
    best_score = 0.0
    for profile in _all_profiles():
        domain_keys = profile.comparison_keys
        overlap = sum(1 for k in domain_keys if k in sample)
        if overlap == 0:
            continue
        score = overlap / len(domain_keys)
        if score > best_score:
            best_score = score
            best_profile = profile
    if best_profile is not None:
        return best_profile.comparison_keys, best_profile

    # Generic fallback: use all top-level keys present in either output.
    all_keys: set[str] = set()
    for d in (parsed_primary, parsed_ref):
        if d is not None:
            for k, v in d.items():
                if isinstance(v, (str, int, float, bool)):
                    all_keys.add(k)
    if all_keys:
        return tuple(sorted(all_keys)), None
    return _URL_KEYS, None


def _diff_keys_for(parsed_primary: dict | None, parsed_ref: dict | None) -> tuple[str, ...]:
    """Choose comparison keys based on what the output actually contains.

    Thin wrapper around ``_detect_domain`` for backward compatibility.
    """
    return _detect_domain(parsed_primary, parsed_ref)[0]

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
        default_level: int = 2,
    ) -> None:
        self.reference_targets = reference_targets
        self.map_size = map_size
        self.default_level = default_level

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
        level: int | None = None,
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
        if level is None:
            level = self.default_level
        bitmap = bytearray(self.map_size)
        _danger_lvl = 0  # Track max danger level for DangerBooster

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

        # Detect which comparison keys to use (URL vs SAML vs JWT etc.)
        cmp_keys, _matched_profile = _detect_domain(
            parsed[0], parsed[1] if len(parsed) > 1 else None,
        )

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

        # Feature 2.5: SAML signature acceptance vector (L1+)
        # Hashes per-library sig acceptance bitfield to break coverage saturation.
        sig_bits = []
        for d in parsed:
            if d and "signature_valid" in d:
                sig_bits.append("1" if d["signature_valid"] else "0")
        if sig_bits and level >= 1:
            sig_vec = ",".join(sig_bits)
            _set(bitmap, "saml_sig_vec", sig_vec)
            if raw_record is not None:
                raw_record.features.append(("saml_sig_vec", sig_vec))

        # Feature 2.6: JWT per-field semantic coverage (L2+)
        # Instead of treating all JWT output fields equally, create
        # separate features for security-critical fields vs informational ones.
        # This prevents signature_valid divergence from being drowned out
        # by noise in iss/aud formatting differences.
        p_parsed_jwt = parsed[0]
        if p_parsed_jwt is not None and "signature_valid" in p_parsed_jwt:
            # Security-critical fields get individual features per pair
            _jwt_critical = ("signature_valid", "effective_alg", "sub", "role", "scope", "key_source")
            _jwt_temporal = ("time_valid", "exp_state", "nbf_state")
            _jwt_structural = ("nested_jwt", "inner_signature_valid", "crit_processed", "b64_mode", "zip_processed")

            for i in range(n):
                r_parsed_i = parsed[i + 1]
                if r_parsed_i is None or "signature_valid" not in r_parsed_i:
                    continue

                # Critical field divergence → individual bits (L2+)
                for field in _jwt_critical:
                    pv = p_parsed_jwt.get(field)
                    rv = r_parsed_i.get(field)
                    if pv is not None and rv is not None and str(pv).lower() != str(rv).lower():
                        ns = f"jwt_crit_{i}_{field}"
                        if level >= 2:
                            _set(bitmap, ns, f"{pv}|{rv}")
                        if raw_record is not None:
                            raw_record.features.append((ns, f"{pv}|{rv}"))

                # Temporal field divergence → bucketed (L2+)
                for field in _jwt_temporal:
                    pv = p_parsed_jwt.get(field)
                    rv = r_parsed_i.get(field)
                    if pv is not None and rv is not None and pv != rv:
                        ns = f"jwt_time_{i}_{field}"
                        if level >= 2:
                            _set(bitmap, ns, "1")
                        if raw_record is not None:
                            raw_record.features.append((ns, "1"))

                # Structural field divergence → individual bits (L2+)
                for field in _jwt_structural:
                    pv = p_parsed_jwt.get(field)
                    rv = r_parsed_i.get(field)
                    if pv is not None and rv is not None and pv != rv:
                        ns = f"jwt_struct_{i}_{field}"
                        if level >= 2:
                            _set(bitmap, ns, "1")
                        if raw_record is not None:
                            raw_record.features.append((ns, "1"))

                # Claim type divergence vector (L3+)
                p_ctypes = p_parsed_jwt.get("claim_types", {})
                r_ctypes = r_parsed_i.get("claim_types", {})
                if isinstance(p_ctypes, dict) and isinstance(r_ctypes, dict):
                    ctype_diff = []
                    for ck in ("sub", "role", "scope", "exp", "aud"):
                        pt = str(p_ctypes.get(ck, "")).lower()
                        rt = str(r_ctypes.get(ck, "")).lower()
                        if pt and rt and pt != rt:
                            ctype_diff.append(f"{ck}:{pt}>{rt}")
                    if ctype_diff and level >= 3:
                        _set(bitmap, f"jwt_ctype_{i}", ",".join(ctype_diff))
                        if raw_record is not None:
                            raw_record.features.append((f"jwt_ctype_{i}", ",".join(ctype_diff)))

        # Feature 2.7: Apache confusion phase trace (L2+)
        # Per-phase request_rec hashes provide gradient toward confusion.
        # Cross-phase pairs (access_check vs handler) detect intra-target
        # confusion — the core signal for Apache module interaction bugs.
        _apache_phase_fields = (
            "uri_at_translate", "uri_at_access_check",
            "uri_at_fixup", "uri_at_handler",
            "filename_at_access_check", "filename_at_handler",
            "handler_at_access_check", "handler_at_handler",
        )
        p_parsed_ac = parsed[0]
        if p_parsed_ac is not None and "uri_at_translate" in p_parsed_ac:
            # Per-phase value hashes (single-target features)
            for field in _apache_phase_fields:
                val = str(p_parsed_ac.get(field, "")).strip()
                if val:
                    ns = f"phase_{field}"
                    if level >= 2:
                        _set(bitmap, ns, val)
                    if raw_record is not None:
                        raw_record.features.append((ns, val))

            # Cross-phase confusion pairs (the gradient signal)
            uri_ac = str(p_parsed_ac.get("uri_at_access_check", ""))
            uri_h = str(p_parsed_ac.get("uri_at_handler", ""))
            if uri_ac and uri_h and uri_ac != uri_h:
                sig = f"{uri_ac}|{uri_h}"
                if level >= 2:
                    _set(bitmap, "uri_confusion", sig)
                if raw_record is not None:
                    raw_record.features.append(("uri_confusion", sig))

            fn_ac = str(p_parsed_ac.get("filename_at_access_check", ""))
            fn_h = str(p_parsed_ac.get("filename_at_handler", ""))
            if fn_ac and fn_h and fn_ac != fn_h:
                sig = f"{fn_ac}|{fn_h}"
                if level >= 2:
                    _set(bitmap, "fn_confusion", sig)
                if raw_record is not None:
                    raw_record.features.append(("fn_confusion", sig))

            handler_ac = str(p_parsed_ac.get("handler_at_access_check", ""))
            handler_h = str(p_parsed_ac.get("handler_at_handler", ""))
            if handler_ac and handler_h and handler_ac != handler_h:
                sig = f"{handler_ac}|{handler_h}"
                if level >= 2:
                    _set(bitmap, "handler_confusion", sig)
                if raw_record is not None:
                    raw_record.features.append(("handler_confusion", sig))

            # Status code as coverage feature (L1+)
            sc = p_parsed_ac.get("status_code")
            if sc is not None:
                sc_bucket = str(sc // 100)  # 2xx→"2", 4xx→"4"
                if level >= 1:
                    _set(bitmap, "phase_status", sc_bucket)
                if raw_record is not None:
                    raw_record.features.append(("phase_status", sc_bucket))

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
        #
        # Two tiers:
        #   L2 — ecat (element-class divergence): groups elements into
        #         security-relevant categories, yielding ~6 stable bits
        #         per pair instead of a unique hash per element set.
        #   L3 — elem_div / attr_div (raw set hash): full SHA256 of the
        #         exact element/attribute sets for maximum resolution.
        p_parsed = parsed[0]
        if p_parsed is not None and "elements_kept" in p_parsed:
            for i in range(n):
                r_parsed_i = parsed[i + 1]
                if r_parsed_i is None or "elements_kept" not in r_parsed_i:
                    continue
                # Build element sets (shared by both tiers)
                p_elems = frozenset(
                    str(e).lower() for e in p_parsed.get("elements_kept", [])
                )
                r_elems = frozenset(
                    str(e).lower() for e in r_parsed_i.get("elements_kept", [])
                )

                # ── Feature 6a: Element-class divergence (L2+) ──
                # Hash per security category: does one sanitizer keep
                # elements in this class while the other strips them?
                if p_elems != r_elems:
                    for cat_name, cat_elems in _ELEMENT_CLASSES.items():
                        p_has = bool(p_elems & cat_elems)
                        r_has = bool(r_elems & cat_elems)
                        if p_has != r_has:
                            ns_ecat = f"ecat_0_{i}_{cat_name}"
                            val_ecat = f"{p_has}|{r_has}"
                            if level >= 2:
                                _set(bitmap, ns_ecat, val_ecat)
                            if raw_record is not None:
                                raw_record.features.append((ns_ecat, val_ecat))

                # ── Feature 6b: Raw element set divergence (L3+) ──
                if p_elems != r_elems:
                    elem_sig = hashlib.sha256(
                        f"{sorted(p_elems)}|{sorted(r_elems)}".encode()
                    ).hexdigest()[:8]
                    if level >= 3:
                        _set(bitmap, f"elem_div_0_{i}", elem_sig)
                    if raw_record is not None:
                        raw_record.features.append(
                            (f"elem_div_0_{i}", elem_sig)
                        )
                # ── Feature 6c: Raw attribute set divergence (L3+) ──
                p_attrs = frozenset(
                    str(a).lower() for a in p_parsed.get("attributes_kept", [])
                )
                r_attrs = frozenset(
                    str(a).lower() for a in r_parsed_i.get("attributes_kept", [])
                )
                if p_attrs != r_attrs:
                    attr_sig = hashlib.sha256(
                        f"{sorted(p_attrs)}|{sorted(r_attrs)}".encode()
                    ).hexdigest()[:8]
                    if level >= 3:
                        _set(bitmap, f"attr_div_0_{i}", attr_sig)
                    if raw_record is not None:
                        raw_record.features.append(
                            (f"attr_div_0_{i}", attr_sig)
                        )

        # Feature 7: Namespace transition divergence (L2+)
        # Tracks per-pair differences in namespace transition count and
        # max DOM depth — inputs that cause different namespace handling
        # across sanitizers are mXSS-relevant.
        if p_parsed is not None and "ns_transitions" in p_parsed:
            for i in range(n):
                r_parsed_i = parsed[i + 1]
                if r_parsed_i is None or "ns_transitions" not in r_parsed_i:
                    continue
                p_nst = p_parsed.get("ns_transitions", 0)
                r_nst = r_parsed_i.get("ns_transitions", 0)
                if p_nst != r_nst:
                    # Bucket: 0, 1, 2, 3+
                    p_b = str(min(p_nst, 3)) if p_nst <= 3 else "3+"
                    r_b = str(min(r_nst, 3)) if r_nst <= 3 else "3+"
                    ns_nst = f"nst_0_{i}"
                    val_nst = f"{p_b}|{r_b}"
                    if level >= 2:
                        _set(bitmap, ns_nst, val_nst)
                    if raw_record is not None:
                        raw_record.features.append((ns_nst, val_nst))

                p_depth = p_parsed.get("max_depth", 0)
                r_depth = r_parsed_i.get("max_depth", 0)
                if p_depth != r_depth:
                    # Bucket: 0, 1-3, 4-7, 8+
                    def _depth_bucket(d):
                        if d == 0: return "0"
                        if d <= 3: return "1-3"
                        if d <= 7: return "4-7"
                        return "8+"
                    ns_dep = f"depth_0_{i}"
                    val_dep = f"{_depth_bucket(p_depth)}|{_depth_bucket(r_depth)}"
                    if level >= 2:
                        _set(bitmap, ns_dep, val_dep)
                    if raw_record is not None:
                        raw_record.features.append((ns_dep, val_dep))

        # Feature 8: Progressive danger signals (single-target, L1+)
        # Encodes security-relevant milestones from sanitizer output,
        # providing gradient reward toward exploit-capable inputs.
        # Key insight: reward based on REPARSED output danger, not just
        # sanitized output — benign entity diffs don't generate reward.
        if p_parsed is not None:
            # ── Survived element categories (sanitized output) ──
            p_elems = frozenset(
                str(e).lower() for e in p_parsed.get("elements_kept", [])
            )
            for cat_name, cat_elems in _ELEMENT_CLASSES.items():
                if p_elems & cat_elems:
                    ns_surv = f"surv_{cat_name}"
                    if level >= 1:
                        _set(bitmap, ns_surv, "1")
                    if raw_record is not None:
                        raw_record.features.append((ns_surv, "1"))

            # ── Security signal vector (sanitized) ──
            sig_fields = [
                "has_script", "has_event_handler", "has_javascript_uri",
                "has_data_uri", "has_svg", "has_math", "has_style",
                "has_iframe", "has_object_embed", "has_noscript",
            ]
            sig_vec = ""
            for f in sig_fields:
                sig_vec += "1" if p_parsed.get(f) else "0"
            if level >= 2:
                _set(bitmap, "sig_vec", sig_vec)
            if raw_record is not None:
                raw_record.features.append(("sig_vec", sig_vec))

            # ── Reparsed security signal vector ──
            r_sig_fields = [
                "r_has_script", "r_has_event_handler", "r_has_javascript_uri",
                "r_has_data_uri", "r_has_svg", "r_has_math", "r_has_style",
                "r_has_iframe", "r_has_noscript",
            ]
            r_sig_vec = ""
            for f in r_sig_fields:
                r_sig_vec += "1" if p_parsed.get(f) else "0"
            if level >= 2:
                _set(bitmap, "r_sig_vec", r_sig_vec)
            if raw_record is not None:
                raw_record.features.append(("r_sig_vec", r_sig_vec))

            # ── Danger level (based on REPARSED output, not sanitized) ──
            danger = 0
            if not p_parsed.get("empty_output"):
                danger = 1  # something survived sanitization
            if p_elems & _ELEMENT_CLASSES.get("namespace", frozenset()):
                danger = max(danger, 2)  # namespace element in sanitized
            # Security-relevant mXSS: new elements/signals after reparse
            if p_parsed.get("mxss_security"):
                danger = max(danger, 3)  # structural mXSS (not benign entity diff)
            if p_parsed.get("browser_mxss"):
                danger = max(danger, 4)  # browser confirmed differential
            # Danger in REPARSED output (the actual attack surface)
            if p_parsed.get("r_has_event_handler") or p_parsed.get("r_has_javascript_uri"):
                danger = max(danger, 5)  # dangerous pattern after reparse
            if p_parsed.get("danger_escalation"):
                danger = max(danger, 6)  # THE GOAL: sanitizer bypassed

            _danger_lvl = danger  # Surface for DangerBooster

            if level >= 1:
                _set(bitmap, "danger_lvl", str(danger))
            if raw_record is not None:
                raw_record.features.append(("danger_lvl", str(danger)))

            # ── Near-miss signals (L2+): guide toward dangerous variations ──
            near_miss_fields = [
                "near_miss_img", "near_miss_a_href", "near_miss_style",
                "near_miss_form", "near_miss_svg", "near_miss_math",
            ]
            for nm in near_miss_fields:
                if p_parsed.get(nm):
                    if level >= 2:
                        _set(bitmap, nm, "1")
                    if raw_record is not None:
                        raw_record.features.append((nm, "1"))

            # ── New elements after reparse (L2+) ──
            new_elems = p_parsed.get("new_elements_after_reparse", [])
            if new_elems:
                ne_sig = ",".join(sorted(str(e) for e in new_elems[:5]))
                if level >= 2:
                    _set(bitmap, "new_elems", ne_sig)
                if raw_record is not None:
                    raw_record.features.append(("new_elems", ne_sig))

            # ── Danger escalation flag (L1+, highest priority) ──
            if p_parsed.get("danger_escalation"):
                if level >= 1:
                    _set(bitmap, "escalation", "1")
                if raw_record is not None:
                    raw_record.features.append(("escalation", "1"))

            # ── Cross-product: danger × categories (L2+) ──
            if danger >= 2 and level >= 2:
                for cat_name, cat_elems in _ELEMENT_CLASSES.items():
                    if p_elems & cat_elems:
                        ns_dc = f"dcat_{cat_name}"
                        val_dc = str(danger)
                        _set(bitmap, ns_dc, val_dc)
                        if raw_record is not None:
                            raw_record.features.append((ns_dc, val_dc))

            # ── Namespace transitions (single-target, L2+) ──
            nst = p_parsed.get("ns_transitions", 0)
            if nst > 0:
                nst_b = "1" if nst == 1 else "2" if nst == 2 else "3+"
                if level >= 2:
                    _set(bitmap, "p_nst", nst_b)
                if raw_record is not None:
                    raw_record.features.append(("p_nst", nst_b))

            # ── Max depth bucket (single-target, L2+) ──
            depth = p_parsed.get("max_depth", 0)
            if depth > 0:
                d_b = "1-3" if depth <= 3 else "4-7" if depth <= 7 else "8-15" if depth <= 15 else "16+"
                if level >= 2:
                    _set(bitmap, "p_depth", d_b)
                if raw_record is not None:
                    raw_record.features.append(("p_depth", d_b))

        # ── Generic danger ladder fallback (non-sanitizer domains) ──
        # If the mXSS-specific block above didn't set a danger level,
        # evaluate the matched domain's declarative danger ladder.
        if _danger_lvl == 0 and _matched_profile is not None and _matched_profile.danger_ladder:
            _danger_lvl = _compute_danger(p_parsed, _matched_profile.danger_ladder)
            if _danger_lvl > 0:
                if level >= 1:
                    _set(bitmap, "danger_lvl", str(_danger_lvl))
                if raw_record is not None:
                    raw_record.features.append(("danger_lvl", str(_danger_lvl)))

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

        # Feature 9: Concolic constraint features (L3+)
        # Hash extracted constraints into the bitmap so inputs triggering
        # novel constraint patterns count as coverage-novel.
        if level >= 3 and hasattr(inp, 'metadata'):
            for cstr in (inp.metadata.get("constraints") or []):
                if isinstance(cstr, dict):
                    cstr_key = f"{cstr.get('domain','')}:{cstr.get('predicate','')}:{cstr.get('pair','')}"
                    _set(bitmap, "cstr", cstr_key)
                    if raw_record is not None:
                        raw_record.features.append(("cstr", cstr_key))

        edge_count = _n_bitmap_count(bitmap) if _NATIVE else sum(1 for b in bitmap if b)
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
        """Try to parse URL parser JSON output.  Uses cached parsed_json()."""
        return result.parsed_json()

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
