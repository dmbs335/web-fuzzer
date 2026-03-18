"""DOM Clobbering differential strategies for cross-target comparison.

Detects exploitable divergences in how different sanitizers handle
DOM clobbering vectors:
  1. ClobberVectorDivergence  (HIGH/MEDIUM) — one has vectors the other blocks
  2. ClobberChainDepth        (HIGH)        — chain depth differs
  3. ClobberAnchorHref        (CRITICAL)    — one allows anchor+href, other strips
  4. ClobberBuiltinShadow     (HIGH)        — builtin property shadow divergence
  5. ClobberDefense           (MEDIUM)      — defense feature divergence

Architecture mirrors SanitizerDiffStrategy — pluggable strategies
for composition with DiffOracle.

References:
  - dom-clobbering.md taxonomy (sections 1-8)
  - Khodayari & Pellegrino "It's (DOM) Clobbering Time" (CCS 2023)
  - DOMPurify sanitize-dom / sanitize-named-props defenses
"""

from __future__ import annotations

import hashlib

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_json(result: ExecutionResult) -> dict | None:
    """Parse JSON output from a domclobber target via cached parser."""
    return result.parsed_json()


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


def _fingerprint(*parts: str) -> str:
    """Create a stable fingerprint from string parts."""
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _target_name_class(targets: list) -> str:
    """Normalize clobbering target names into security buckets."""
    _BUILTIN = frozenset({
        "cookie", "domain", "referrer", "location", "URL",
        "body", "head", "forms", "images", "links",
        "getElementById", "querySelector", "title", "currentScript",
        "defaultView",
    })
    _FRAMEWORK = frozenset({
        "CLOSURE_BASE_PATH", "AMP_MODE", "__webpack_public_path__",
        "__webpack_nonce__", "__webpack_require__", "analytics", "ga",
        "_gaq", "dataLayer",
    })
    for t in targets:
        if t in _FRAMEWORK:
            return "_framework_"
        if t in _BUILTIN:
            return "_builtin_"
    return "_custom_"


# ── Strategy 1: Clobber vector divergence ────────────────────────


class ClobberVectorDivergenceStrategy:
    """Compare clobber_count, clobber_ids, clobber_names.

    Finding if one target has clobbering vectors the other does not.
    """

    name = "clobber_vector"

    _DANGEROUS = frozenset({
        "currentScript", "location", "cookie", "domain", "referrer",
        "defaultView", "body", "head", "getElementById", "querySelector",
        "CLOSURE_BASE_PATH", "AMP_MODE", "__webpack_public_path__",
        "__webpack_nonce__",
    })

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_json(primary)
        r = _parse_json(reference)
        if p is None or r is None:
            return None

        p_ids = set(p.get("clobber_ids", []))
        r_ids = set(r.get("clobber_ids", []))
        p_names = set(p.get("clobber_names", []))
        r_names = set(r.get("clobber_names", []))

        p_all = p_ids | p_names
        r_all = r_ids | r_names

        if p_all == r_all:
            return None

        only_primary = p_all - r_all
        only_ref = r_all - p_all
        all_divergent = only_primary | only_ref

        # Check if any divergent target is dangerous
        has_dangerous = bool(all_divergent & self._DANGEROUS)
        severity = Severity.HIGH if has_dangerous else Severity.MEDIUM

        allowing = "primary" if only_primary else f"ref[{ref_index}]"
        blocking = f"ref[{ref_index}]" if only_primary else "primary"
        extra = only_primary if only_primary else only_ref
        nc = _target_name_class(sorted(all_divergent))

        return Finding(
            title=(
                f"DOM Clobbering Divergence: {allowing} allows "
                f"{', '.join(sorted(extra)[:5])} (vs {blocking})"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            fingerprint=_fingerprint(self.name, "vector_div", allowing, nc),
            metadata={
                "strategy": self.name,
                "category": "clobber_vector_divergence",
                "accepting_side": allowing,
                "blocking_side": blocking,
                "ref_index": ref_index,
                "target_name_class": nc,
                "only_primary": sorted(only_primary),
                "only_ref": sorted(only_ref),
                "primary_ids": sorted(p_ids)[:20],
                "ref_ids": sorted(r_ids)[:20],
                "input_preview": _input_preview(inp),
            },
        )


# ── Strategy 2: Chain depth divergence ───────────────────────────


class ClobberChainDepthStrategy:
    """Compare clobber_chain_depth across targets.

    Finding if one target allows deeper property chain access.
    """

    name = "clobber_chain_depth"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_json(primary)
        r = _parse_json(reference)
        if p is None or r is None:
            return None

        p_depth = p.get("clobber_chain_depth", 0)
        r_depth = r.get("clobber_chain_depth", 0)

        if p_depth == r_depth:
            return None

        deeper_side = "primary" if p_depth > r_depth else f"ref[{ref_index}]"
        shallower_side = f"ref[{ref_index}]" if p_depth > r_depth else "primary"
        max_depth = max(p_depth, r_depth)

        # Collect target names for name_class
        all_targets = (
            list(p.get("clobber_ids", []))
            + list(r.get("clobber_ids", []))
        )
        nc = _target_name_class(all_targets)

        return Finding(
            title=(
                f"DOM Clobbering Chain Depth: {deeper_side} depth={max_depth} "
                f"vs {shallower_side} depth={min(p_depth, r_depth)}"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            fingerprint=_fingerprint(self.name, "depth_div", deeper_side, nc),
            metadata={
                "strategy": self.name,
                "category": "clobber_chain_depth",
                "accepting_side": deeper_side,
                "blocking_side": shallower_side,
                "ref_index": ref_index,
                "target_name_class": nc,
                "primary_depth": p_depth,
                "ref_depth": r_depth,
                "input_preview": _input_preview(inp),
            },
        )


# ── Strategy 3: Anchor href divergence ──────────────────────────


class ClobberAnchorHrefStrategy:
    """Compare clobber_has_anchor_href across targets.

    CRITICAL if one allows anchor+href (the key toString exploitation
    primitive), other strips it.
    """

    name = "clobber_anchor_href"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_json(primary)
        r = _parse_json(reference)
        if p is None or r is None:
            return None

        p_href = p.get("clobber_has_anchor_href", False)
        r_href = r.get("clobber_has_anchor_href", False)

        if p_href == r_href:
            return None

        allowing = "primary" if p_href else f"ref[{ref_index}]"
        blocking = f"ref[{ref_index}]" if p_href else "primary"

        all_targets = (
            list(p.get("clobber_ids", []))
            + list(r.get("clobber_ids", []))
        )
        nc = _target_name_class(all_targets)

        return Finding(
            title=(
                f"DOM Clobbering Anchor Href: {allowing} allows "
                f"anchor+href but {blocking} strips"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            fingerprint=_fingerprint(self.name, "anchor_href", allowing, nc),
            metadata={
                "strategy": self.name,
                "category": "clobber_anchor_href",
                "accepting_side": allowing,
                "blocking_side": blocking,
                "ref_index": ref_index,
                "target_name_class": nc,
                "primary_has_href": p_href,
                "ref_has_href": r_href,
                "primary_ids": sorted(p.get("clobber_ids", []))[:20],
                "ref_ids": sorted(r.get("clobber_ids", []))[:20],
                "input_preview": _input_preview(inp),
            },
        )


# ── Strategy 4: Builtin shadow divergence ───────────────────────


class ClobberBuiltinShadowStrategy:
    """Compare clobber_builtins_shadowed lists across targets.

    Identify which builtins diverge between implementations.
    """

    name = "clobber_builtin_shadow"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_json(primary)
        r = _parse_json(reference)
        if p is None or r is None:
            return None

        p_builtins = set(p.get("clobber_builtins_shadowed", []))
        r_builtins = set(r.get("clobber_builtins_shadowed", []))

        if p_builtins == r_builtins:
            return None

        only_primary = p_builtins - r_builtins
        only_ref = r_builtins - p_builtins
        all_divergent = only_primary | only_ref

        allowing = "primary" if only_primary else f"ref[{ref_index}]"
        blocking = f"ref[{ref_index}]" if only_primary else "primary"
        extra = only_primary if only_primary else only_ref
        nc = _target_name_class(sorted(all_divergent))

        return Finding(
            title=(
                f"DOM Clobbering Builtin Shadow: {allowing} shadows "
                f"{', '.join(sorted(extra)[:5])} (vs {blocking})"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            fingerprint=_fingerprint(self.name, "builtin_shadow", allowing, nc),
            metadata={
                "strategy": self.name,
                "category": "clobber_builtin_shadow",
                "accepting_side": allowing,
                "blocking_side": blocking,
                "ref_index": ref_index,
                "target_name_class": nc,
                "only_primary": sorted(only_primary),
                "only_ref": sorted(only_ref),
                "primary_builtins": sorted(p_builtins),
                "ref_builtins": sorted(r_builtins),
                "input_preview": _input_preview(inp),
            },
        )


# ── Strategy 5: Defense feature divergence ──────────────────────


class ClobberDefenseStrategy:
    """Compare sanitize_dom_active and sanitize_named_props_active.

    Report if one target has a clobbering defense the other lacks.
    """

    name = "clobber_defense"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_json(primary)
        r = _parse_json(reference)
        if p is None or r is None:
            return None

        p_dom = p.get("sanitize_dom_active", False)
        r_dom = r.get("sanitize_dom_active", False)
        p_named = p.get("sanitize_named_props_active", False)
        r_named = r.get("sanitize_named_props_active", False)

        defenses_differ = (p_dom != r_dom) or (p_named != r_named)
        if not defenses_differ:
            return None

        # Determine which side has more defense
        p_score = int(p_dom) + int(p_named)
        r_score = int(r_dom) + int(r_named)

        if p_score == r_score:
            # Different defenses but same count — still worth reporting
            accepting = "primary"
            blocking = f"ref[{ref_index}]"
        elif p_score > r_score:
            accepting = f"ref[{ref_index}]"  # ref lacks defense
            blocking = "primary"
        else:
            accepting = "primary"  # primary lacks defense
            blocking = f"ref[{ref_index}]"

        all_targets = (
            list(p.get("clobber_ids", []))
            + list(r.get("clobber_ids", []))
        )
        nc = _target_name_class(all_targets)

        differences = []
        if p_dom != r_dom:
            differences.append("sanitize_dom")
        if p_named != r_named:
            differences.append("sanitize_named_props")

        return Finding(
            title=(
                f"DOM Clobbering Defense Gap: {accepting} lacks "
                f"{', '.join(differences)} (vs {blocking})"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            fingerprint=_fingerprint(self.name, "defense_gap", accepting, nc),
            metadata={
                "strategy": self.name,
                "category": "clobber_defense_gap",
                "accepting_side": accepting,
                "blocking_side": blocking,
                "ref_index": ref_index,
                "target_name_class": nc,
                "primary_dom_defense": p_dom,
                "ref_dom_defense": r_dom,
                "primary_named_defense": p_named,
                "ref_named_defense": r_named,
                "defense_differences": differences,
                "input_preview": _input_preview(inp),
            },
        )


# ── Factory ──────────────────────────────────────────────────────


def get_domclobber_strategies() -> list:
    """Return all DOM clobbering differential strategies.

    Intended to be composed with DiffOracle's existing strategies.
    Order matters: highest-impact strategies first.
    """
    return [
        ClobberVectorDivergenceStrategy(),
        ClobberChainDepthStrategy(),
        ClobberAnchorHrefStrategy(),
        ClobberBuiltinShadowStrategy(),
        ClobberDefenseStrategy(),
    ]
