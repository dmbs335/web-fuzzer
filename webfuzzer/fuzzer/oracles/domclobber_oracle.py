"""DOM Clobbering oracle — single-target detection of clobbering vectors.

Works with the domclobber target which outputs JSON:

    {
        "clobber_count": 3,
        "clobber_chain_depth": 2,
        "clobber_has_anchor_href": true,
        "clobber_has_form_children": true,
        "clobber_dangerous_targets": ["currentScript", "location"],
        "clobber_builtins_shadowed": ["getElementById"],
        "clobber_ids": ["config", "settings"],
        "clobber_names": ["currentScript"],
        "sanitize_dom_active": false,
        "sanitize_named_props_active": false,
        "divergence_count": 0,
    }

Detection priority:
  1. CRITICAL: dangerous targets + anchor href (direct exploitation)
  2. HIGH: form children + chain depth >= 2 (property chain access)
  3. HIGH: dangerous targets without anchor (potential exploitation)
  4. HIGH: browser divergence (cross-browser inconsistency)
  5. MEDIUM: builtins shadowed (document/window property pollution)
  6. LOW: any clobbering vectors detected
"""

from __future__ import annotations

import hashlib
import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_clobber_output(result: ExecutionResult) -> dict | None:
    """Parse JSON output from a domclobber target."""
    data = result.parsed_json()
    if data is None:
        return None
    # Accept if any clobbering key is present
    _KNOWN = {"clobber_count", "clobber_chain_depth", "clobber_has_anchor_href",
              "clobber_dangerous_targets", "clobber_builtins_shadowed"}
    if any(k in data for k in _KNOWN):
        return data
    return None


def _fingerprint(*parts: str) -> str:
    """Create a stable fingerprint from string parts."""
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


class DomClobberOracle:
    """DOM Clobbering detection oracle for single-target analysis.

    Parses JSON output from the domclobber target and reports findings
    based on detected clobbering vectors, chain depth, and dangerous
    target properties.
    """

    name = "domclobber"

    DANGEROUS_TARGETS = frozenset({
        "currentScript", "location", "cookie", "domain", "referrer",
        "defaultView", "body", "head", "getElementById", "querySelector",
        "CLOSURE_BASE_PATH", "AMP_MODE", "__webpack_public_path__",
        "__webpack_nonce__", "__webpack_require__",
    })

    FRAMEWORK_TARGETS = frozenset({
        "CLOSURE_BASE_PATH", "AMP_MODE", "__webpack_public_path__",
        "__webpack_nonce__", "__webpack_require__", "analytics", "ga",
        "_gaq", "dataLayer",
    })

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        """Check domclobber target JSON output for clobbering indicators."""
        data = _parse_clobber_output(result)
        if data is None:
            return None

        clobber_count = data.get("clobber_count", 0)
        chain_depth = data.get("clobber_chain_depth", 0)
        has_anchor_href = data.get("clobber_has_anchor_href", False)
        dangerous_targets = data.get("clobber_dangerous_targets", [])
        builtins_shadowed = data.get("clobber_builtins_shadowed", [])
        clobber_ids = data.get("clobber_ids", [])
        clobber_names = data.get("clobber_names", [])
        has_form_children = data.get("clobber_has_form_children", False)
        divergence_count = data.get("divergence_count", 0)

        # Nothing to report if no clobbering and no divergence
        if not clobber_count and not divergence_count:
            return None

        inp_preview = inp.data[:300].decode("utf-8", errors="replace")
        sorted_dangerous = sorted(dangerous_targets) if dangerous_targets else ["none"]

        # Priority 1: CRITICAL — dangerous targets + anchor href
        if dangerous_targets and has_anchor_href:
            return Finding(
                title=(
                    f"DOM Clobbering: dangerous target "
                    f"'{dangerous_targets[0]}' with anchor href"
                ),
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=_fingerprint(
                    "critical", "dangerous_anchor",
                    "|".join(sorted_dangerous), "true",
                ),
                metadata={
                    "category": "dangerous_anchor",
                    "clobber_count": clobber_count,
                    "chain_depth": chain_depth,
                    "has_anchor_href": has_anchor_href,
                    "dangerous_targets": dangerous_targets,
                    "builtins_shadowed": builtins_shadowed,
                    "clobber_ids": clobber_ids[:20],
                    "clobber_names": clobber_names[:20],
                    "input_preview": inp_preview,
                },
            )

        # Priority 2: HIGH — form children + chain depth >= 2
        if has_form_children and chain_depth >= 2:
            return Finding(
                title=(
                    f"DOM Clobbering: form child chain depth {chain_depth}"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=_fingerprint(
                    "high", "form_chain",
                    "|".join(sorted_dangerous), str(has_anchor_href),
                ),
                metadata={
                    "category": "form_chain",
                    "clobber_count": clobber_count,
                    "chain_depth": chain_depth,
                    "has_anchor_href": has_anchor_href,
                    "has_form_children": has_form_children,
                    "dangerous_targets": dangerous_targets,
                    "clobber_ids": clobber_ids[:20],
                    "clobber_names": clobber_names[:20],
                    "input_preview": inp_preview,
                },
            )

        # Priority 3: HIGH — dangerous targets without anchor
        if dangerous_targets:
            return Finding(
                title=(
                    f"DOM Clobbering: dangerous target "
                    f"'{dangerous_targets[0]}' clobbered"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=_fingerprint(
                    "high", "dangerous_target",
                    "|".join(sorted_dangerous), "false",
                ),
                metadata={
                    "category": "dangerous_target",
                    "clobber_count": clobber_count,
                    "chain_depth": chain_depth,
                    "has_anchor_href": has_anchor_href,
                    "dangerous_targets": dangerous_targets,
                    "clobber_ids": clobber_ids[:20],
                    "clobber_names": clobber_names[:20],
                    "input_preview": inp_preview,
                },
            )

        # Priority 4: HIGH — browser divergence (cross-browser inconsistency)
        if divergence_count > 0:
            return Finding(
                title=(
                    f"DOM Clobbering: {divergence_count} cross-browser divergences"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=_fingerprint(
                    "high", "browser_divergence",
                    str(divergence_count), str(has_anchor_href),
                ),
                metadata={
                    "category": "browser_divergence",
                    "divergence_count": divergence_count,
                    "clobber_count": clobber_count,
                    "chain_depth": chain_depth,
                    "has_anchor_href": has_anchor_href,
                    "clobber_ids": clobber_ids[:20],
                    "clobber_names": clobber_names[:20],
                    "input_preview": inp_preview,
                },
            )

        # Priority 5: MEDIUM — builtins shadowed
        if builtins_shadowed:
            return Finding(
                title=(
                    f"DOM Clobbering: builtin '{builtins_shadowed[0]}' shadowed"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=_fingerprint(
                    "medium", "builtin_shadow",
                    "|".join(sorted(builtins_shadowed)), str(has_anchor_href),
                ),
                metadata={
                    "category": "builtin_shadow",
                    "clobber_count": clobber_count,
                    "chain_depth": chain_depth,
                    "builtins_shadowed": builtins_shadowed,
                    "clobber_ids": clobber_ids[:20],
                    "clobber_names": clobber_names[:20],
                    "input_preview": inp_preview,
                },
            )

        # Priority 6: LOW — any clobbering vectors
        if clobber_count > 0:
            return Finding(
                title=f"DOM Clobbering: {clobber_count} vector(s) detected",
                severity=Severity.LOW,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=_fingerprint(
                    "low", "basic_clobber", "none", str(has_anchor_href),
                ),
                metadata={
                    "category": "basic_clobber",
                    "clobber_count": clobber_count,
                    "chain_depth": chain_depth,
                    "clobber_ids": clobber_ids[:20],
                    "clobber_names": clobber_names[:20],
                    "input_preview": inp_preview,
                },
            )

        return None
