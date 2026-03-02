"""HTML sanitizer differential strategies for cross-library comparison.

Detects exploitable divergences between sanitizer implementations:
  1. Bypass       (CRITICAL) — one allows dangerous pattern, another blocks
  2. Namespace    (HIGH)     — namespace element divergence (mXSS indicator)
  3. Structural   (MEDIUM)   — security-relevant element divergence
  4. DOM Clobbering (MEDIUM) — clobbering vector divergence

Architecture mirrors SamlDiffStrategy — pluggable DiffStrategy
for composition with DiffOracle.

References:
  - mutation-xss.md taxonomy (§1-§8)
  - dompurify.md product security (§1-§7)
  - dom-clobbering.md (§1-§8)
  - IEEE S&P 2024 "Parse Me, Baby, One More Time"
"""

from __future__ import annotations

import json
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_sanitizer_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a sanitizer target.

    Tolerant of partial results: if any security signal key is present
    we accept the output even if ``error`` is set.
    """
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if not isinstance(data, dict):
            return None
        # Accept if any recognised key is present (even with error)
        _KNOWN = {"sanitized", "empty_output", "has_script", "has_event_handler"}
        if any(k in data for k in _KNOWN):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


# ── Primary strategy: Security signal bypass ──────────────────


class SanitizerBypassStrategy:
    """Primary sanitizer differential strategy.

    Detects when one sanitizer allows a dangerous pattern (script tag,
    event handler, javascript: URI, etc.) that another sanitizer blocks.
    This is the highest-impact finding type — directly indicates a
    sanitizer bypass.
    """

    name = "sanitizer_bypass"

    _SIGNAL_MAP: dict[str, tuple[str, Severity]] = {
        "has_script": ("script_bypass", Severity.CRITICAL),
        "has_event_handler": ("event_handler_bypass", Severity.CRITICAL),
        "has_javascript_uri": ("javascript_uri_bypass", Severity.CRITICAL),
        "has_data_uri": ("data_uri_bypass", Severity.HIGH),
        "has_iframe": ("iframe_bypass", Severity.HIGH),
        "has_object_embed": ("object_embed_bypass", Severity.HIGH),
        "has_base": ("base_tag_bypass", Severity.HIGH),
    }

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_sanitizer_output(primary.stdout)
        r = _parse_sanitizer_output(reference.stdout)

        if p is None and r is None:
            return None

        # One-sided parse failure
        if p is None or r is None:
            return self._check_one_sided(inp, primary, reference, ref_index, p, r)

        # Compare security signals — order by severity (CRITICAL first)
        for signal, (category, severity) in self._SIGNAL_MAP.items():
            p_val = p.get(signal, False)
            r_val = r.get(signal, False)
            if p_val != r_val:
                allowing = "primary" if p_val else f"ref[{ref_index}]"
                blocking = f"ref[{ref_index}]" if p_val else "primary"
                return Finding(
                    title=(
                        f"Sanitizer Bypass: {allowing} allows {signal} "
                        f"but {blocking} blocks"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "signal": signal,
                        "allowing_side": allowing,
                        "blocking_side": blocking,
                        "ref_index": ref_index,
                        "primary_sanitized": (p.get("sanitized") or "")[:500],
                        "ref_sanitized": (r.get("sanitized") or "")[:500],
                        "input_preview": _input_preview(inp),
                    },
                )

        return None

    def _check_one_sided(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
        p: dict | None,
        r: dict | None,
    ) -> Finding | None:
        """One target parsed, the other crashed/errored."""
        parsed = p if p is not None else r
        if parsed is None:
            return None

        # Only report if the parsed side has dangerous content
        for signal, (category, severity) in self._SIGNAL_MAP.items():
            if parsed.get(signal, False):
                parsed_side = "primary" if p is not None else f"ref[{ref_index}]"
                failed_side = f"ref[{ref_index}]" if p is not None else "primary"
                return Finding(
                    title=(
                        f"Sanitizer One-Sided: {parsed_side} allows {signal} "
                        f"but {failed_side} crashes"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "signal": signal,
                        "parsed_side": parsed_side,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
        return None


# ── Namespace divergence strategy ─────────────────────────────


_NAMESPACE_ELEMENTS = frozenset({
    "svg", "math", "foreignobject", "annotation-xml",
    "mtext", "mi", "mo", "mn", "ms",
    "mglyph", "malignmark",
})


class SanitizerNamespaceDivergenceStrategy:
    """Detect namespace element divergence between sanitizers.

    When one sanitizer preserves SVG/MathML namespace elements and
    another strips them, this indicates different parser behavior
    for foreign content — a primary mXSS attack surface.
    """

    name = "sanitizer_namespace"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_sanitizer_output(primary.stdout)
        r = _parse_sanitizer_output(reference.stdout)
        if p is None or r is None:
            return None

        p_elems = set(p.get("elements_kept", []))
        r_elems = set(r.get("elements_kept", []))

        p_ns = p_elems & _NAMESPACE_ELEMENTS
        r_ns = r_elems & _NAMESPACE_ELEMENTS

        if p_ns == r_ns:
            return None

        only_primary = p_ns - r_ns
        only_ref = r_ns - p_ns

        allowing = "primary" if only_primary else f"ref[{ref_index}]"
        extra = only_primary if only_primary else only_ref

        return Finding(
            title=(
                f"Namespace Divergence: {allowing} keeps "
                f"{', '.join(sorted(extra))} (ref[{ref_index}])"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "namespace_divergence",
                "primary_ns": sorted(p_ns),
                "ref_ns": sorted(r_ns),
                "only_primary": sorted(only_primary),
                "only_ref": sorted(only_ref),
                "ref_index": ref_index,
                "primary_sanitized": (p.get("sanitized") or "")[:500],
                "ref_sanitized": (r.get("sanitized") or "")[:500],
                "input_preview": _input_preview(inp),
            },
        )


# ── Structural mutation strategy ──────────────────────────────


_SECURITY_RELEVANT_ELEMENTS = frozenset({
    "script", "iframe", "object", "embed", "applet",
    "base", "form", "input", "textarea", "select", "button",
    "style", "link", "meta", "noscript", "template",
    "svg", "math",
})


class SanitizerStructuralMutationStrategy:
    """Detect security-relevant structural differences between sanitizers.

    Compares the set of security-relevant elements kept by each sanitizer.
    Purely cosmetic differences (div vs p, h3 vs h4) are ignored.
    """

    name = "sanitizer_structural"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_sanitizer_output(primary.stdout)
        r = _parse_sanitizer_output(reference.stdout)
        if p is None or r is None:
            return None

        p_elems = set(p.get("elements_kept", []))
        r_elems = set(r.get("elements_kept", []))

        # Only look at security-relevant elements
        p_sec = p_elems & _SECURITY_RELEVANT_ELEMENTS
        r_sec = r_elems & _SECURITY_RELEVANT_ELEMENTS

        if p_sec == r_sec:
            return None

        # Skip namespace elements (handled by namespace strategy)
        diff = (p_sec ^ r_sec) - _NAMESPACE_ELEMENTS
        if not diff:
            return None

        only_primary = (p_sec - r_sec) - _NAMESPACE_ELEMENTS
        only_ref = (r_sec - p_sec) - _NAMESPACE_ELEMENTS

        if not only_primary and not only_ref:
            return None

        allowing = "primary" if only_primary else f"ref[{ref_index}]"
        extra = only_primary if only_primary else only_ref

        return Finding(
            title=(
                f"Structural Divergence: {allowing} keeps "
                f"{', '.join(sorted(extra))} (ref[{ref_index}])"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "structural_mutation",
                "only_primary": sorted(only_primary),
                "only_ref": sorted(only_ref),
                "ref_index": ref_index,
                "primary_sanitized": (p.get("sanitized") or "")[:500],
                "ref_sanitized": (r.get("sanitized") or "")[:500],
                "input_preview": _input_preview(inp),
            },
        )


# ── DOM clobbering strategy ───────────────────────────────────


_CLOBBER_ATTRS = frozenset({"id", "name"})
_CLOBBER_ELEMENTS = frozenset({"a", "form", "input", "img", "embed", "object"})


class SanitizerDomClobberingStrategy:
    """Detect DOM clobbering vector divergence.

    When one sanitizer preserves elements with id/name attributes
    (potential DOM clobbering vectors) and another strips them,
    this indicates different clobbering attack surface.
    """

    name = "sanitizer_clobbering"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_sanitizer_output(primary.stdout)
        r = _parse_sanitizer_output(reference.stdout)
        if p is None or r is None:
            return None

        p_attrs = set(p.get("attributes_kept", []))
        r_attrs = set(r.get("attributes_kept", []))
        p_elems = set(p.get("elements_kept", []))
        r_elems = set(r.get("elements_kept", []))

        p_has_clobber = bool(p_attrs & _CLOBBER_ATTRS) and bool(p_elems & _CLOBBER_ELEMENTS)
        r_has_clobber = bool(r_attrs & _CLOBBER_ATTRS) and bool(r_elems & _CLOBBER_ELEMENTS)

        if p_has_clobber == r_has_clobber:
            return None

        allowing = "primary" if p_has_clobber else f"ref[{ref_index}]"
        return Finding(
            title=(
                f"DOM Clobbering Divergence: {allowing} allows "
                f"clobbering vectors (ref[{ref_index}])"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "dom_clobbering",
                "primary_clobber_attrs": sorted(p_attrs & _CLOBBER_ATTRS),
                "ref_clobber_attrs": sorted(r_attrs & _CLOBBER_ATTRS),
                "primary_clobber_elems": sorted(p_elems & _CLOBBER_ELEMENTS),
                "ref_clobber_elems": sorted(r_elems & _CLOBBER_ELEMENTS),
                "ref_index": ref_index,
                "primary_sanitized": (p.get("sanitized") or "")[:500],
                "ref_sanitized": (r.get("sanitized") or "")[:500],
                "input_preview": _input_preview(inp),
            },
        )


# ── Factory ───────────────────────────────────────────────────


def get_sanitizer_strategies() -> list:
    """Return all sanitizer differential strategies.

    Intended to be composed with DiffOracle's existing strategies.
    Order matters: highest-impact strategies first.
    """
    return [
        SanitizerBypassStrategy(),
        SanitizerNamespaceDivergenceStrategy(),
        SanitizerStructuralMutationStrategy(),
        SanitizerDomClobberingStrategy(),
    ]
