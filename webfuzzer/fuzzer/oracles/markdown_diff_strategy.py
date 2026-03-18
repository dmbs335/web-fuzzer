"""Markdown renderer differential strategies for cross-library comparison.

Detects exploitable divergences between Markdown renderer implementations:
  1. XSS Injection  (CRITICAL/HIGH) — one renders dangerous HTML, another blocks
  2. Link Injection  (HIGH)         — javascript:/data: URIs in links
  3. Raw HTML        (MEDIUM)       — raw HTML block preservation divergence
  4. Autolink        (MEDIUM)       — autolink detection divergence

Architecture mirrors SanitizerDiffStrategy — pluggable DiffStrategy
for composition with DiffOracle.
"""

from __future__ import annotations

import json
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_markdown_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a Markdown renderer target.

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
        _KNOWN = {"html", "empty_output", "has_script", "has_event_handler",
                   "has_javascript_uri", "has_data_uri", "has_iframe",
                   "has_raw_html", "autolinks_found", "link_hrefs"}
        if any(k in data for k in _KNOWN):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


# -- Primary strategy: XSS injection signals -------------------------


class MarkdownXssInjectionStrategy:
    """Primary Markdown differential strategy.

    Detects when one renderer produces dangerous HTML (script tag,
    event handler, javascript: URI, etc.) that another renderer blocks
    or escapes.  Directly indicates a Markdown-to-XSS injection path.
    """

    name = "markdown_xss_injection"

    _SIGNAL_MAP: dict[str, tuple[str, Severity]] = {
        "has_script": ("xss_script_injection", Severity.CRITICAL),
        "has_event_handler": ("xss_event_handler", Severity.CRITICAL),
        "has_javascript_uri": ("javascript_uri_injection", Severity.CRITICAL),
        "has_data_uri": ("data_uri_injection", Severity.HIGH),
        "has_iframe": ("xss_html_injection", Severity.HIGH),
    }

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)

        if p is None and r is None:
            return None

        # One-sided parse failure
        if p is None or r is None:
            return self._check_one_sided(inp, primary, reference, ref_index, p, r)

        # Compare security signals -- order by severity (CRITICAL first)
        for signal, (category, severity) in self._SIGNAL_MAP.items():
            p_val = p.get(signal, False)
            r_val = r.get(signal, False)
            if p_val != r_val:
                allowing = "primary" if p_val else f"ref[{ref_index}]"
                blocking = f"ref[{ref_index}]" if p_val else "primary"
                return Finding(
                    title=(
                        f"Markdown XSS: {allowing} allows {signal} "
                        f"but {blocking} blocks"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "mechanism": signal,
                        "signal": signal,
                        "allowing_side": allowing,
                        "blocking_side": blocking,
                        "ref_index": ref_index,
                        "primary_html": (p.get("html") or "")[:500],
                        "ref_html": (r.get("html") or "")[:500],
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
                        f"Markdown One-Sided: {parsed_side} allows {signal} "
                        f"but {failed_side} crashes"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "mechanism": signal,
                        "signal": signal,
                        "parsed_side": parsed_side,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
        return None


# -- Link injection strategy ------------------------------------------


class MarkdownLinkInjectionStrategy:
    """Detect dangerous URI divergence in rendered links.

    Compares link_hrefs arrays between primary and reference.
    Reports when one renderer produces javascript: or data:text/html
    URIs that the other does not.
    """

    name = "markdown_link_injection"

    _DANGEROUS_PREFIXES = ("javascript:", "data:text/html")

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)
        if p is None or r is None:
            return None

        p_hrefs = set(p.get("link_hrefs", []))
        r_hrefs = set(r.get("link_hrefs", []))

        p_dangerous = {h for h in p_hrefs if self._is_dangerous(h)}
        r_dangerous = {h for h in r_hrefs if self._is_dangerous(h)}

        if p_dangerous == r_dangerous:
            return None

        only_primary = p_dangerous - r_dangerous
        only_ref = r_dangerous - p_dangerous

        if not only_primary and not only_ref:
            return None

        allowing = "primary" if only_primary else f"ref[{ref_index}]"
        extra = only_primary if only_primary else only_ref

        # Determine category from the first dangerous URI found
        sample = next(iter(extra))
        category = (
            "javascript_uri_injection"
            if sample.lower().startswith("javascript:")
            else "data_uri_injection"
        )

        return Finding(
            title=(
                f"Markdown Link Injection: {allowing} renders dangerous "
                f"URI (ref[{ref_index}])"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": category,
                "mechanism": self._classify_scheme(sample),
                "accepting_side": allowing,
                "dangerous_uris_primary": sorted(only_primary)[:10],
                "dangerous_uris_ref": sorted(only_ref)[:10],
                "ref_index": ref_index,
                "primary_html": (p.get("html") or "")[:500],
                "ref_html": (r.get("html") or "")[:500],
                "input_preview": _input_preview(inp),
            },
        )

    @staticmethod
    def _classify_scheme(uri: str) -> str:
        u = uri.strip().lower()
        if u.startswith("javascript:"):
            return "javascript_uri"
        if u.startswith("data:text/html"):
            return "data_html_uri"
        if u.startswith("data:"):
            return "data_uri"
        if u.startswith("vbscript:"):
            return "vbscript_uri"
        return "unknown_dangerous_uri"

    @staticmethod
    def _is_dangerous(href: str) -> bool:
        h = href.strip().lower()
        return any(h.startswith(pfx) for pfx in MarkdownLinkInjectionStrategy._DANGEROUS_PREFIXES)


# -- Raw HTML divergence strategy -------------------------------------


class MarkdownRawHtmlDivergenceStrategy:
    """Detect raw HTML block preservation divergence.

    When one renderer preserves raw HTML blocks and another strips or
    escapes them, this indicates different security postures for
    inline HTML handling.
    """

    name = "markdown_raw_html"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)
        if p is None or r is None:
            return None

        p_raw = p.get("has_raw_html", False)
        r_raw = r.get("has_raw_html", False)

        if p_raw == r_raw:
            return None

        allowing = "primary" if p_raw else f"ref[{ref_index}]"
        stripping = f"ref[{ref_index}]" if p_raw else "primary"

        return Finding(
            title=(
                f"Raw HTML Divergence: {allowing} preserves raw HTML "
                f"but {stripping} strips (ref[{ref_index}])"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "raw_html_divergence",
                "mechanism": "raw_html_block",
                "allowing_side": allowing,
                "stripping_side": stripping,
                "ref_index": ref_index,
                "primary_html": (p.get("html") or "")[:500],
                "ref_html": (r.get("html") or "")[:500],
                "input_preview": _input_preview(inp),
            },
        )


# -- Autolink divergence strategy -------------------------------------


class MarkdownAutolinkDivergenceStrategy:
    """Detect autolink detection divergence between renderers.

    When one renderer auto-links URLs/emails and another does not,
    this indicates different parsing behavior that may affect
    link injection attack surface.
    """

    name = "markdown_autolink"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)
        if p is None or r is None:
            return None

        p_autolinks = p.get("autolinks_found", False)
        r_autolinks = r.get("autolinks_found", False)

        if p_autolinks == r_autolinks:
            return None

        detecting = "primary" if p_autolinks else f"ref[{ref_index}]"
        ignoring = f"ref[{ref_index}]" if p_autolinks else "primary"

        return Finding(
            title=(
                f"Autolink Divergence: {detecting} detects autolinks "
                f"but {ignoring} does not (ref[{ref_index}])"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "autolink_divergence",
                "mechanism": "autolink_detection",
                "detecting_side": detecting,
                "ignoring_side": ignoring,
                "ref_index": ref_index,
                "primary_html": (p.get("html") or "")[:500],
                "ref_html": (r.get("html") or "")[:500],
                "input_preview": _input_preview(inp),
            },
        )


# -- Tag category divergence strategy ----------------------------------


class MarkdownTagCategoryDivergenceStrategy:
    """Detect divergence in security-relevant HTML tag categories.

    Groups tags into categories (exec, embed, form, foreign, media, meta)
    and reports when one renderer produces tags in a dangerous category
    that another doesn't.  Catches <object>, <embed>, <form>, <svg>,
    <math>, <base>, <meta> differences that boolean signals miss.
    """

    name = "markdown_tag_category"

    _DANGEROUS_CATS = {
        "exec": Severity.CRITICAL,   # script, style
        "embed": Severity.HIGH,      # iframe, object, embed
        "form": Severity.HIGH,       # form, input, button
        "meta": Severity.HIGH,       # base, meta (redirect/base-uri)
        "foreign": Severity.MEDIUM,  # svg, math (namespace confusion)
    }

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)
        if p is None or r is None:
            return None

        p_cats = set(filter(None, (p.get("tag_category_set") or "").split(",")))
        r_cats = set(filter(None, (r.get("tag_category_set") or "").split(",")))

        # Only report dangerous category differences
        for cat, severity in self._DANGEROUS_CATS.items():
            p_has = cat in p_cats
            r_has = cat in r_cats
            if p_has != r_has:
                allowing = "primary" if p_has else f"ref[{ref_index}]"
                blocking = f"ref[{ref_index}]" if p_has else "primary"
                return Finding(
                    title=(
                        f"Tag Category Divergence: {allowing} allows "
                        f"'{cat}' tags but {blocking} blocks"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "tag_category_divergence",
                        "mechanism": f"tag_cat_{cat}",
                        "tag_category": cat,
                        "allowing_side": allowing,
                        "blocking_side": blocking,
                        "ref_index": ref_index,
                        "primary_cats": sorted(p_cats),
                        "ref_cats": sorted(r_cats),
                        "input_preview": _input_preview(inp),
                    },
                )
        return None


# -- Event handler type divergence strategy ----------------------------


class MarkdownEventHandlerTypeDivergenceStrategy:
    """Detect divergence in specific event handler types.

    Goes beyond boolean has_event_handler: reports when one renderer
    allows onclick but another only allows onmouseover, etc.
    """

    name = "markdown_event_handler_type"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)
        if p is None or r is None:
            return None

        p_handlers = set(filter(None, (p.get("event_handler_set") or "").split(",")))
        r_handlers = set(filter(None, (r.get("event_handler_set") or "").split(",")))

        if p_handlers == r_handlers:
            return None

        only_p = p_handlers - r_handlers
        only_r = r_handlers - p_handlers

        if not only_p and not only_r:
            return None

        allowing = "primary" if only_p else f"ref[{ref_index}]"
        extra = only_p if only_p else only_r
        sample = next(iter(sorted(extra)))

        return Finding(
            title=(
                f"Event Handler Type Divergence: {allowing} allows "
                f"on{sample} but not the other (ref[{ref_index}])"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "event_handler_type_divergence",
                "mechanism": f"handler_{sample}",
                "allowing_side": allowing,
                "handlers_primary": sorted(p_handlers),
                "handlers_ref": sorted(r_handlers),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


# -- Link context divergence strategy ----------------------------------


class MarkdownLinkContextDivergenceStrategy:
    """Detect divergence in where dangerous URIs appear.

    Reports when dangerous content appears in different HTML contexts
    (a href vs img src vs iframe src vs form action) between renderers.
    """

    name = "markdown_link_context"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)
        if p is None or r is None:
            return None

        p_ctx = set(filter(None, (p.get("link_context_set") or "").split(",")))
        r_ctx = set(filter(None, (r.get("link_context_set") or "").split(",")))

        if p_ctx == r_ctx:
            return None

        # Only interesting if at least one side has dangerous content
        p_danger = p.get("dangerous_link_count", 0) or p.get("has_javascript_uri") or p.get("has_iframe")
        r_danger = r.get("dangerous_link_count", 0) or r.get("has_javascript_uri") or r.get("has_iframe")
        if not p_danger and not r_danger:
            return None

        only_p = p_ctx - r_ctx
        only_r = r_ctx - p_ctx

        if not only_p and not only_r:
            return None

        allowing = "primary" if only_p else f"ref[{ref_index}]"
        extra = only_p if only_p else only_r
        sample = next(iter(sorted(extra)))

        return Finding(
            title=(
                f"Link Context Divergence: {allowing} renders "
                f"'{sample}' context not in other (ref[{ref_index}])"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "link_context_divergence",
                "mechanism": f"ctx_{sample}",
                "allowing_side": allowing,
                "contexts_primary": sorted(p_ctx),
                "contexts_ref": sorted(r_ctx),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


# -- Dangerous scheme divergence strategy ------------------------------


class MarkdownDangerousSchemesDivergenceStrategy:
    """Detect divergence in which dangerous URI schemes pass through.

    Goes beyond boolean has_javascript_uri: reports when one renderer
    allows javascript: but blocks data:, while another does the opposite.
    """

    name = "markdown_dangerous_schemes"

    _SCHEME_SEVERITY = {
        "javascript": Severity.CRITICAL,
        "data_html": Severity.HIGH,
        "data": Severity.MEDIUM,
        "vbscript": Severity.CRITICAL,
    }

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_markdown_output(primary.stdout)
        r = _parse_markdown_output(reference.stdout)
        if p is None or r is None:
            return None

        p_schemes = set(filter(None, (p.get("dangerous_scheme_set") or "").split(",")))
        r_schemes = set(filter(None, (r.get("dangerous_scheme_set") or "").split(",")))

        if p_schemes == r_schemes:
            return None

        only_p = p_schemes - r_schemes
        only_r = r_schemes - p_schemes

        if not only_p and not only_r:
            return None

        allowing = "primary" if only_p else f"ref[{ref_index}]"
        extra = only_p if only_p else only_r
        # Pick highest severity scheme
        best_scheme = max(extra, key=lambda s: list(self._SCHEME_SEVERITY.keys()).index(s)
                         if s in self._SCHEME_SEVERITY else 99)
        severity = self._SCHEME_SEVERITY.get(best_scheme, Severity.MEDIUM)

        return Finding(
            title=(
                f"Scheme Divergence: {allowing} allows {best_scheme}: "
                f"but not the other (ref[{ref_index}])"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "dangerous_scheme_divergence",
                "mechanism": f"scheme_{best_scheme}",
                "allowing_side": allowing,
                "schemes_primary": sorted(p_schemes),
                "schemes_ref": sorted(r_schemes),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


# -- Factory ----------------------------------------------------------


def get_markdown_strategies() -> list:
    """Return all Markdown differential strategies.

    Intended to be composed with DiffOracle's existing strategies.
    Order matters: highest-impact strategies first.
    """
    return [
        MarkdownXssInjectionStrategy(),
        MarkdownLinkInjectionStrategy(),
        MarkdownDangerousSchemesDivergenceStrategy(),
        MarkdownTagCategoryDivergenceStrategy(),
        MarkdownEventHandlerTypeDivergenceStrategy(),
        MarkdownLinkContextDivergenceStrategy(),
        MarkdownRawHtmlDivergenceStrategy(),
        MarkdownAutolinkDivergenceStrategy(),
    ]
