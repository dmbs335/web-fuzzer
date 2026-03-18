"""mXSS oracle — detects DOM mutation and idempotency violations.

Works with the mXSS target which outputs JSON:

    {
        "sanitized": "<clean HTML>",
        "reparsed": "<innerHTML after re-parse>",        // JSDOM
        "resanitized": "<sanitize(sanitize(input))>",
        "mxss": true/false,                              // JSDOM
        "idempotency": true/false,
        "browser_reparsed": "<innerHTML via Chromium>",   // optional
        "browser_mxss": true/false,                       // optional
        "browser_parser_diff": true/false,                // optional
        "cascade_mxss": true/false,                       // optional
    }

Detection priority:
  1. **Browser mXSS**: sanitized !== browser_reparsed (real browser re-parse).
     CRITICAL if dangerous patterns appear in browser output.
  2. **Cascade mXSS**: multi-round innerHTML produces mutations.
  3. **JSDOM mXSS**: sanitized !== reparsed (JSDOM re-parse).
  4. **Idempotency violation**: sanitize(sanitize(input)) !== sanitize(input).
  5. **XSS in sanitized output**: dangerous patterns surviving sanitization.
"""

from __future__ import annotations

import html.parser
import json

from ..protocols import ExecutionResult, Finding, Input, Severity


class _DangerousPatternFinder(html.parser.HTMLParser):
    """DOM-level detection of dangerous HTML patterns.

    Unlike regex, this properly ignores HTML-like text inside attribute
    values (e.g. ``<form id="x <img src=x onerror=alert(1)>">``) because
    the parser treats it as an attribute value, not as a real element.
    """

    _DANGEROUS_ELEMENTS = frozenset({
        "script", "iframe", "embed", "object", "applet",
    })
    _DANGEROUS_URI_ATTRS = frozenset({
        "href", "src", "action", "formaction", "data", "poster", "background",
    })
    _DANGEROUS_SCHEMES = ("javascript:", "vbscript:", "data:text/html")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.found: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self.found:
            return
        tag_lower = tag.lower()

        # Dangerous elements
        if tag_lower in self._DANGEROUS_ELEMENTS:
            self.found = f"{tag_lower} element"
            return

        # Event handler attributes (on*)
        for name, value in attrs:
            if not name:
                continue
            name_lower = name.lower()
            if name_lower.startswith("on") and len(name_lower) > 2:
                self.found = "event handler"
                return
            # Dangerous URI schemes in URL attributes
            if name_lower in self._DANGEROUS_URI_ATTRS and value:
                val = value.strip().lower()
                for scheme in self._DANGEROUS_SCHEMES:
                    if val.startswith(scheme):
                        self.found = f"{scheme.rstrip(':')} URI"
                        return


def _has_dangerous_pattern(html_str: str) -> str | None:
    """Return description of first dangerous pattern found, or None.

    Uses html.parser for DOM-level detection — properly ignores
    HTML-like text inside attribute values to avoid false positives.
    """
    finder = _DangerousPatternFinder()
    try:
        finder.feed(html_str)
    except Exception:
        pass  # Malformed HTML — treat as no dangerous pattern
    return finder.found


def _compute_severity(data: dict) -> Severity:
    """Determine severity based on what changed during re-parse."""
    sanitized = data.get("sanitized", "")
    reparsed = data.get("reparsed", "")

    # Check if dangerous elements appeared in reparsed but not sanitized
    reparsed_danger = _has_dangerous_pattern(reparsed)
    sanitized_danger = _has_dangerous_pattern(sanitized)

    if reparsed_danger and not sanitized_danger:
        # Dangerous element introduced by re-parse — real mXSS
        return Severity.CRITICAL

    if reparsed_danger and sanitized_danger:
        # Both have dangerous patterns — sanitizer itself failed
        return Severity.CRITICAL

    # Structural mutation without obvious XSS — still interesting
    return Severity.HIGH


class MxssOracle:
    """mXSS detection oracle for double-parse and idempotency checking.

    Parses JSON output from the mXSS target and reports findings when:
    - DOM mutation detected after innerHTML re-parsing
    - Idempotency violation detected on double-sanitization
    - Dangerous patterns found in sanitized output
    """

    name = "mxss"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        """Check mXSS target JSON output for mutations and violations."""
        output = result.stdout
        if not output:
            return None

        # Parse JSON output from the mXSS target
        try:
            data = json.loads(output)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        sanitized = data.get("sanitized", "")
        reparsed = data.get("reparsed", "")
        resanitized = data.get("resanitized", "")
        is_mxss = data.get("mxss", False)
        is_idempotency = data.get("idempotency", False)

        # Browser-specific fields (optional, from Playwright target)
        browser_reparsed = data.get("browser_reparsed", "")
        is_browser_mxss = data.get("browser_mxss", False)
        is_browser_parser_diff = data.get("browser_parser_diff", False)
        is_cascade_mxss = data.get("cascade_mxss", False)
        inp_preview = inp.data[:200].decode("utf-8", errors="replace")

        # Priority 1: Browser mXSS — real browser re-parse differs
        if is_browser_mxss:
            browser_danger = _has_dangerous_pattern(browser_reparsed)
            sanitized_danger = _has_dangerous_pattern(sanitized)

            if browser_danger and not sanitized_danger:
                # Dangerous pattern introduced by real browser re-parse — REAL mXSS
                return Finding(
                    title=f"Browser mXSS: {browser_danger} introduced by Chromium re-parse",
                    severity=Severity.CRITICAL,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={
                        "category": "browser_mxss_dangerous",
                        "sanitized_preview": sanitized[:500],
                        "browser_reparsed_preview": browser_reparsed[:500],
                        "jsdom_reparsed_preview": reparsed[:500],
                        "diff": data.get("browser_mxss_diff") or {},
                        "dangerous_in_browser": browser_danger,
                        "browser_parser_diff": is_browser_parser_diff,
                        "cascade_mxss": is_cascade_mxss,
                        "input_preview": inp_preview,
                    },
                )

            # Browser structural mutation (no dangerous pattern yet)
            severity = Severity.HIGH if is_browser_parser_diff else Severity.MEDIUM
            title = "Browser mXSS: DOM mutation after Chromium re-parse"
            if is_browser_parser_diff:
                title = "Browser mXSS: JSDOM/Chromium parser differential"
            if is_cascade_mxss:
                title += " (cascade)"

            return Finding(
                title=title,
                severity=severity,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "browser_mxss_structural",
                    "sanitized_preview": sanitized[:500],
                    "browser_reparsed_preview": browser_reparsed[:500],
                    "jsdom_reparsed_preview": reparsed[:500],
                    "diff": data.get("browser_mxss_diff") or {},
                    "browser_parser_diff": is_browser_parser_diff,
                    "cascade_mxss": is_cascade_mxss,
                    "input_preview": inp_preview,
                },
            )

        # Priority 2: JSDOM mXSS — DOM mutation after innerHTML
        if is_mxss:
            severity = _compute_severity(data)
            diff_info = data.get("mxssDiff")
            reparsed_danger = _has_dangerous_pattern(reparsed)

            title = "mXSS: DOM mutation after innerHTML re-parse"
            if reparsed_danger:
                title = f"mXSS: {reparsed_danger} introduced by DOM mutation"

            return Finding(
                title=title,
                severity=severity,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "mxss_dom_mutation",
                    "sanitized_preview": sanitized[:500],
                    "reparsed_preview": reparsed[:500],
                    "diff": diff_info or {},
                    "dangerous_in_reparsed": reparsed_danger or "",
                    "input_preview": inp_preview,
                },
            )

        # Priority 3: Idempotency violation
        if is_idempotency:
            idempotency_diff = data.get("idempotencyDiff")
            return Finding(
                title="Sanitizer idempotency violation (double-sanitize differs)",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "idempotency_violation",
                    "sanitized_preview": sanitized[:500],
                    "resanitized_preview": resanitized[:500],
                    "diff": idempotency_diff or {},
                    "input_preview": inp_preview,
                },
            )

        # Priority 4: XSS patterns in sanitized output (fallback)
        danger = _has_dangerous_pattern(sanitized)
        if danger:
            return Finding(
                title=f"XSS bypass: {danger} survived sanitization",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "xss_bypass",
                    "pattern": danger,
                    "sanitized_preview": sanitized[:500],
                    "input_preview": inp_preview,
                },
            )

        return None
