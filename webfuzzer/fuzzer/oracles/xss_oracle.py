"""XSS bypass oracle — detects dangerous patterns surviving sanitization.

Scans sanitizer output (stdout) for HTML constructs that should have been
removed.  If any dangerous pattern is found in the sanitized output,
the sanitizer has failed and a finding is reported.

Detection categories:
  - Script elements            (<script>)
  - Event handler attributes   (on*=)
  - Dangerous URI schemes      (javascript:, vbscript:, data:text/html)
  - Namespace-based XSS        (SVG/MathML with script or event handlers)
  - Dangerous element survival (iframe, object, embed, base, applet)
  - CSS-based XSS              (expression(), -moz-binding, @import javascript:)

Context validation:
  - ``html_attr`` patterns are skipped when the match sits inside
    entity-encoded text (``&lt;...&gt;``).
  - ``css`` patterns are only reported when inside a real ``<style>`` element
    and not entity-encoded.
  - ``any`` patterns have no extra context checks.
"""

from __future__ import annotations

import re

from ..protocols import ExecutionResult, Finding, Input, Severity

# ── Context helpers ──────────────────────────────────────────────


def _is_entity_encoded_context(output: bytes, match_start: int) -> bool:
    """Return True if *match_start* sits inside entity-encoded text.

    Looks backward up to 200 bytes for ``&lt;``.  If the closest
    ``&lt;`` is nearer than (or at the same position as) the closest
    real ``<``, the match is inside an encoded fragment such as
    ``&lt;base href="javascript:..."&gt;`` and should be ignored.
    """
    window = output[max(0, match_start - 200):match_start]
    last_entity_lt = window.rfind(b"&lt;")
    if last_entity_lt == -1:
        return False
    last_real_lt = window.rfind(b"<")
    if last_real_lt == -1:
        # Only entity-encoded < found — definitely encoded context.
        return True
    # ``&lt;`` occupies 4 bytes; if the last real ``<`` falls *within*
    # the ``&lt;`` token itself it is part of the entity, not a real tag.
    return last_real_lt <= last_entity_lt + 3


def _is_inside_style_tag(output: bytes, match_start: int) -> bool:
    """Return True if *match_start* falls between ``<style`` and ``</style``."""
    before = output[:match_start].lower()
    last_open = before.rfind(b"<style")
    last_close = before.rfind(b"</style")
    if last_open == -1:
        return False
    return last_open > last_close


# ── XSS pattern definitions ──────────────────────────────────────
#
# Each entry: (compiled regex, severity, short description, context_type)
#   context_type: "html_attr" | "css" | "any"

XSS_PATTERNS: list[tuple[re.Pattern[bytes], Severity, str, str]] = [
    # --- Script execution ---
    (
        re.compile(rb"<\s*script[\s/>]", re.I),
        Severity.CRITICAL,
        "Script tag survived sanitization",
        "html_attr",
    ),
    (
        re.compile(
            rb"<[^>]+\s+on[a-z]{2,30}\s*=",
            re.I,
        ),
        Severity.CRITICAL,
        "Event handler attribute survived sanitization",
        "html_attr",
    ),

    # --- Dangerous URI schemes ---
    (
        re.compile(
            rb"""(?:href|src|action|formaction|data|poster|background)\s*=\s*["']?\s*javascript\s*:""",
            re.I,
        ),
        Severity.CRITICAL,
        "javascript: URI survived in attribute",
        "html_attr",
    ),
    (
        re.compile(
            rb"""(?:href|src|action|formaction)\s*=\s*["']?\s*vbscript\s*:""",
            re.I,
        ),
        Severity.HIGH,
        "vbscript: URI survived in attribute",
        "html_attr",
    ),
    (
        re.compile(
            rb"""(?:href|src|action)\s*=\s*["']?\s*data\s*:\s*text/html""",
            re.I,
        ),
        Severity.HIGH,
        "data:text/html URI survived in attribute",
        "html_attr",
    ),

    # --- SVG/MathML namespace XSS ---
    (
        re.compile(rb"<\s*svg\b[^>]*>[\s\S]{0,500}<\s*script", re.I),
        Severity.CRITICAL,
        "SVG with embedded script survived",
        "any",
    ),
    (
        re.compile(
            rb"<\s*svg\b[^>]*>[\s\S]{0,500}\bon[a-z]{2,30}\s*=",
            re.I,
        ),
        Severity.CRITICAL,
        "SVG with event handler survived",
        "any",
    ),
    (
        re.compile(
            rb"<\s*math\b[^>]*>[\s\S]{0,1000}<\s*annotation[^>]*encoding\s*=\s*[\"']?\s*text/html",
            re.I,
        ),
        Severity.HIGH,
        "MathML annotation with text/html encoding survived",
        "any",
    ),
    (
        re.compile(
            rb"<\s*foreignObject\b",
            re.I,
        ),
        Severity.HIGH,
        "SVG foreignObject survived (namespace switch vector)",
        "html_attr",
    ),

    # --- Dangerous elements ---
    (
        re.compile(
            rb"""<\s*iframe\b[^>]*\bsrc\s*=\s*["']?\s*(?:javascript|data|vbscript)\s*:""",
            re.I,
        ),
        Severity.CRITICAL,
        "iframe with dangerous src survived",
        "html_attr",
    ),
    (
        re.compile(rb"<\s*object\b[^>]*\bdata\s*=", re.I),
        Severity.MEDIUM,
        "object element with data attribute survived",
        "html_attr",
    ),
    (
        re.compile(rb"<\s*embed\b[^>]*\bsrc\s*=", re.I),
        Severity.MEDIUM,
        "embed element with src survived",
        "html_attr",
    ),
    (
        re.compile(rb"<\s*applet\b", re.I),
        Severity.MEDIUM,
        "applet element survived",
        "html_attr",
    ),
    (
        re.compile(rb"<\s*base\b[^>]*\bhref\s*=", re.I),
        Severity.HIGH,
        "base tag with href survived (URL hijack)",
        "html_attr",
    ),

    # --- Form-based XSS ---
    (
        re.compile(
            rb"""<\s*form\b[^>]*\baction\s*=\s*["']?\s*javascript\s*:""",
            re.I,
        ),
        Severity.HIGH,
        "form with javascript: action survived",
        "html_attr",
    ),

    # --- Meta redirect XSS ---
    (
        re.compile(
            rb"""<\s*meta\b[^>]*http-equiv\s*=\s*["']?\s*refresh[^>]*javascript\s*:""",
            re.I,
        ),
        Severity.HIGH,
        "meta refresh with javascript: survived",
        "html_attr",
    ),

    # --- CSS-based XSS ---
    (
        re.compile(rb"expression\s*\(", re.I),
        Severity.MEDIUM,
        "CSS expression() survived in style",
        "css",
    ),
    (
        re.compile(rb"-moz-binding\s*:", re.I),
        Severity.MEDIUM,
        "-moz-binding survived in style",
        "css",
    ),
    (
        re.compile(rb"@import\b[^;]*javascript\s*:", re.I),
        Severity.HIGH,
        "CSS @import with javascript: survived",
        "css",
    ),

    # --- mXSS-specific patterns (taxonomy-derived) ---

    # §1-3: MathML annotation-xml with HTML encoding (integration point)
    (
        re.compile(
            rb'<\s*annotation-xml\b[^>]*encoding\s*=\s*["\']?\s*'
            rb"(?:text/html|application/xhtml\+xml)",
            re.I,
        ),
        Severity.HIGH,
        "MathML annotation-xml with HTML encoding survived (mXSS vector)",
        "any",
    ),
    # §1-1: mglyph/malignmark integration points with dangerous content
    (
        re.compile(
            rb"<\s*(?:mglyph|malignmark)\b[^>]*>"
            rb"[\s\S]{0,500}(?:<\s*script|on[a-z]{2,30}\s*=)",
            re.I,
        ),
        Severity.HIGH,
        "MathML integration point (mglyph/malignmark) with dangerous content",
        "any",
    ),
    # §3: Style element in body context with unfiltered CSS
    (
        re.compile(
            rb"(?:<\s*(?:div|p|span|br|img|a|b|i|em|strong|body|table"
            rb"|form|input|ul|ol|li|h[1-6])\b[^>]*>|[a-zA-Z0-9])"
            rb"\s*<\s*style\b[^>]*>[\s\S]{1,5000}"
            rb"(?:@import|expression|url\s*\(|background\s*:)",
            re.I,
        ),
        Severity.HIGH,
        "Style element in body context with unfiltered CSS (injection vector)",
        "any",
    ),
    # §1-3: Nested namespace elements with dangerous content
    (
        re.compile(
            rb"<\s*(?:svg|math)\b[^>]*>[\s\S]{0,2000}"
            rb"<\s*(?:svg|math)\b[^>]*>"
            rb"[\s\S]{0,500}(?:<\s*script|on[a-z]+\s*=)",
            re.I,
        ),
        Severity.CRITICAL,
        "Nested namespace elements with dangerous content (multi-layer mXSS)",
        "any",
    ),
    # Browser security: DOM clobbering vector
    (
        re.compile(
            rb"<\s*(?:form|img|a|embed|object)\b[^>]*"
            rb"\b(?:id|name)\s*=\s*[\"']?\s*"
            rb"(?:document|location|window|top|self|parent"
            rb"|frames|opener|closed|length|origin)\b",
            re.I,
        ),
        Severity.MEDIUM,
        "DOM clobbering vector survived (id/name targeting builtins)",
        "html_attr",
    ),
    # §1-4: CDATA section in output (should not survive in HTML)
    (
        re.compile(rb"<!\[CDATA\["),
        Severity.MEDIUM,
        "CDATA section survived in output (parser differential indicator)",
        "any",
    ),
    # §4: xmlns attribute with embedded event handler
    (
        re.compile(
            rb"""xmlns\s*=\s*["'][^"']*"""
            rb"""(?:on[a-z]{2,30}\s*=|javascript\s*:)[^"']*["']""",
            re.I,
        ),
        Severity.HIGH,
        "xmlns attribute contains embedded event handler/script (mXSS)",
        "any",
    ),
    # §3-3: noscript with dangerous content
    (
        re.compile(
            rb"<\s*noscript\b[^>]*>[\s\S]{0,500}"
            rb"(?:<\s*(?:script|img|svg|math|iframe)\b[^>]*"
            rb"\b(?:on[a-z]+|src|href)\s*=)",
            re.I,
        ),
        Severity.HIGH,
        "noscript with dangerous content survived (scripting flag differential)",
        "any",
    ),
    # §3: template element with dangerous content
    (
        re.compile(
            rb"<\s*template\b[^>]*>[\s\S]{0,1000}"
            rb"(?:<\s*script|on[a-z]+\s*=|javascript\s*:)",
            re.I,
        ),
        Severity.MEDIUM,
        "Template element with dangerous content survived",
        "any",
    ),
    # Browser security: Prototype pollution pattern
    (
        re.compile(
            rb"(?:__proto__|constructor\s*\.\s*prototype"
            rb"|constructor\s*\[)",
        ),
        Severity.MEDIUM,
        "Prototype pollution pattern survived sanitization",
        "any",
    ),
]


def _build_combined_pattern(
    patterns: list[tuple[re.Pattern[bytes], Severity, str, str]],
) -> tuple[re.Pattern[bytes], list[tuple[Severity, str, str]]]:
    """Combine individual patterns into one alternation regex.

    Returns the combined compiled pattern and a metadata list indexed
    by named-group number.  Each sub-pattern is wrapped in an inline
    case-insensitive flag ``(?i:...)`` when the original used ``re.I``.
    """
    parts: list[str] = []
    meta: list[tuple[Severity, str, str]] = []

    for idx, (pat, sev, desc, ctx) in enumerate(patterns):
        raw = pat.pattern
        if isinstance(raw, bytes):
            raw = raw.decode("latin-1")
        # Wrap in inline (?i:...) if originally case-insensitive
        if pat.flags & re.IGNORECASE:
            parts.append(f"(?P<p{idx}>(?i:{raw}))")
        else:
            parts.append(f"(?P<p{idx}>{raw})")
        meta.append((sev, desc, ctx))

    combined_src = "|".join(parts).encode("latin-1")
    combined = re.compile(combined_src)
    return combined, meta


class XssOracle:
    """XSS bypass detection oracle.

    Scans the sanitized output for HTML constructs that indicate
    the sanitizer failed to neutralize a potential XSS vector.

    Context-aware: skips matches that are entity-encoded text or
    CSS patterns outside ``<style>`` elements.

    Performance: all patterns are combined into a single alternation
    regex so the engine only makes one pass over the output.
    """

    name = "xss"

    def __init__(
        self,
        extra_patterns: list[tuple[re.Pattern[bytes], Severity, str, str]] | None = None,
    ) -> None:
        self.patterns = list(XSS_PATTERNS)
        if extra_patterns:
            self.patterns.extend(extra_patterns)
        # Build combined regex for single-pass matching
        self._combined, self._meta = _build_combined_pattern(self.patterns)

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        """Check sanitizer output for surviving XSS patterns."""
        output = result.stdout
        if not output:
            return None

        for match in self._combined.finditer(output):
            # Identify which sub-pattern matched
            group_name = match.lastgroup
            if not group_name:
                continue
            idx = int(group_name[1:])  # "p0" → 0
            severity, description, context_type = self._meta[idx]

            # ── Context validation ──
            if context_type == "html_attr":
                if _is_entity_encoded_context(output, match.start()):
                    continue  # entity-encoded text, not a real attribute
            elif context_type == "css":
                if not _is_inside_style_tag(output, match.start()):
                    continue  # CSS pattern outside <style> — not exploitable
                if _is_entity_encoded_context(output, match.start()):
                    continue  # entity-encoded CSS text
            # context_type == "any" → no extra checks

            matched_text = match.group(0)[:200]
            return Finding(
                title=f"XSS: {description}",
                severity=severity,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "xss_bypass",
                    "description": description,
                    "match": matched_text.decode("utf-8", errors="replace"),
                    "input_preview": inp.data[:200].decode(
                        "utf-8", errors="replace"
                    ),
                    "output_preview": output[:500].decode(
                        "utf-8", errors="replace"
                    ),
                },
            )

        return None
