"""XSS-aware differential strategy for sanitizer comparison.

Compares sanitizer outputs and reports when one sanitizer allows
a dangerous pattern that another sanitizer blocks.  This is the
primary mechanism for finding implementation-specific bypasses.

Unlike the standalone XssOracle which checks a single output,
this strategy performs pairwise comparison to identify divergent
sanitization behavior.
"""

from __future__ import annotations

import re
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity
from .xss_oracle import _is_entity_encoded_context, _is_inside_style_tag

# Quick-check patterns — lightweight regex set for fast scanning.
# Each entry: (compiled regex, name, context_type)
#   context_type: "html_attr" | "css" | "any"
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[bytes], str, str]] = [
    (re.compile(rb"<\s*script[\s/>]", re.I), "script_tag", "html_attr"),
    (re.compile(rb"<[^>]+\s+on[a-z]{2,30}\s*=", re.I), "event_handler", "html_attr"),
    (
        re.compile(
            rb"""(?:href|src|action|formaction)\s*=\s*["']?\s*javascript\s*:""",
            re.I,
        ),
        "javascript_uri",
        "html_attr",
    ),
    (
        re.compile(
            rb"""(?:href|src|action)\s*=\s*["']?\s*data\s*:\s*text/html""",
            re.I,
        ),
        "data_html_uri",
        "html_attr",
    ),
    (re.compile(rb"<\s*svg\b[^>]*>[\s\S]{0,500}<\s*script", re.I), "svg_script", "any"),
    (
        re.compile(rb"<\s*svg\b[^>]*>[\s\S]{0,500}\bon[a-z]+\s*=", re.I),
        "svg_event",
        "any",
    ),
    (re.compile(rb"<\s*foreignObject\b", re.I), "foreignobject", "html_attr"),
    (
        re.compile(
            rb"<\s*iframe\b[^>]*src\s*=\s*[\"']?\s*(?:javascript|data)\s*:",
            re.I,
        ),
        "iframe_dangerous",
        "html_attr",
    ),
    (re.compile(rb"<\s*base\b[^>]*href\s*=", re.I), "base_tag", "html_attr"),
    (re.compile(rb"<\s*object\b[^>]*data\s*=", re.I), "object_tag", "html_attr"),
    (re.compile(rb"<\s*embed\b[^>]*src\s*=", re.I), "embed_tag", "html_attr"),
    (re.compile(rb"expression\s*\(", re.I), "css_expression", "css"),
    (re.compile(rb"@import\b[^;]*javascript\s*:", re.I), "css_import_js", "css"),
    # mXSS-specific patterns (taxonomy-derived)
    (
        re.compile(
            rb'<\s*annotation-xml\b[^>]*encoding\s*=\s*["\']?\s*text/html',
            re.I,
        ),
        "annotation_xml_html",
        "any",
    ),
    (
        re.compile(rb"<\s*(?:mglyph|malignmark)\b", re.I),
        "mathml_integration_point",
        "any",
    ),
    (re.compile(rb"<!\[CDATA\["), "cdata_section", "any"),
    (
        re.compile(
            rb"<\s*noscript\b[^>]*>[\s\S]{0,200}<\s*(?:img|svg|script)",
            re.I,
        ),
        "noscript_dangerous",
        "any",
    ),
    (
        re.compile(rb"""xmlns\s*=\s*["'][^"']*on[a-z]+="""  , re.I),
        "xmlns_event_embed",
        "any",
    ),
]


def _find_dangerous(output: bytes) -> dict[str, bytes]:
    """Return dict of detected dangerous pattern names -> matched bytes.

    Applies the same context validation as :class:`XssOracle`:
    ``html_attr`` patterns are skipped inside entity-encoded text,
    ``css`` patterns require a surrounding ``<style>`` element.
    """
    found: dict[str, bytes] = {}
    for pat, name, context_type in _DANGEROUS_PATTERNS:
        m = pat.search(output)
        if not m:
            continue

        # Context validation
        if context_type == "html_attr":
            if _is_entity_encoded_context(output, m.start()):
                continue
        elif context_type == "css":
            if not _is_inside_style_tag(output, m.start()):
                continue
            if _is_entity_encoded_context(output, m.start()):
                continue

        found[name] = m.group(0)[:120]
    return found


class XssBypassStrategy:
    """Differential strategy: detect XSS bypass via sanitizer divergence.

    Reports a finding when:
      - Primary sanitizer allows dangerous patterns that reference blocks, OR
      - Reference sanitizer allows dangerous patterns that primary blocks

    Both directions are valuable for security research.
    """

    name = "xss_bypass"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        # Skip comparison if either target crashed
        if primary.exit_code != 0 and reference.exit_code != 0:
            return None

        primary_dangerous = _find_dangerous(primary.stdout)
        ref_dangerous = _find_dangerous(reference.stdout)

        # Case 1: Primary allows something reference blocks
        primary_only = set(primary_dangerous) - set(ref_dangerous)
        if primary_only:
            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                direction="primary_bypass",
                patterns=primary_only,
                primary_matches={k: primary_dangerous[k] for k in primary_only},
                primary_output=primary.stdout,
                ref_output=reference.stdout,
            )

        # Case 2: Reference allows something primary blocks
        ref_only = set(ref_dangerous) - set(primary_dangerous)
        if ref_only:
            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                direction="reference_bypass",
                patterns=ref_only,
                primary_matches={k: ref_dangerous[k] for k in ref_only},
                primary_output=primary.stdout,
                ref_output=reference.stdout,
            )

        return None

    @staticmethod
    def _make_finding(
        *,
        inp: Input,
        result: ExecutionResult,
        ref_index: int,
        direction: str,
        patterns: set[str],
        primary_matches: dict[str, bytes],
        primary_output: bytes,
        ref_output: bytes,
    ) -> Finding:
        pat_str = ", ".join(sorted(patterns))
        if direction == "primary_bypass":
            title = (
                f"XSS Bypass: primary allows [{pat_str}] "
                f"but ref[{ref_index}] blocks it"
            )
            severity = Severity.CRITICAL
        else:
            title = (
                f"XSS Bypass: ref[{ref_index}] allows [{pat_str}] "
                f"but primary blocks it"
            )
            severity = Severity.HIGH

        decoded_matches: dict[str, str] = {
            k: v.decode("utf-8", errors="replace")
            for k, v in primary_matches.items()
        }

        return Finding(
            title=title,
            severity=severity,
            input=inp,
            result=result,
            oracle_name="differential",
            metadata={
                "strategy": "xss_bypass",
                "direction": direction,
                "dangerous_patterns": sorted(patterns),
                "matches": decoded_matches,
                "ref_index": ref_index,
                "primary_output_prefix": primary_output[:300].decode(
                    "utf-8", errors="replace"
                ),
                "ref_output_prefix": ref_output[:300].decode(
                    "utf-8", errors="replace"
                ),
            },
        )
