"""mXSS oracle — detects DOM mutation and idempotency violations.

Works with the mXSS target (sanitizer_dompurify_mxss.js /
sanitizer_dompurify_mxss_module.js) which outputs JSON:

    {
        "sanitized": "<clean HTML>",
        "reparsed": "<innerHTML after re-parse>",
        "resanitized": "<sanitize(sanitize(input))>",
        "mxss": true/false,
        "idempotency": true/false,
        "mxssDiff": "...",          // optional
        "idempotencyDiff": "..."    // optional
    }

Detection:
  1. **mXSS (DOM mutation)**: sanitized !== reparsed after innerHTML assignment.
     This is the core mXSS attack vector — the browser re-parses sanitized
     output differently, potentially re-introducing dangerous elements.
  2. **Idempotency violation**: sanitize(sanitize(input)) !== sanitize(input).
     Parser confusion where the sanitizer produces different output on
     double-sanitization — indicates fragile parsing boundaries.
  3. **XSS in sanitized output**: Scans sanitized field for dangerous
     patterns (script tags, event handlers, javascript: URIs).
"""

from __future__ import annotations

import json
import re

from ..protocols import ExecutionResult, Finding, Input, Severity

# Quick XSS patterns to check against sanitized output
_DANGEROUS_PATTERNS: list[tuple[re.Pattern[bytes], str]] = [
    (re.compile(rb"<\s*script[\s/>]", re.I), "script tag"),
    (re.compile(rb"<[^>]+\s+on[a-z]{2,30}\s*=", re.I), "event handler"),
    (re.compile(rb"""(?:href|src|action)\s*=\s*["']?\s*javascript\s*:""", re.I), "javascript: URI"),
    (re.compile(rb"<\s*iframe\b", re.I), "iframe element"),
    (re.compile(rb"<\s*embed\b[^>]*\bsrc\s*=", re.I), "embed element"),
    (re.compile(rb"<\s*object\b[^>]*\bdata\s*=", re.I), "object element"),
]


def _has_dangerous_pattern(html: str) -> str | None:
    """Return description of first dangerous pattern found, or None."""
    data = html.encode("utf-8", errors="replace")
    for pat, desc in _DANGEROUS_PATTERNS:
        if pat.search(data):
            return desc
    return None


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

        # Priority 1: mXSS — DOM mutation after innerHTML
        if is_mxss:
            severity = _compute_severity(data)
            diff_info = data.get("mxssDiff")

            # Check if the mutation introduced dangerous elements
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
                    "input_preview": inp.data[:200].decode("utf-8", errors="replace"),
                },
            )

        # Priority 2: Idempotency violation
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
                    "input_preview": inp.data[:200].decode("utf-8", errors="replace"),
                },
            )

        # Priority 3: XSS patterns in sanitized output (fallback)
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
                    "input_preview": inp.data[:200].decode("utf-8", errors="replace"),
                },
            )

        return None
