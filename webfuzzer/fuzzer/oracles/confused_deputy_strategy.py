"""Confused Deputy strategy for Apache Confusion fuzzing.

Instead of comparing different configs, this strategy operates on a
SINGLE config and verifies exploitability:

1. The target has known-denied paths (/admin/, /internal/)
2. For each mutated URL, check if the response BODY contains
   protected content markers — regardless of status code
3. If protected content is served, this is a confirmed bypass

This eliminates cross-config FPs entirely. The oracle is:
"Did the fuzzer's URL mutation cause Apache to serve content
from a directory that the same config explicitly denies?"

Also detects Confused Deputy phase patterns:
- filename_at_access_check is in a permitted dir
- filename_at_handler crossed into a denied dir
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_output(stdout: bytes) -> dict | None:
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "status_code" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:200].decode("utf-8", errors="replace")


def _classify_mechanism(inp: Input) -> str:
    """Classify bypass mechanism from the input URL pattern."""
    url = inp.data.decode("utf-8", errors="replace")
    if "..;" in url:
        return "path_param_traversal"
    if "%2e%2e" in url.lower() or "%252e" in url.lower():
        return "encoded_traversal"
    if ".." in url:
        return "traversal"
    if ";jsessionid=" in url.lower():
        return "path_param_jsessionid"
    if ";" in url or "%3b" in url.lower():
        return "path_param"
    if "%2f" in url.lower() or "%5c" in url.lower():
        return "encoded_separator"
    if "//" in url:
        return "slash_merging"
    if "%00" in url:
        return "null_byte"
    if "%2e" in url.lower():
        return "encoded_dot"
    # Check for extensionless (MultiViews bypass)
    parts = url.rstrip("/").rsplit("/", 1)
    if len(parts) == 2 and "." not in parts[1] and parts[1]:
        return "extensionless_multiviews"
    return "unknown"


class ConfusedDeputyStrategy:
    """Detects when a single Apache config serves protected content
    via a URL that should have been denied.

    This is the primary oracle for finding real confusion bugs.
    No cross-config comparison needed.
    """

    name = "confused_deputy"

    def check(
        self,
        inp: Input,
        result: ExecutionResult,
    ) -> Finding | list[Finding] | None:
        """Single-target check (not a DiffStrategy — called by engine directly)."""
        p = _parse_output(result.stdout)
        if not p:
            return None

        findings = []

        # Signal 1: Protected content served (CRITICAL — confirmed bypass)
        if p.get("served_protected_content"):
            mechanism = _classify_mechanism(inp)
            marker = p.get("body_marker", "")
            findings.append(Finding(
                title=(
                    f"CONTENT LEAK: protected content ({marker!r}) "
                    f"served via {mechanism}"
                ),
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name="confused_deputy",
                metadata={
                    "strategy": self.name,
                    "category": "content_leak",
                    "mechanism": mechanism,
                    "body_marker": marker,
                    "status_code": p.get("status_code"),
                    "filename_at_handler": p.get("filename_at_handler", ""),
                    "confirmed_leak": True,
                },
            ))

        # Signal 2: Filename crossed into denied dir (HIGH — likely bypass)
        if p.get("filename_crossed_into_denied"):
            status = p.get("status_code", 0)
            fn_handler = p.get("filename_at_handler", "")
            fn_access = p.get("filename_at_access_check", "")
            mechanism = _classify_mechanism(inp)

            severity = Severity.HIGH
            if status == 200 and p.get("served_protected_content"):
                severity = Severity.CRITICAL  # already covered above
            elif status == 200:
                severity = Severity.HIGH  # crossed but content not confirmed

            if severity != Severity.CRITICAL:  # avoid duplicate with Signal 1
                findings.append(Finding(
                    title=(
                        f"Filename crossed denied dir: "
                        f"access_check={fn_access[:40]!r} → "
                        f"handler={fn_handler[:40]!r}"
                    ),
                    severity=severity,
                    input=inp,
                    result=result,
                    oracle_name="confused_deputy",
                    metadata={
                        "strategy": self.name,
                        "category": "filename_confusion",
                        "mechanism": mechanism,
                        "filename_at_access_check": fn_access,
                        "filename_at_handler": fn_handler,
                        "status_code": status,
                    },
                ))

        # Signal 3: PATH_INFO points to denied path (MEDIUM — CGI context)
        path_info = p.get("path_info_at_handler", "")
        if path_info:
            denied_segments = ("/admin", "/internal")
            if any(seg in path_info for seg in denied_segments):
                mechanism = _classify_mechanism(inp)
                findings.append(Finding(
                    title=f"PATH_INFO targets denied path: {path_info!r}",
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=result,
                    oracle_name="confused_deputy",
                    metadata={
                        "strategy": self.name,
                        "category": "path_info_confusion",
                        "mechanism": mechanism,
                        "path_info": path_info,
                        "status_code": p.get("status_code"),
                    },
                ))

        return findings if findings else None
