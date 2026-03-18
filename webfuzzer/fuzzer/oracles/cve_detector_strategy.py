"""CVE-specific detection strategies for Apache Confusion vulnerabilities.

Single-target oracles that detect known CVE conditions from phase trace data,
without requiring cross-config differential comparison.

Each detector checks for the specific exploitation conditions of one CVE
(or family) and produces findings with CVE identifiers.
"""

from __future__ import annotations

import json
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_trace(stdout: bytes) -> dict | None:
    """Parse JSON from target output — supports both phase-trace and flat formats."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict):
            return data  # Accept any dict (flat or phase-trace format)
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _phase(trace: dict, name: str) -> dict:
    return trace.get("phases", {}).get(name, {})


def _input_preview(inp: Input) -> str:
    return inp.data[:200].decode("utf-8", errors="replace")


# ── CVE-2024-38474: %3F Path Truncation ──────────────────────────


class CVE38474DetectorStrategy:
    """Detect %3F path truncation — protected content served or args leaked."""

    name = "cve_38474_qmark"

    def check(
        self, inp: Input, result: ExecutionResult,
    ) -> Finding | None:
        trace = _parse_trace(result.stdout)
        if not trace:
            return None

        status = trace.get("status", 0)
        served_protected = trace.get("served_protected_content", False)
        body_marker = trace.get("body_marker", "")

        # Signal 1 (strongest): Protected content served + %3F in input
        input_str = _input_preview(inp)
        has_qmark = "%3f" in input_str.lower() or "%253f" in input_str.lower()

        if served_protected and has_qmark and status == 200:
            return Finding(
                title=f"CVE-2024-38474: %3F truncation → content leak ({body_marker})",
                severity=Severity.CRITICAL,
                oracle_name="cve_scanner",
                input=inp,
                result=result,
                metadata={
                    "cve": "CVE-2024-38474",
                    "strategy": self.name,
                    "category": "qmark_truncation",
                    "body_marker": body_marker,
                    "status": status,
                },
            )

        # Signal 2: Phase trace args (if available)
        handler = _phase(trace, "handler_phase")
        args = handler.get("args", "") or trace.get("args_at_handler", "")
        if args and args.startswith("/") and "." in args:
            return Finding(
                title=f"CVE-2024-38474: Rule suffix in args: {args[:40]}",
                severity=Severity.HIGH,
                oracle_name="cve_scanner",
                input=inp,
                result=result,
                metadata={
                    "cve": "CVE-2024-38474",
                    "strategy": self.name,
                    "category": "args_leak",
                    "leaked_args": args[:80],
                    "status": status,
                },
            )

        return None


# ── CVE-2024-38475: DocumentRoot Confusion ───────────────────────


class CVE38475DetectorStrategy:
    """Detect DocumentRoot escape — filename outside docroot at handler phase."""

    name = "cve_38475_docroot"

    _ESCAPE_PREFIXES = ("/usr/", "/proc/", "/etc/", "/var/", "/tmp/", "/opt/", "/home/")
    _DOCROOT_PREFIXES = ("/usr/local/apache2/htdocs", "/var/www/html", "/srv/http")

    def check(
        self, inp: Input, result: ExecutionResult,
    ) -> Finding | None:
        trace = _parse_trace(result.stdout)
        if not trace:
            return None

        handler = _phase(trace, "handler_phase")
        filename = handler.get("filename", "")
        status = trace.get("status", 0)

        # Skip proxy: filenames (different issue)
        if filename.startswith("proxy:"):
            return None

        # Also check from flat trace output (non-phase format)
        if not filename:
            filename = trace.get("filename_at_handler", "")
        if not filename:
            return None

        inside_docroot = any(filename.startswith(dr) for dr in self._DOCROOT_PREFIXES)
        outside_escape = any(filename.startswith(ep) for ep in self._ESCAPE_PREFIXES)

        if outside_escape and not inside_docroot:
            sev = Severity.CRITICAL if status == 200 else Severity.MEDIUM
            return Finding(
                title=f"CVE-2024-38475: DocRoot escape — {filename[:50]}",
                severity=sev,
                oracle_name="cve_scanner",
                input=inp,
                result=result,
                metadata={
                    "cve": "CVE-2024-38475",
                    "strategy": self.name,
                    "category": "docroot_escape",
                    "filename": filename[:120],
                    "status": status,
                    "content_served": status == 200,
                },
            )

        return None


# ── CVE-2024-39573: Prefix SSRF ─────────────────────────────────


class CVE39573DetectorStrategy:
    """Detect prefix-controlled SSRF — filename starts with proxy: scheme."""

    name = "cve_39573_prefix"

    def check(
        self, inp: Input, result: ExecutionResult,
    ) -> Finding | None:
        trace = _parse_trace(result.stdout)
        if not trace:
            return None

        handler = _phase(trace, "handler_phase")
        filename = handler.get("filename", "")
        handler_name = handler.get("handler", "")
        status = trace.get("status", 0)

        # Signal: filename starts with proxy: AND was not set by ProxyPass
        # (ProxyPass sets r->proxyreq early; prefix SSRF sets it via rewrite)
        if filename.startswith("proxy:") and status in (500, 502, 503):
            # 500/502/503 = proxy handler tried but backend unreachable
            scheme = filename.split(":", 2)[1] if ":" in filename[6:] else "unknown"
            return Finding(
                title=f"CVE-2024-39573: Prefix SSRF via {scheme}",
                severity=Severity.CRITICAL,
                oracle_name="cve_scanner",
                input=inp,
                result=result,
                metadata={
                    "cve": "CVE-2024-39573",
                    "strategy": self.name,
                    "category": "prefix_ssrf",
                    "proxy_url": filename[:120],
                    "scheme": scheme[:20],
                    "status": status,
                },
            )

        return None


# ── CVE-2024-38476: CRLF → Handler Invocation ───────────────────


class CVE38476DetectorStrategy:
    """Detect CRLF injection → arbitrary handler invocation."""

    name = "cve_38476_crlf"

    _HANDLER_INDICATORS = ("server-status", "server-info", "proxy:", "application/x-httpd-php")

    def check(
        self, inp: Input, result: ExecutionResult,
    ) -> Finding | None:
        trace = _parse_trace(result.stdout)
        if not trace:
            return None

        handler = _phase(trace, "handler_phase")
        final_handler = trace.get("final_handler", "")
        status = trace.get("status", 0)

        # Signal: handler was set to a restricted handler AND status 200
        input_str = _input_preview(inp)
        if "%0d%0a" not in input_str.lower() and "%0D%0A" not in input_str:
            return None  # No CRLF in input → not this CVE

        for indicator in self._HANDLER_INDICATORS:
            if indicator in final_handler and status == 200:
                return Finding(
                    title=f"CVE-2024-38476: CRLF → handler {indicator}",
                    severity=Severity.CRITICAL,
                    oracle_name="cve_scanner",
                    input=inp,
                    result=result,
                    metadata={
                        "cve": "CVE-2024-38476",
                        "strategy": self.name,
                        "category": "crlf_handler",
                        "invoked_handler": final_handler[:80],
                        "status": status,
                    },
                )

        return None


# ── Patch Bypass Detector ────────────────────────────────────────


class PatchBypassDetectorStrategy:
    """Detect ANY CVE condition on patched Apache (2.4.60+) = potential 0-day."""

    name = "patch_bypass"

    def __init__(self):
        self._detectors = [
            CVE38474DetectorStrategy(),
            CVE38475DetectorStrategy(),
            CVE39573DetectorStrategy(),
            CVE38476DetectorStrategy(),
        ]

    def check(
        self, inp: Input, result: ExecutionResult,
    ) -> Finding | None:
        for detector in self._detectors:
            finding = detector.check(inp, result)
            if finding:
                # Elevate severity — this would be a new 0-day
                return Finding(
                    title=f"PATCH BYPASS: {finding.title}",
                    severity=Severity.CRITICAL,
                    oracle_name="patch_bypass",
                    input=inp,
                    result=result,
                    metadata={
                        **finding.metadata,
                        "original_cve": finding.metadata.get("cve", "unknown"),
                        "strategy": "patch_bypass",
                        "category": "patch_bypass",
                        "note": "CVE condition triggered on patched Apache — potential 0-day",
                    },
                )

        return None


# ── Combined Scanner ─────────────────────────────────────────────


class CVEScannerStrategy:
    """Run all CVE detectors and return the first match."""

    name = "cve_scanner"

    def __init__(self):
        self._detectors = [
            CVE38474DetectorStrategy(),
            CVE38475DetectorStrategy(),
            CVE39573DetectorStrategy(),
            CVE38476DetectorStrategy(),
        ]

    def check(
        self, inp: Input, result: ExecutionResult,
    ) -> Finding | None:
        for detector in self._detectors:
            finding = detector.check(inp, result)
            if finding:
                return finding
        return None
