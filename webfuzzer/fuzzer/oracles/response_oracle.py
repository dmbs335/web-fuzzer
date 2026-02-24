"""Response-based oracle — detects bugs via HTTP/process response analysis.

Pluggable response checks:
  a) status_code   — 5xx server errors
  b) error_pattern — regex matching against error messages
  c) timing_anomaly — response time exceeds baseline
  d) reflection    — input reflected unescaped in output (XSS)

Each check is a ResponseCheck Protocol, making it easy to add custom checks.
"""

from __future__ import annotations

import re
from typing import Protocol

from ..protocols import ExecutionResult, Finding, Input, Severity


class ResponseCheck(Protocol):
    """A single response-based check. Plug in custom checks."""
    name: str
    def check(self, inp: Input, result: ExecutionResult) -> Finding | None: ...


# ── Built-in checks ───────────────────────────────────────────────

class StatusCodeCheck:
    """Detect server errors via exit code or status_code metadata."""

    name = "status_code"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        status = result.metadata.get("status_code", 0)
        if isinstance(status, int) and status >= 500:
            return Finding(
                title=f"Server error: HTTP {status}",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={"status_code": status},
            )
        return None


class ErrorPatternCheck:
    """Detect errors via regex matching on stdout/stderr."""

    name = "error_pattern"

    # Vulnerability indicator patterns
    PATTERNS: dict[str, list[re.Pattern[str]]] = {
        "sqli": [
            re.compile(rb"SQL syntax", re.I),
            re.compile(rb"mysql_fetch", re.I),
            re.compile(rb"ORA-\d{5}", re.I),
            re.compile(rb"SQLSTATE\[", re.I),
            re.compile(rb"pg_query", re.I),
            re.compile(rb"sqlite3\.OperationalError", re.I),
            re.compile(rb"Unclosed quotation mark", re.I),
        ],
        "stack_trace": [
            re.compile(rb"Traceback \(most recent", re.I),
            re.compile(rb"at line \d+", re.I),
            re.compile(rb"Exception in thread", re.I),
            re.compile(rb"Fatal error:", re.I),
            re.compile(rb"panic:", re.I),
            re.compile(rb"Segmentation fault", re.I),
        ],
        "info_leak": [
            re.compile(rb"(?:password|secret|token|api_key)\s*[:=]", re.I),
            re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
            re.compile(rb"phpinfo\(\)"),
        ],
        "path_disclosure": [
            re.compile(rb"(?:/home/|/var/www/|C:\\\\)[\w/\\\\]+\.\w+", re.I),
            re.compile(rb"DocumentRoot", re.I),
        ],
    }

    def __init__(self, extra_patterns: dict[str, list[re.Pattern[str]]] | None = None):
        if extra_patterns:
            self.PATTERNS = {**self.PATTERNS, **extra_patterns}

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        output = result.stdout + result.stderr

        for category, patterns in self.PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(output)
                if match:
                    severity = {
                        "sqli": Severity.HIGH,
                        "stack_trace": Severity.MEDIUM,
                        "info_leak": Severity.HIGH,
                        "path_disclosure": Severity.LOW,
                    }.get(category, Severity.MEDIUM)

                    return Finding(
                        title=f"Error pattern: {category} ({pattern.pattern[:40]})",
                        severity=severity,
                        input=inp,
                        result=result,
                        oracle_name=self.name,
                        metadata={
                            "category": category,
                            "match": match.group(0)[:200].decode("utf-8", errors="replace"),
                        },
                    )
        return None


class TimingAnomalyCheck:
    """Detect potential DoS via response time anomaly."""

    name = "timing"

    def __init__(self, threshold_ms: float = 5000.0, baseline_factor: float = 10.0):
        self.threshold_ms = threshold_ms
        self.baseline_factor = baseline_factor
        self._baseline: float = 0.0
        self._count: int = 0

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        duration = result.duration_ms

        # Update rolling baseline
        self._count += 1
        self._baseline += (duration - self._baseline) / self._count

        # Check absolute threshold
        if duration > self.threshold_ms:
            return Finding(
                title=f"Timing anomaly: {duration:.0f}ms (threshold={self.threshold_ms:.0f}ms)",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={"duration_ms": duration, "baseline_ms": self._baseline},
            )

        # Check relative threshold (N times baseline)
        if self._count > 100 and self._baseline > 0:
            if duration > self._baseline * self.baseline_factor:
                return Finding(
                    title=f"Timing anomaly: {duration:.0f}ms ({duration/self._baseline:.1f}x baseline)",
                    severity=Severity.LOW,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={"duration_ms": duration, "baseline_ms": self._baseline},
                )

        return None


class ReflectionCheck:
    """Detect reflected input (potential XSS)."""

    name = "reflection"

    def __init__(self, min_reflection_len: int = 8):
        self.min_len = min_reflection_len

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        output = result.stdout + result.metadata.get("body", b"")
        if not output:
            return None

        # Check if significant portion of input is reflected verbatim
        data = inp.data
        if len(data) < self.min_len:
            return None

        # Check substrings of input for reflection
        for start in range(0, len(data) - self.min_len, self.min_len):
            chunk = data[start:start + self.min_len]
            if chunk in output:
                # Check if it contains potentially dangerous content
                dangerous = any(
                    marker in chunk
                    for marker in [b"<script", b"onerror", b"javascript:", b"<svg", b"<img"]
                )
                if dangerous:
                    return Finding(
                        title="Reflected potentially dangerous input (XSS candidate)",
                        severity=Severity.HIGH,
                        input=inp,
                        result=result,
                        oracle_name=self.name,
                        metadata={"reflected_chunk": chunk[:100].decode("utf-8", errors="replace")},
                    )

        return None


# ── Composite response oracle ────────────────────────────────────

class ResponseOracle:
    """Composes multiple ResponseCheck implementations into one Oracle."""

    name = "response"

    def __init__(self, checks: list[ResponseCheck] | None = None):
        self.checks: list[ResponseCheck] = checks or [
            StatusCodeCheck(),
            ErrorPatternCheck(),
            TimingAnomalyCheck(),
            ReflectionCheck(),
        ]

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        for check in self.checks:
            finding = check.check(inp, result)
            if finding:
                return finding
        return None
