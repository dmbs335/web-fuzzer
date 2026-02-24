"""Fault escalation oracle (Witcher, IEEE S&P'23 style).

Converts application-level errors into detectable findings.
Maps error patterns in stdout/stderr to vulnerability categories:
  SQL errors      → SQLi finding
  Command errors  → Command injection finding
  SSRF indicators → SSRF finding
  LFI indicators  → Local file inclusion finding
"""

from __future__ import annotations

import re

from ..protocols import ExecutionResult, Finding, Input, Severity

# Vulnerability pattern mapping
VULN_PATTERNS: dict[str, list[tuple[re.Pattern[bytes], Severity, str]]] = {
    "sqli": [
        (re.compile(rb"You have an error in your SQL syntax", re.I), Severity.CRITICAL, "MySQL SQL injection"),
        (re.compile(rb"mysql_fetch_\w+\(\)", re.I), Severity.HIGH, "MySQL function error"),
        (re.compile(rb"ORA-\d{5}", re.I), Severity.CRITICAL, "Oracle SQL injection"),
        (re.compile(rb"SQLSTATE\[\w+\]", re.I), Severity.HIGH, "PDO SQL error"),
        (re.compile(rb"pg_query\(\).*failed", re.I), Severity.CRITICAL, "PostgreSQL injection"),
        (re.compile(rb"sqlite3\.OperationalError", re.I), Severity.HIGH, "SQLite injection"),
        (re.compile(rb"Unclosed quotation mark after", re.I), Severity.CRITICAL, "MSSQL injection"),
        (re.compile(rb"unterminated quoted string", re.I), Severity.HIGH, "SQL syntax error"),
        (re.compile(rb"near \".*\": syntax error", re.I), Severity.HIGH, "SQLite syntax error"),
    ],
    "cmdi": [
        (re.compile(rb"sh: [\w/]+: not found", re.I), Severity.CRITICAL, "Shell command execution"),
        (re.compile(rb"'[\w]+' is not recognized as", re.I), Severity.CRITICAL, "Windows command execution"),
        (re.compile(rb"uid=\d+\(\w+\) gid=\d+", re.I), Severity.CRITICAL, "Command injection (id output)"),
        (re.compile(rb"root:x:0:0:", re.I), Severity.CRITICAL, "File read via command injection"),
        (re.compile(rb"bash: [\w/]+: Permission denied", re.I), Severity.HIGH, "Command injection attempt"),
    ],
    "ssrf": [
        (re.compile(rb"connect\(\) failed", re.I), Severity.MEDIUM, "SSRF connection attempt"),
        (re.compile(rb"couldn't connect to host", re.I), Severity.MEDIUM, "SSRF connection failed"),
        (re.compile(rb"Connection refused", re.I), Severity.MEDIUM, "SSRF port scan indicator"),
        (re.compile(rb"getaddrinfo.*failed", re.I), Severity.MEDIUM, "SSRF DNS resolution"),
        (re.compile(rb"169\.254\.169\.254", re.I), Severity.CRITICAL, "SSRF metadata endpoint"),
    ],
    "lfi": [
        (re.compile(rb"No such file or directory", re.I), Severity.LOW, "Path traversal attempt"),
        (re.compile(rb"failed to open stream", re.I), Severity.MEDIUM, "PHP file inclusion"),
        (re.compile(rb"include\(\).*failed opening", re.I), Severity.HIGH, "PHP include vulnerability"),
        (re.compile(rb"Warning: file_get_contents", re.I), Severity.MEDIUM, "PHP file read"),
    ],
    "xxe": [
        (re.compile(rb"parser error.*Entity", re.I), Severity.HIGH, "XXE entity error"),
        (re.compile(rb"DOCTYPE.*ENTITY", re.I), Severity.MEDIUM, "XXE indicator"),
    ],
    "ssti": [
        (re.compile(rb"TemplateSyntaxError", re.I), Severity.HIGH, "SSTI template error"),
        (re.compile(rb"UndefinedError", re.I), Severity.MEDIUM, "SSTI undefined variable"),
        (re.compile(rb"jinja2\.exceptions", re.I), Severity.HIGH, "Jinja2 SSTI"),
    ],
}


class SanitizerOracle:
    """Witcher-style fault escalation oracle.

    Scans process output for vulnerability indicator patterns and
    converts them into structured findings.
    """

    name = "sanitizer"

    def __init__(
        self,
        extra_patterns: dict[str, list[tuple[re.Pattern[bytes], Severity, str]]] | None = None,
    ) -> None:
        self.patterns = dict(VULN_PATTERNS)
        if extra_patterns:
            for category, pats in extra_patterns.items():
                if category in self.patterns:
                    self.patterns[category].extend(pats)
                else:
                    self.patterns[category] = pats

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        output = result.stdout + result.stderr + result.metadata.get("body", b"")

        for category, patterns in self.patterns.items():
            for pattern, severity, description in patterns:
                match = pattern.search(output)
                if match:
                    return Finding(
                        title=f"{category.upper()}: {description}",
                        severity=severity,
                        input=inp,
                        result=result,
                        oracle_name=self.name,
                        metadata={
                            "category": category,
                            "description": description,
                            "match": match.group(0)[:200].decode("utf-8", errors="replace"),
                        },
                    )

        return None
