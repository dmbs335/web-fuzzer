"""Cookie single-target security oracle.

Detects security anomalies in a single cookie parser's behavior:
  - Cookie prefix violations accepted (__Host- without Secure/Path=/)
  - Control characters accepted in cookie name/value
  - CRLF injection in cookie value
  - Null byte in cookie value (truncation risk)
  - Cookie bomb (oversized values)

Note: Cross-parser differential detection is handled by
cookie_diff_strategy.py in differential mode.
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_cookie_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a cookie target.  Returns None on failure."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "name" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


class CookieOracle:
    """Single-target cookie security oracle."""

    name = "cookie"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0:
            return None

        parsed = _parse_cookie_output(result.stdout)
        if parsed is None:
            return None

        name = parsed.get("name", "")
        value = parsed.get("value", "")
        domain = parsed.get("domain", "")
        path = parsed.get("path", "")
        secure = parsed.get("secure", False)
        samesite = parsed.get("samesite", "")

        raw = inp.data

        # CRITICAL: __Host- prefix accepted without Secure flag
        if name.startswith("__Host-") or name.startswith("__host-"):
            if not secure:
                return Finding(
                    title=f"Cookie: __Host- prefix accepted without Secure flag",
                    severity=Severity.CRITICAL,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={
                        "category": "prefix_no_secure",
                        "name": name,
                        "secure": secure,
                    },
                )
            if domain:
                return Finding(
                    title=f"Cookie: __Host- prefix accepted with Domain={domain}",
                    severity=Severity.CRITICAL,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={
                        "category": "prefix_with_domain",
                        "name": name,
                        "domain": domain,
                    },
                )
            if path and path != "/":
                return Finding(
                    title=f"Cookie: __Host- prefix accepted with Path={path}",
                    severity=Severity.HIGH,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={
                        "category": "prefix_wrong_path",
                        "name": name,
                        "path": path,
                    },
                )

        # HIGH: CRLF in parsed cookie value (header injection)
        if "\r" in value or "\n" in value:
            return Finding(
                title="Cookie: CRLF characters accepted in cookie value",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "crlf_in_value",
                    "name": name,
                    "value_preview": value[:100],
                },
            )

        # HIGH: Null byte in parsed value (truncation attack)
        if "\x00" in value:
            return Finding(
                title="Cookie: Null byte accepted in cookie value",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "null_byte_value",
                    "name": name,
                },
            )

        # MEDIUM: Control characters in cookie name
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in name):
            return Finding(
                title="Cookie: Control characters accepted in cookie name",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "control_char_name",
                    "name": repr(name),
                },
            )

        # MEDIUM: TLD-only domain (super cookie)
        if domain in (".com", ".net", ".org", ".co.uk", ".io", "."):
            return Finding(
                title=f"Cookie: TLD-only domain accepted: {domain}",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "tld_only_domain",
                    "domain": domain,
                },
            )

        # MEDIUM: SameSite=None without Secure
        if samesite.lower() == "none" and not secure:
            return Finding(
                title="Cookie: SameSite=None accepted without Secure flag",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "samesite_none_no_secure",
                    "samesite": samesite,
                    "secure": secure,
                },
            )

        return None
