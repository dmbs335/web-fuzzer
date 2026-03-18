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

        # CRITICAL: __Secure- prefix accepted without Secure flag
        if name.startswith("__Secure-") or name.startswith("__secure-"):
            if not secure:
                return Finding(
                    title="Cookie: __Secure- prefix accepted without Secure flag",
                    severity=Severity.CRITICAL,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={
                        "category": "secure_prefix_no_secure",
                        "name": name,
                        "secure": secure,
                    },
                )

        # HIGH: Unicode whitespace in parsed cookie name (normalization bypass)
        _UNICODE_WS = frozenset("\x85\xa0\u1680\u2000\u2001\u2002\u2003"
                                "\u2004\u2005\u2006\u2007\u2008\u2009"
                                "\u200a\u2028\u2029\u202f\u205f\u3000")
        if any(c in _UNICODE_WS for c in name):
            return Finding(
                title="Cookie: Unicode whitespace in cookie name (prefix bypass risk)",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "unicode_whitespace_name",
                    "name": repr(name),
                },
            )

        # MEDIUM: Nameless cookie (empty name) accepted
        if not name:
            return Finding(
                title="Cookie: Nameless cookie (empty name) accepted",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "nameless_cookie",
                    "value_preview": value[:100],
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
