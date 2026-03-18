"""OAuth single-target security oracle.

Detects high-signal anomalies in one OAuth implementation's output:
  - Fragment in redirect_uri accepted (RFC 6749 §3.1.2 violation)
  - Loopback matching for non-native applications
  - Scope with empty elements parsed without error
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_oauth_output(stdout: bytes) -> dict | None:
    """Parse JSON output from an OAuth target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "input_type" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


class OAuthOracle:
    """Single-target OAuth security oracle."""

    name = "oauth"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0:
            return None

        parsed = _parse_oauth_output(result.stdout)
        if parsed is None:
            return None

        # Check 1: Fragment in redirect_uri accepted (RFC violation)
        if (
            parsed.get("input_type") == "redirect_uri"
            and parsed.get("fragment_present") is True
            and parsed.get("redirect_match") is True
        ):
            return Finding(
                title="OAuth: redirect_uri with fragment accepted (RFC 6749 §3.1.2 violation)",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "fragment_accepted",
                    "candidate_normalized": parsed.get("candidate_normalized"),
                },
            )

        # Check 2: Loopback port matching on web application (should only be native)
        if (
            parsed.get("input_type") == "redirect_uri"
            and parsed.get("loopback_detected") is True
            and parsed.get("redirect_match") is True
        ):
            # This is interesting if the input didn't specify native app type
            input_data = {}
            try:
                input_data = json.loads(inp.data.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
                pass
            if input_data.get("application_type") != "native":
                return Finding(
                    title="OAuth: loopback port-agnostic matching on non-native app",
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={"category": "loopback_web_app"},
                )

        # Check 3: PKCE challenge_match=True when challenge key was absent
        # CVE-2025-4144 pattern: library skips PKCE check entirely
        if (
            parsed.get("input_type") == "pkce"
            and parsed.get("challenge_was_absent") is True
            and parsed.get("challenge_match") is True
        ):
            return Finding(
                title="OAuth: PKCE challenge_match=True without challenge (CVE-2025-4144 pattern)",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "pkce_presence_bypass",
                    "method_resolved": parsed.get("method_resolved"),
                },
            )

        return None
