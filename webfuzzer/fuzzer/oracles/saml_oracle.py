"""SAML single-target security oracle.

Detects security anomalies in a single SAML library's behavior:
  - Signature accepted with multiple assertions (XSW bypass indicator)
  - Weak/deprecated algorithms accepted (SHA-1, MD5)
  - Multiple assertions detected (structural anomaly)

Note: Our target wrappers always extract NameID regardless of signature
validity (for differential comparison), so "subject extracted from unsigned
assertion" is NOT a finding — it's by design.  Real bypass detection is
handled by saml_diff_strategy.py in differential mode.
"""

from __future__ import annotations

from ..protocols import ExecutionResult, Finding, Input, Severity
from ._saml_parsing import parse_saml_output as _parse_saml_output

# Algorithms considered weak/deprecated
_WEAK_ALGORITHMS = frozenset({
    "sha1", "rsa-sha1", "md5", "hmac-sha1",
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#sha1",
    "http://www.w3.org/2001/04/xmldsig-more#md5",
})


class SamlOracle:
    """Single-target SAML security oracle."""

    name = "saml"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0:
            return None

        parsed = _parse_saml_output(result.stdout)
        if parsed is None:
            return None

        sig_valid = parsed.get("signature_valid")
        subject = (parsed.get("subject") or "").strip()
        assertion_count = parsed.get("assertion_count", 0)
        ref_match = parsed.get("reference_matches_selected_assertion")

        # CRITICAL: Signature accepted despite multiple assertions (XSW bypass)
        if sig_valid is True and assertion_count > 1:
            return Finding(
                title=f"SAML: Signature accepted with {assertion_count} assertions (XSW bypass)",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "sig_accepted_multi_assertion",
                    "assertion_count": assertion_count,
                    "subject": subject,
                },
            )

        # Signature scope mismatch is a direct auth-bypass indicator:
        # the library accepted a signature but extracted from a different assertion.
        if sig_valid is True and ref_match is False:
            return Finding(
                title="SAML: Signature accepted but selected assertion is outside Reference URI scope",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "reference_scope_mismatch",
                    "assertion_count": assertion_count,
                    "assertion_id": parsed.get("assertion_id"),
                    "reference_uri": parsed.get("reference_uri"),
                    "subject": subject,
                },
            )

        # HIGH: Multiple assertions detected (structural anomaly)
        if assertion_count > 1:
            return Finding(
                title=f"SAML: {assertion_count} assertions processed (XSW indicator)",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "multiple_assertions",
                    "assertion_count": assertion_count,
                    "subject": subject,
                },
            )

        # MEDIUM: Weak algorithm accepted
        algos = parsed.get("algorithms", {})
        for algo_field in ("signature", "digest"):
            algo = (algos.get(algo_field) or "").lower()
            if algo and algo in _WEAK_ALGORITHMS:
                return Finding(
                    title=f"SAML: Weak {algo_field} algorithm accepted: {algo}",
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={
                        "category": "weak_algorithm",
                        "algorithm_field": algo_field,
                        "algorithm": algo,
                    },
                )

        return None


class SamlSigTrueOracle(SamlOracle):
    """SAML oracle alias for sig=true differential campaigns."""

    name = "saml_sigtrue"


class SamlValidatorOracle(SamlOracle):
    """SAML oracle alias for validator-bug differential campaigns."""

    name = "saml_validator"
