"""JWT single-target security oracle.

Detects high-signal anomalies in one JWT implementation's output:
  - alg=none accepted
  - embedded/dynamic key sources trusted
  - token type confusion (JWS vs JWE)
  - critical headers ignored
  - temporal validation skipped

Cross-library divergences are handled by jwt_diff_strategy.py.
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_jwt_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a JWT target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and (
            "signature_valid" in data
            or "sub" in data
            or "effective_alg" in data
        ):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


class JwtOracle:
    """Single-target JWT security oracle."""

    name = "jwt"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0:
            return None

        parsed = _parse_jwt_output(result.stdout)
        if parsed is None:
            return None

        sig_valid = parsed.get("signature_valid")
        effective_alg = str(parsed.get("effective_alg") or parsed.get("header_alg") or "").strip()
        key_source = str(parsed.get("key_source") or "").strip()
        expected_type = str(parsed.get("token_type_expected") or "").strip()
        observed_type = str(parsed.get("token_type_observed") or "").strip()
        time_valid = parsed.get("time_valid")
        crit_processed = parsed.get("crit_processed")
        nested_jwt = parsed.get("nested_jwt")
        inner_signature_valid = parsed.get("inner_signature_valid")
        inner_alg = str(parsed.get("inner_alg") or "").strip()

        # nested_plainjwt_bypass: only fire when target actually attempted
        # inner verification and it came back False (not None = never tried)
        if sig_valid is True and nested_jwt and inner_signature_valid is False:
            return Finding(
                title="JWT: nested PlainJWT accepted without inner signature verification",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "nested_plainjwt_bypass",
                    "token_type_expected": expected_type,
                    "token_type_observed": observed_type,
                    "inner_alg": inner_alg,
                },
            )

        if sig_valid is True and effective_alg.lower() == "none":
            return Finding(
                title="JWT: alg=none accepted",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "alg_none_bypass",
                    "effective_alg": effective_alg,
                    "sub": parsed.get("sub"),
                },
            )

        # dynamic_key_trust: REMOVED from single-target oracle.
        # Targets report key_source from header parsing (before verification),
        # not from actual key resolution. sig_valid=True + key_source=jku just
        # means "header had jku AND sig verified with configured key" — not that
        # the library trusted jku. Cross-library divergence on key_source is
        # detected by JwtKeySourceDivergenceStrategy in jwt_diff_strategy.py.

        if sig_valid is True and expected_type and observed_type and expected_type != observed_type:
            return Finding(
                title=f"JWT: token type confusion ({expected_type} expected, got {observed_type})",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "token_type_confusion",
                    "token_type_expected": expected_type,
                    "token_type_observed": observed_type,
                },
            )

        if sig_valid is True and crit_processed is False:
            return Finding(
                title="JWT: critical headers ignored during verification",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "crit_header_ignored",
                    "crit_processed": crit_processed,
                },
            )

        if sig_valid is True and time_valid is False:
            return Finding(
                title="JWT: token accepted despite failed temporal validation",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "temporal_validation_gap",
                    "exp_state": parsed.get("exp_state"),
                    "nbf_state": parsed.get("nbf_state"),
                    "iat_state": parsed.get("iat_state"),
                },
            )

        return None
