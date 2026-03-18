"""Tests for JWT oracle and differential strategies."""

import json

import pytest

from webfuzzer.fuzzer.oracles.jwt_diff_strategy import (
    JwtAlgorithmDivergenceStrategy,
    JwtClaimConfusionStrategy,
    JwtClaimTypeStrategy,
    JwtDuplicateKeyStrategy,
    JwtHeaderPolicyStrategy,
    JwtKeySourceDivergenceStrategy,
    JwtSigTrueOnlyWrapper,
    JwtSignatureBypassStrategy,
    JwtTemporalConfusionStrategy,
    JwtZipConfusionStrategy,
    get_jwt_strategies,
)
from webfuzzer.fuzzer.oracles.jwt_oracle import JwtOracle, _parse_jwt_output
from webfuzzer.fuzzer.protocols import ExecutionResult, Input, Severity


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(exit_code=exit_code, stdout=json.dumps(data).encode())


def _first(result):
    """Unwrap list or single Finding from compare() for test assertions."""
    if isinstance(result, list):
        return result[0]
    return result


VALID_JWT = {
    "signature_valid": True,
    "header_alg": "HS256",
    "effective_alg": "HS256",
    "key_source": "configured",
    "resolved_kid": "kid-1",
    "token_type_expected": "jws",
    "token_type_observed": "jws",
    "typ": "JWT",
    "cty": None,
    "crit_processed": True,
    "sub": "user-123",
    "iss": "https://issuer.example",
    "aud": "https://api.example",
    "role": "user",
    "scope": "read",
    "time_valid": True,
    "exp_state": "valid",
    "nbf_state": "valid",
    "iat_state": "valid",
    "duplicate_header_keys": [],
    "duplicate_claim_keys": [],
    "claim_parse_mode": "last_wins",
}


class TestParseJwtOutput:
    def test_valid_json(self):
        parsed = _parse_jwt_output(json.dumps(VALID_JWT).encode())
        assert parsed is not None
        assert parsed["signature_valid"] is True

    def test_invalid_json(self):
        assert _parse_jwt_output(b"not-json") is None


class TestJwtOracle:
    @pytest.fixture
    def oracle(self):
        return JwtOracle()

    def test_name(self, oracle):
        assert oracle.name == "jwt"

    def test_none_alg_accepted(self, oracle):
        data = {**VALID_JWT, "effective_alg": "none"}
        finding = oracle.check(Input(data=b"jwt"), _make_result(data))
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "alg_none_bypass"

    def test_dynamic_key_source_suppressed(self, oracle):
        """dynamic_key_trust removed from single-target oracle (false positive).

        Targets set key_source from header parsing, not from actual key
        resolution. Detection moved to JwtKeySourceDivergenceStrategy.
        """
        data = {**VALID_JWT, "key_source": "embedded_jwk"}
        finding = oracle.check(Input(data=b"jwt"), _make_result(data))
        assert finding is None

    def test_token_type_confusion(self, oracle):
        data = {
            **VALID_JWT,
            "token_type_expected": "jws",
            "token_type_observed": "jwe",
        }
        finding = oracle.check(Input(data=b"jwt"), _make_result(data))
        assert finding is not None
        assert finding.metadata["category"] == "token_type_confusion"

    def test_nested_plainjwt_bypass_requires_false(self, oracle):
        """nested_plainjwt_bypass only fires when inner_signature_valid=False.

        inner_signature_valid=None means target never attempted inner
        verification — not a bug. Only False = target tried and failed.
        """
        # inner_signature_valid=None → suppressed (target never tried)
        data_none = {
            **VALID_JWT,
            "token_type_expected": "nested_jws",
            "token_type_observed": "jwe",
            "nested_jwt": True,
            "inner_alg": "none",
            "inner_signature_valid": None,
        }
        finding = oracle.check(Input(data=b"jwt"), _make_result(data_none))
        # Falls through to token_type_confusion (expected!=observed)
        assert finding is not None
        assert finding.metadata["category"] == "token_type_confusion"

        # inner_signature_valid=False → fires
        data_false = {**data_none, "inner_signature_valid": False}
        finding = oracle.check(Input(data=b"jwt"), _make_result(data_false))
        assert finding is not None
        assert finding.metadata["category"] == "nested_plainjwt_bypass"

    def test_time_validation_gap(self, oracle):
        data = {**VALID_JWT, "time_valid": False, "exp_state": "expired"}
        finding = oracle.check(Input(data=b"jwt"), _make_result(data))
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "temporal_validation_gap"

    def test_no_finding_for_valid(self, oracle):
        assert oracle.check(Input(data=b"jwt"), _make_result(VALID_JWT)) is None


class TestJwtSignatureBypassStrategy:
    def test_signature_bypass(self):
        s = JwtSignatureBypassStrategy()
        primary = _make_result(VALID_JWT)
        # signature_error with non-algorithm error → real bypass
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": "InvalidSignatureError: bad signature",
        })
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "signature_bypass"

    def test_cross_config_noise_suppressed(self):
        """Cross-config noise: rejecting side error mentions algorithm."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": "InvalidAlgorithmError: algorithm not allowed",
        })
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is None

    def test_exploit_confidence_with_sentinel(self):
        s = JwtSignatureBypassStrategy()
        primary = _make_result({**VALID_JWT, "sub": "evil-sentinel-9z9"})
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": "InvalidSignatureError: bad signature",
        })
        inp = Input(data=b"jwt", metadata={"jwt_evil_sentinel": "evil-sentinel-9z9"})
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["exploit_confidence"] == "HIGH"

    def test_no_finding_when_both_reject(self):
        s = JwtSignatureBypassStrategy()
        primary = _make_result({**VALID_JWT, "signature_valid": False})
        reference = _make_result({**VALID_JWT, "signature_valid": False})
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is None


class TestJwtClaimConfusionStrategy:
    def test_subject_confusion(self):
        s = JwtClaimConfusionStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "sub": "admin-123"})
        result = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        finding = _first(result)
        assert finding is not None
        assert finding.metadata["category"] == "subject_confusion"


class TestJwtSigTrueOnlyWrapper:
    def test_suppresses_when_sig_false(self):
        inner = JwtClaimConfusionStrategy()
        wrapper = JwtSigTrueOnlyWrapper(inner)
        primary = _make_result({**VALID_JWT, "signature_valid": False, "sub": "a"})
        reference = _make_result({**VALID_JWT, "signature_valid": False, "sub": "b"})
        finding = wrapper.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is None

    def test_fires_when_both_sig_true(self):
        inner = JwtClaimConfusionStrategy()
        wrapper = JwtSigTrueOnlyWrapper(inner)
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "sub": "admin-123"})
        result = wrapper.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        finding = _first(result)
        assert finding is not None
        assert finding.metadata["category"] == "subject_confusion"


class TestJwtAlgorithmDivergenceStrategy:
    def test_alg_divergence_with_gate(self):
        s = JwtAlgorithmDivergenceStrategy()
        # Input must contain "alg" bytes for gate to pass
        inp = Input(data=b'{"alg":"HS256"}')
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "effective_alg": "HS384"})
        result = s.compare(inp, primary, reference, ref_index=0)
        finding = _first(result)
        assert finding is not None
        assert finding.metadata["category"] == "algorithm_confusion"

    def test_skips_without_gate_bytes(self):
        s = JwtAlgorithmDivergenceStrategy()
        # Input without alg bytes - gate should block
        inp = Input(data=b"no-relevant-bytes")
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "effective_alg": "HS384"})
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is None


class TestJwtKeySourceDivergenceStrategy:
    def test_key_source_divergence_with_gate(self):
        s = JwtKeySourceDivergenceStrategy()
        inp = Input(data=b'{"jwk":{"kty":"oct"}}')
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "key_source": "embedded_jwk"})
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "key_confusion"


class TestJwtHeaderPolicyStrategy:
    def test_crit_processed_divergence(self):
        s = JwtHeaderPolicyStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "crit_processed": False})
        findings = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert findings is not None
        assert any(f.metadata["category"] == "header_policy_confusion" for f in findings)


class TestJwtTemporalStrategy:
    def test_temporal_divergence_with_gate(self):
        s = JwtTemporalConfusionStrategy()
        inp = Input(data=b'{"exp":12345}')
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "time_valid": False, "exp_state": "expired"})
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "temporal_confusion"

    def test_skips_without_temporal_gate(self):
        s = JwtTemporalConfusionStrategy()
        inp = Input(data=b"no-temporal-bytes")
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "time_valid": False})
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is None


class TestJwtDuplicateKeyStrategy:
    def test_duplicate_key_divergence(self):
        s = JwtDuplicateKeyStrategy()
        # Input must contain duplicate key indicators
        inp = Input(data=b'{"role":"user","role":"admin"}')
        primary = _make_result(VALID_JWT)
        reference = _make_result({
            **VALID_JWT,
            "duplicate_claim_keys": ["role"],
            "claim_parse_mode": "first_wins",
        })
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "duplicate_key_confusion"


class TestCrossConfigNoiseSuppression:
    """Regression: cross-config noise (HMAC-only vs RSA-only) must be suppressed."""

    def test_jsonwebtoken_rsa_error(self):
        """jsonwebtoken RSA target rejects HS256 with 'invalid algorithm'."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": "JsonWebTokenError: invalid algorithm",
        })
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_pyjwt_rsa_error(self):
        """PyJWT RSA target rejects HS256 with 'InvalidAlgorithmError'."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": "InvalidAlgorithmError: The specified alg value is not allowed",
        })
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_jwcrypto_rsa_error(self):
        """jwcrypto RSA target rejects HS256 with 'Algorithm not allowed'."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": 'InvalidJWSSignature: Verification failed for all signatures["Failed: [InvalidJWSOperation(\'Algorithm not allowed\')]"]',
        })
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_reverse_direction_suppressed(self):
        """RSA target accepts RS256, HMAC target rejects with algorithm error."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result({**VALID_JWT, "signature_valid": False,
                                "signature_error": "algorithm not supported"})
        reference = _make_result({**VALID_JWT, "effective_alg": "RS256",
                                  "header_alg": "RS256"})
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_not_suppressed_for_real_alg_confusion(self):
        """effective_alg != header_alg means real algorithm confusion — never suppress."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result({**VALID_JWT, "effective_alg": "none",
                                "header_alg": "HS256"})
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": "InvalidAlgorithmError: algorithm not allowed",
        })
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_not_suppressed_for_non_alg_error(self):
        """Non-algorithm errors (signature mismatch, format) pass through."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "signature_error": "InvalidSignatureError: Signature verification failed",
        })
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is not None

    def test_not_suppressed_when_no_signature_error(self):
        """No signature_error field at all — cannot determine if cross-config."""
        s = JwtSignatureBypassStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result({**VALID_JWT, "signature_valid": False})
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is not None


class TestDynamicKeyTrustSuppression:
    """Regression: dynamic_key_trust removed from single-target oracle."""

    @pytest.mark.parametrize("key_source", [
        "embedded_jwk", "jku", "x5u", "x5c", "header_jwk",
    ])
    def test_all_dynamic_key_sources_suppressed(self, key_source):
        """All key_source values must NOT produce findings in single-target oracle."""
        oracle = JwtOracle()
        data = {**VALID_JWT, "key_source": key_source}
        assert oracle.check(Input(data=b"jwt"), _make_result(data)) is None


class TestNestedPlainJwtBypassGate:
    """Regression: nested_plainjwt_bypass gate on inner_signature_valid."""

    def _base_data(self):
        return {
            **VALID_JWT,
            "token_type_expected": "nested_jws",
            "token_type_observed": "jwe",
            "nested_jwt": True,
            "inner_alg": "none",
        }

    def test_inner_sig_none_suppressed(self):
        """inner_signature_valid=None → target never tried → suppress."""
        oracle = JwtOracle()
        data = {**self._base_data(), "inner_signature_valid": None}
        finding = oracle.check(Input(data=b"jwt"), _make_result(data))
        # Falls through to token_type_confusion, NOT nested_plainjwt_bypass
        assert finding is not None
        assert finding.metadata["category"] == "token_type_confusion"

    def test_inner_sig_false_fires(self):
        """inner_signature_valid=False → target tried and failed → fire."""
        oracle = JwtOracle()
        data = {**self._base_data(), "inner_signature_valid": False}
        finding = oracle.check(Input(data=b"jwt"), _make_result(data))
        assert finding is not None
        assert finding.metadata["category"] == "nested_plainjwt_bypass"

    def test_inner_sig_true_no_finding(self):
        """inner_signature_valid=True → inner sig verified OK → no finding."""
        oracle = JwtOracle()
        data = {**self._base_data(), "inner_signature_valid": True}
        finding = oracle.check(Input(data=b"jwt"), _make_result(data))
        # Falls through to token_type_confusion (expected!=observed)
        assert finding is not None
        assert finding.metadata["category"] == "token_type_confusion"


class TestTypCtyNormalization:
    """Regression: typ/cty None≡'' prevents false divergences."""

    def test_none_vs_empty_suppressed(self):
        """typ=None vs typ='' should NOT fire."""
        s = JwtHeaderPolicyStrategy()
        primary = _make_result({**VALID_JWT, "typ": None})
        reference = _make_result({**VALID_JWT, "typ": ""})
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_cty_none_vs_empty_suppressed(self):
        """cty=None vs cty='' should NOT fire."""
        s = JwtHeaderPolicyStrategy()
        primary = _make_result({**VALID_JWT, "cty": None})
        reference = _make_result({**VALID_JWT, "cty": ""})
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_none_vs_jwt_fires(self):
        """typ=None vs typ='JWT' IS a real divergence."""
        s = JwtHeaderPolicyStrategy()
        primary = _make_result({**VALID_JWT, "typ": None})
        reference = _make_result({**VALID_JWT, "typ": "JWT"})
        findings = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert findings is not None
        assert any(f.metadata["category"] == "header_policy_confusion" for f in findings)

    def test_both_none_suppressed(self):
        """typ=None vs typ=None should NOT fire."""
        s = JwtHeaderPolicyStrategy()
        primary = _make_result({**VALID_JWT, "typ": None})
        reference = _make_result({**VALID_JWT, "typ": None})
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None


class TestGetJwtStrategies:
    def test_strategy_count(self):
        strategies = get_jwt_strategies()
        # 4 default (exit_code, status_code, timing, error_pattern)
        # + 10 JWT strategies = 14
        assert len(strategies) == 14

    def test_strategy_names(self):
        names = {s.name for s in get_jwt_strategies()}
        assert "output" not in names
        assert "exit_code" in names
        assert "jwt_bypass" in names
        assert "jwt_claim_confusion_sigtrue" in names
        assert "jwt_alg_divergence" in names
        assert "jwt_key_source" in names
        assert "jwt_header_policy_sigtrue" in names
        assert "jwt_temporal_sigtrue" in names
        assert "jwt_duplicate_keys" in names
        assert "jwt_claim_type_sigtrue" in names
        assert "jwt_zip_confusion_sigtrue" in names


class TestJwtClaimTypeStrategy:
    def test_type_divergence_detected(self):
        s = JwtClaimTypeStrategy()
        primary = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "string", "exp": "number"},
        })
        reference = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "null", "exp": "number"},
        })
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "claim_type_confusion"
        assert finding.metadata["field"] == "sub"
        assert finding.severity == Severity.CRITICAL

    def test_same_types_no_finding(self):
        s = JwtClaimTypeStrategy()
        primary = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "string", "exp": "number"},
        })
        reference = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "string", "exp": "number"},
        })
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_missing_field_no_finding(self):
        s = JwtClaimTypeStrategy()
        primary = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "string"},
        })
        reference = _make_result({
            **VALID_JWT,
            "claim_types": {"exp": "number"},
        })
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_exp_type_divergence(self):
        s = JwtClaimTypeStrategy()
        primary = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "string", "exp": "number"},
        })
        reference = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "string", "exp": "string"},
        })
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["field"] == "exp"
        assert finding.severity == Severity.HIGH

    def test_no_claim_types_field(self):
        s = JwtClaimTypeStrategy()
        primary = _make_result(VALID_JWT)
        reference = _make_result(VALID_JWT)
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_cross_language_type_aliases_suppressed(self):
        """string==str, number==int/float, boolean==bool — cross-language noise."""
        s = JwtClaimTypeStrategy()
        primary = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "string", "exp": "number", "role": "boolean"},
        })
        reference = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "str", "exp": "int", "role": "bool"},
        })
        assert s.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None

    def test_real_type_confusion_still_fires(self):
        """null vs string is a real type confusion, not a naming alias."""
        s = JwtClaimTypeStrategy()
        primary = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "str", "exp": "number"},
        })
        reference = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "null", "exp": "number"},
        })
        finding = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["field"] == "sub"

    def test_sigtrue_gate(self):
        wrapped = JwtSigTrueOnlyWrapper(JwtClaimTypeStrategy())
        primary = _make_result({
            **VALID_JWT,
            "signature_valid": False,
            "claim_types": {"sub": "string"},
        })
        reference = _make_result({
            **VALID_JWT,
            "claim_types": {"sub": "null"},
        })
        assert wrapped.compare(Input(data=b"jwt"), primary, reference, ref_index=0) is None


class TestDuplicateKeyGateAlg:
    def test_duplicate_alg_triggers_gate(self):
        s = JwtDuplicateKeyStrategy()
        # Input with duplicate alg
        inp = Input(data=b'eyJhbGciOiJIUzI1NiIsImFsZyI6Im5vbmUifQ.eyJzdWIiOiJ1c2VyIn0.')
        primary = _make_result({
            **VALID_JWT,
            "duplicate_header_keys": ["alg"],
        })
        reference = _make_result({
            **VALID_JWT,
            "duplicate_header_keys": [],
        })
        # The raw input contains "alg" twice (in the base64 decoded header)
        # We need raw bytes with literal "alg" appearing twice
        raw = b'"alg":"HS256","alg":"none"'
        inp2 = Input(data=raw)
        finding = s.compare(inp2, primary, reference, ref_index=0)
        assert finding is not None


class TestJwtZipConfusionStrategy:
    def test_zip_divergence_detected(self):
        s = JwtZipConfusionStrategy()
        inp = Input(data=b'eyJhbGciOiJIUzI1NiIsInppcCI6IkRFRiJ9."zip"')
        primary = _make_result({**VALID_JWT, "zip_processed": True})
        reference = _make_result({**VALID_JWT, "zip_processed": False})
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "zip_format_confusion"

    def test_no_zip_in_input_skips(self):
        s = JwtZipConfusionStrategy()
        inp = Input(data=b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig")
        primary = _make_result({**VALID_JWT, "zip_processed": True})
        reference = _make_result({**VALID_JWT, "zip_processed": False})
        assert s.compare(inp, primary, reference, ref_index=0) is None

    def test_same_zip_no_finding(self):
        s = JwtZipConfusionStrategy()
        inp = Input(data=b'"zip":"DEF"')
        primary = _make_result({**VALID_JWT, "zip_processed": True})
        reference = _make_result({**VALID_JWT, "zip_processed": True})
        assert s.compare(inp, primary, reference, ref_index=0) is None

    def test_sigtrue_gate(self):
        wrapped = JwtSigTrueOnlyWrapper(JwtZipConfusionStrategy())
        inp = Input(data=b'"zip":"DEF"')
        primary = _make_result({**VALID_JWT, "signature_valid": False, "zip_processed": True})
        reference = _make_result({**VALID_JWT, "zip_processed": False})
        assert wrapped.compare(inp, primary, reference, ref_index=0) is None


class TestHeaderPolicyB64Mode:
    def test_b64_mode_divergence(self):
        s = JwtHeaderPolicyStrategy()
        primary = _make_result({**VALID_JWT, "b64_mode": True})
        reference = _make_result({**VALID_JWT, "b64_mode": False})
        findings = s.compare(Input(data=b"jwt"), primary, reference, ref_index=0)
        assert findings is not None
        b64_finding = [f for f in findings if f.metadata["field"] == "b64_mode"]
        assert len(b64_finding) == 1
        assert b64_finding[0].metadata["category"] == "header_policy_confusion"
