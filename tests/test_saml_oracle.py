"""Tests for SAML oracle and differential strategies."""

import json
import pytest

from webfuzzer.fuzzer.protocols import ExecutionResult, Finding, Input, Severity
from webfuzzer.fuzzer.oracles.saml_oracle import SamlOracle, _parse_saml_output
from webfuzzer.fuzzer.oracles.saml_diff_strategy import (
    SamlDiffStrategy,
    SamlAlgorithmConfusionStrategy,
    SamlIssuerConfusionStrategy,
    get_saml_strategies,
)


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(
        exit_code=exit_code,
        stdout=json.dumps(data).encode(),
    )


VALID_SAML = {
    "signature_valid": True,
    "signature_error": None,
    "subject": "user@example.com",
    "subject_format": "emailAddress",
    "issuer": "https://idp.example.com",
    "audience": "https://sp.example.com",
    "attributes": {"role": "user"},
    "assertion_count": 1,
    "algorithms": {"signature": "rsa-sha256", "digest": "sha256"},
}


VALID_ADMIN = {
    **VALID_SAML,
    "subject": "admin@example.com",
    "attributes": {"role": "admin"},
}


INVALID_SAML = {
    **VALID_SAML,
    "signature_valid": False,
    "signature_error": "Digest mismatch",
}


class TestParseOutput:
    def test_valid_json(self):
        data = json.dumps(VALID_SAML).encode()
        result = _parse_saml_output(data)
        assert result is not None
        assert result["signature_valid"] is True

    def test_empty_bytes(self):
        assert _parse_saml_output(b"") is None

    def test_invalid_json(self):
        assert _parse_saml_output(b"not json") is None

    def test_unrelated_json(self):
        assert _parse_saml_output(b'{"foo": "bar"}') is None


class TestSamlOracle:
    @pytest.fixture
    def oracle(self):
        return SamlOracle()

    def test_name(self, oracle):
        assert oracle.name == "saml"

    def test_valid_signature_no_finding(self, oracle):
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(VALID_SAML)
        finding = oracle.check(inp, result)
        assert finding is None

    def test_unsigned_assertion_no_finding(self, oracle):
        """Invalid signature with subject extracted is by design — not a finding."""
        data = {**INVALID_SAML, "subject": "admin@example.com"}
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(data)
        finding = oracle.check(inp, result)
        assert finding is None

    def test_sig_accepted_multi_assertion(self, oracle):
        """Signature accepted with multiple assertions -> CRITICAL (XSW bypass)."""
        data = {**VALID_SAML, "assertion_count": 2}
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(data)
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "XSW bypass" in finding.title

    def test_multiple_assertions(self, oracle):
        """Multiple assertions with invalid sig -> HIGH (structural anomaly)."""
        data = {**INVALID_SAML, "assertion_count": 3}
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(data)
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "3" in finding.title

    def test_weak_algorithm(self, oracle):
        data = {**VALID_SAML, "algorithms": {"signature": "rsa-sha1", "digest": "sha1"}}
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(data)
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_exit_code_nonzero_ignored(self, oracle):
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(VALID_SAML, exit_code=1)
        assert oracle.check(inp, result) is None

    def test_no_subject_no_finding(self, oracle):
        data = {**INVALID_SAML, "subject": None}
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(data)
        assert oracle.check(inp, result) is None


class TestSamlDiffStrategy:
    @pytest.fixture
    def strategy(self):
        return SamlDiffStrategy()

    def test_name(self, strategy):
        assert strategy.name == "saml_bypass"

    def test_signature_bypass_detected(self, strategy):
        """One accepts, another rejects -> CRITICAL."""
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(INVALID_SAML)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "Signature Bypass" in finding.title

    def test_subject_confusion_detected(self, strategy):
        """Both accept but different NameID -> CRITICAL."""
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(VALID_ADMIN)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "Subject Confusion" in finding.title

    def test_attribute_confusion_detected(self, strategy):
        """Same subject, different attributes -> HIGH."""
        data_ref = {**VALID_SAML, "attributes": {"role": "admin"}}
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(data_ref)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "Attribute Confusion" in finding.title

    def test_assertion_count_divergence(self, strategy):
        data_ref = {**VALID_SAML, "assertion_count": 2}
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(data_ref)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_identical_results_no_finding(self, strategy):
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(VALID_SAML)
        assert strategy.compare(inp, primary, reference, ref_index=0) is None

    def test_both_reject_no_finding(self, strategy):
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(INVALID_SAML)
        reference = _make_result(INVALID_SAML)
        assert strategy.compare(inp, primary, reference, ref_index=0) is None

    def test_one_sided_accept(self, strategy):
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        ref_result = ExecutionResult(exit_code=1, stdout=b"", stderr=b"parse error")
        finding = strategy.compare(inp, primary, ref_result, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "One-Sided" in finding.title


class TestAlgorithmConfusion:
    def test_algo_mismatch(self):
        s = SamlAlgorithmConfusionStrategy()
        data_ref = {**VALID_SAML, "algorithms": {"signature": "rsa-sha1", "digest": "sha256"}}
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(data_ref)
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_same_algo_no_finding(self):
        s = SamlAlgorithmConfusionStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(VALID_SAML)
        assert s.compare(inp, primary, reference, ref_index=0) is None


class TestIssuerConfusion:
    def test_issuer_mismatch(self):
        s = SamlIssuerConfusionStrategy()
        data_ref = {**VALID_SAML, "issuer": "https://evil.com"}
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(data_ref)
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM

    def test_audience_mismatch(self):
        s = SamlIssuerConfusionStrategy()
        data_ref = {**VALID_SAML, "audience": "https://evil.com"}
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(data_ref)
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert "Audience" in finding.title


class TestGetSamlStrategies:
    def test_includes_default_and_saml_strategies(self):
        strategies = get_saml_strategies()
        # 5 default (exit_code, output, status_code, timing, error_pattern)
        # + 7 SAML (saml_bypass, saml_algorithm, saml_issuer, saml_encoding,
        #          saml_transform, saml_algo_downgrade, saml_keyinfo)
        assert len(strategies) == 12

    def test_strategy_names(self):
        strategies = get_saml_strategies()
        names = {s.name for s in strategies}
        # Must include both default and SAML-specific strategies
        assert "exit_code" in names, "ExitCodeStrategy missing from SAML strategies"
        assert "output" in names, "OutputStrategy missing from SAML strategies"
        assert "saml_bypass" in names
        assert "saml_algorithm" in names
        assert "saml_encoding" in names
        assert "saml_transform" in names

    def test_all_have_compare(self):
        for s in get_saml_strategies():
            assert hasattr(s, "compare")
            assert callable(s.compare)


# ── Regression tests for gating fixes ──────────────────────────


INVALID_DIFF_SUBJECT = {
    **INVALID_SAML,
    "subject": "evil@attacker.com",
    "assertion_count": 1,
}


class TestAssertionCountWithoutSignature:
    """Regression: assertion_count_divergence must fire WITHOUT signature_valid.

    Session 116 produced 0 differential findings because the
    (p_valid or r_valid) gate suppressed all assertion count
    differences from grammar-generated (unsigned) SAML inputs.
    """

    def test_count_divergence_both_sig_false(self):
        """Both reject sig but different counts -> HIGH finding."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result({**INVALID_SAML, "assertion_count": 1})
        reference = _make_result({**INVALID_SAML, "assertion_count": 2})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "assertion_count_divergence"

    def test_count_divergence_zero_vs_nonzero(self):
        """ref sees 0 assertions, primary sees 1 -> finding."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result({**INVALID_SAML, "assertion_count": 1})
        reference = _make_result({**INVALID_SAML, "assertion_count": 0})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "assertion_count_divergence"

    def test_count_both_zero_no_finding(self):
        """Both see 0 assertions -> no finding."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result({**INVALID_SAML, "assertion_count": 0})
        reference = _make_result({**INVALID_SAML, "assertion_count": 0})
        assert strategy.compare(inp, primary, reference, ref_index=0) is None


class TestSubjectExtractionDivergence:
    """Regression: subject differences must be detected even without valid sig.

    When parsers extract different NameIDs from the same XML
    (regardless of signature status), it indicates a structural
    parsing differential that is prerequisite for XSW attacks.
    """

    def test_different_subjects_sig_false(self):
        """Both sig=false but different subjects -> MEDIUM."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result({**INVALID_SAML, "subject": "user@example.com"})
        reference = _make_result(INVALID_DIFF_SUBJECT)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "subject_extraction_divergence"

    def test_same_subject_sig_false_no_finding(self):
        """Both sig=false and same subject -> no finding from subject check."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(INVALID_SAML)
        reference = _make_result(INVALID_SAML)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is None

    def test_subject_confusion_still_critical_when_both_valid(self):
        """Both sig=true + different subjects -> still CRITICAL (not MEDIUM)."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(VALID_ADMIN)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "subject_confusion"
