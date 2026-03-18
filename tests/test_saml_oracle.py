"""Tests for SAML oracle and differential strategies."""

import json
import pytest

from webfuzzer.fuzzer.protocols import ExecutionResult, Finding, Input, Severity
from webfuzzer.fuzzer.oracles._saml_parsing import parse_saml_output as _parse_saml_output
from webfuzzer.fuzzer.oracles.saml_oracle import SamlOracle, SamlSigTrueOracle
from webfuzzer.fuzzer.oracles.saml_diff_strategy import (
    SamlDiffStrategy,
    SamlAlgorithmConfusionStrategy,
    SamlAlgorithmDowngradeStrategy,
    SamlIssuerConfusionStrategy,
    SamlKeyInfoPrecedenceStrategy,
    SamlReferenceScopeStrategy,
    get_saml_strategies,
    get_saml_sigtrue_strategies,
)


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(
        exit_code=exit_code,
        stdout=json.dumps(data).encode(),
    )


def _first(result):
    """Unwrap list or single Finding from compare() for test assertions."""
    if isinstance(result, list):
        return result[0]
    return result


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

    def test_reference_scope_mismatch(self, oracle):
        data = {
            **VALID_SAML,
            "reference_uri": "#signed-assertion",
            "assertion_id": "evil-assertion",
            "reference_matches_selected_assertion": False,
        }
        inp = Input(data=b"<saml>test</saml>")
        result = _make_result(data)
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "reference_scope_mismatch"

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


class TestSamlSigTrueOracle:
    def test_name(self):
        assert SamlSigTrueOracle().name == "saml_sigtrue"


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
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "Signature Bypass" in finding.title

    def test_subject_confusion_detected(self, strategy):
        """Both accept but different NameID -> CRITICAL."""
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(VALID_ADMIN)
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "Subject Confusion" in finding.title

    def test_attribute_confusion_detected(self, strategy):
        """Same subject, different attributes -> HIGH."""
        data_ref = {**VALID_SAML, "attributes": {"role": "admin"}}
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(data_ref)
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "Attribute Confusion" in finding.title

    def test_assertion_count_divergence(self, strategy):
        data_ref = {**VALID_SAML, "assertion_count": 2}
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(data_ref)
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
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
        finding = _first(strategy.compare(inp, primary, ref_result, ref_index=0))
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


class TestReferenceScopeStrategy:
    def test_reference_scope_divergence(self):
        s = SamlReferenceScopeStrategy()
        primary = _make_result({
            **VALID_SAML,
            "reference_uri": "#assertion-a",
            "assertion_id": "assertion-a",
            "reference_matches_selected_assertion": True,
        })
        reference = _make_result({
            **VALID_SAML,
            "reference_uri": "#assertion-a",
            "assertion_id": "assertion-b",
            "reference_matches_selected_assertion": False,
        })
        inp = Input(data=b"<saml>test</saml>")
        finding = s.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "reference_scope_divergence"

    def test_same_reference_scope_no_finding(self):
        s = SamlReferenceScopeStrategy()
        primary = _make_result({
            **VALID_SAML,
            "reference_uri": "#assertion-a",
            "assertion_id": "assertion-a",
            "reference_matches_selected_assertion": True,
        })
        reference = _make_result({
            **VALID_SAML,
            "reference_uri": "#assertion-a",
            "assertion_id": "assertion-a",
            "reference_matches_selected_assertion": True,
        })
        inp = Input(data=b"<saml>test</saml>")
        assert s.compare(inp, primary, reference, ref_index=0) is None


class TestAssertionSelectionFallback:
    def test_uses_selected_assertion_index_when_ids_missing(self):
        s = get_saml_strategies()
        selection = next(strategy for strategy in s if strategy.name == "saml_assertion_selection")
        primary = _make_result({
            **VALID_SAML,
            "assertion_id": None,
            "selected_assertion_index": 0,
        })
        reference = _make_result({
            **VALID_SAML,
            "assertion_id": None,
            "selected_assertion_index": 1,
        })
        inp = Input(data=b"<saml>test</saml>")
        finding = selection.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["primary_selected_assertion"] == "index:0"
        assert finding.metadata["ref_selected_assertion"] == "index:1"


class TestGetSamlStrategies:
    def test_includes_default_and_saml_strategies(self):
        strategies = get_saml_strategies()
        # 4 default (exit_code, status_code, timing, error_pattern)
        # + 10 SAML (saml_bypass, saml_algorithm, saml_issuer, saml_encoding,
        #           saml_transform, saml_algo_downgrade, saml_keyinfo,
        #           saml_assertion_selection, saml_reference_scope, saml_extraction)
        assert len(strategies) == 14

    def test_strategy_names(self):
        strategies = get_saml_strategies()
        names = {s.name for s in strategies}
        # Must include both default and SAML-specific strategies
        assert "exit_code" in names, "ExitCodeStrategy missing from SAML strategies"
        assert "output" not in names, "OutputStrategy should be excluded from SAML strategies"
        assert "saml_bypass" in names
        assert "saml_algorithm" in names
        assert "saml_encoding" in names
        assert "saml_transform" in names
        assert "saml_reference_scope" in names

    def test_all_have_compare(self):
        for s in get_saml_strategies():
            assert hasattr(s, "compare")
            assert callable(s.compare)


class TestGetSamlSigTrueStrategies:
    def test_includes_only_sigtrue_campaign_strategies(self):
        strategies = get_saml_sigtrue_strategies()
        assert len(strategies) == 10

    def test_strategy_names(self):
        names = {s.name for s in get_saml_sigtrue_strategies()}
        assert "output" not in names
        assert "exit_code" in names
        assert "saml_bypass_sigtrue" in names
        assert "saml_algorithm_sigtrue" in names
        assert "saml_issuer_sigtrue" in names
        assert "saml_assertion_selection_sigtrue" in names
        assert "saml_reference_scope_sigtrue" in names
        assert "saml_extraction_sigtrue" in names

    def test_sigtrue_subject_confusion_requires_both_valid(self):
        strategy = next(s for s in get_saml_sigtrue_strategies() if s.name == "saml_bypass_sigtrue")
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(VALID_ADMIN)
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
        assert finding is not None
        assert finding.metadata["category"] == "subject_confusion"
        assert finding.metadata["sigtrue_only"] is True
        assert finding.metadata["campaign"] == "saml_sigtrue"

    def test_sigtrue_subject_confusion_skips_sig_false(self):
        strategy = next(s for s in get_saml_sigtrue_strategies() if s.name == "saml_bypass_sigtrue")
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALID_SAML)
        reference = _make_result(INVALID_DIFF_SUBJECT)
        assert strategy.compare(inp, primary, reference, ref_index=0) is None


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
        """Both reject sig but different counts -> MEDIUM finding (downgraded)."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result({**INVALID_SAML, "assertion_count": 1})
        reference = _make_result({**INVALID_SAML, "assertion_count": 2})
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "assertion_count_divergence"

    def test_count_divergence_zero_vs_nonzero(self):
        """ref sees 0 assertions, primary sees 1 -> finding."""
        strategy = SamlDiffStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result({**INVALID_SAML, "assertion_count": 1})
        reference = _make_result({**INVALID_SAML, "assertion_count": 0})
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
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
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
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
        finding = _first(strategy.compare(inp, primary, reference, ref_index=0))
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "subject_confusion"


# ── Regression: HMAC confusion false-positive guard ─────────────


class TestHmacConfusionFalsePositive:
    """Regression: HMAC indicator in evil assertion should not trigger
    algo_downgrade_hmac_confusion when the accepting library validates
    a different assertion using RSA-SHA256.

    Root cause from Session 127 Batch 1: XSW input contains HMAC in
    evil assertion's SignatureMethod, but accepting library validates
    the legitimate RSA-signed assertion.  The oracle checked raw bytes
    for 'hmac-sha' and incorrectly flagged HMAC confusion.
    """

    def test_hmac_in_input_but_accepting_uses_rsa(self):
        """HMAC string in input, accepting library reports rsa-sha256 -> None."""
        strategy = SamlAlgorithmDowngradeStrategy()
        # Input contains hmac-sha256 somewhere (e.g. in evil assertion)
        inp = Input(data=b'<SignatureMethod Algorithm="hmac-sha256"/><saml/>')
        # Primary accepts with RSA (validates different assertion)
        primary = _make_result({
            **VALID_SAML,
            "algorithms": {"signature": "rsa-sha256", "digest": "sha256"},
        })
        # Reference rejects
        reference = _make_result(INVALID_SAML)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is None, "Should not flag HMAC confusion when accepting lib uses RSA"

    def test_hmac_accepted_by_library_is_still_critical(self):
        """Library actually reports HMAC algorithm -> CRITICAL finding."""
        strategy = SamlAlgorithmDowngradeStrategy()
        inp = Input(data=b'<SignatureMethod Algorithm="hmac-sha256"/><saml/>')
        # Primary accepts and reports using HMAC
        primary = _make_result({
            **VALID_SAML,
            "algorithms": {"signature": "hmac-sha256", "digest": "sha256"},
        })
        reference = _make_result(INVALID_SAML)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "algo_downgrade_hmac_confusion"

    def test_hmac_in_input_ref_accepts_with_rsa(self):
        """Ref accepts with RSA while HMAC in input -> None (ref side)."""
        strategy = SamlAlgorithmDowngradeStrategy()
        inp = Input(data=b'<SignatureMethod Algorithm="hmac-sha1"/><saml/>')
        primary = _make_result(INVALID_SAML)
        reference = _make_result({
            **VALID_SAML,
            "algorithms": {"signature": "rsa-sha256", "digest": "sha256"},
        })
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is None

    def test_sha1_downgrade_unaffected_by_hmac_guard(self):
        """SHA-1 downgrade is not HMAC, so the HMAC guard does not apply."""
        strategy = SamlAlgorithmDowngradeStrategy()
        inp = Input(data=b'<SignatureMethod Algorithm="rsa-sha1"/><saml/>')
        primary = _make_result({
            **VALID_SAML,
            "algorithms": {"signature": "rsa-sha1", "digest": "sha1"},
        })
        reference = _make_result(INVALID_SAML)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "algo_downgrade_sha1_downgrade"

    def test_hmac_no_algo_reported_still_fires(self):
        """Accepting library reports no algorithm -> conservatively flag."""
        strategy = SamlAlgorithmDowngradeStrategy()
        inp = Input(data=b'<SignatureMethod Algorithm="hmac-sha256"/><saml/>')
        primary = _make_result({
            **VALID_SAML,
            "algorithms": {},
        })
        reference = _make_result(INVALID_SAML)
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None, "No reported algo -> conservatively keep finding"
        assert finding.severity == Severity.CRITICAL


# ── Regression: KeyInfo precedence false-positive guard ──────────


class TestKeyInfoPrecedenceFalsePositive:
    """Regression: KeyInfo manipulation in multi-assertion XSW input
    should not trigger keyinfo_precedence when the accepting library
    validates a different assertion with proper KeyInfo.

    Also, single-assertion KeyInfo manipulation acceptance proves the
    library uses pre-configured cert (safe behavior), so severity
    should be HIGH not CRITICAL.

    Root cause from Session 127 Batch 1: PoC confirmed all 9 libraries
    use pre-configured IdP cert.  Fuzzer mutations only corrupt KeyInfo
    (AAAA, empty, remove) without providing a working attacker key.
    """

    def test_multi_assertion_keyinfo_returns_none(self):
        """Multi-assertion + KeyInfo manipulation -> None (XSW scope)."""
        strategy = SamlKeyInfoPrecedenceStrategy()
        inp = Input(data=b'<ds:KeyInfo/><ds:Signature>x</ds:Signature>')
        primary = _make_result({
            **VALID_SAML,
            "assertion_count": 2,
        })
        reference = _make_result({
            **INVALID_SAML,
            "assertion_count": 2,
        })
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is None, "Multi-assertion KeyInfo should be handled by SamlDiffStrategy"

    def test_multi_assertion_one_side_multiple(self):
        """One side sees 2 assertions -> still None."""
        strategy = SamlKeyInfoPrecedenceStrategy()
        inp = Input(data=b'<ds:KeyInfo/><ds:Signature>x</ds:Signature>')
        primary = _make_result({
            **VALID_SAML,
            "assertion_count": 1,
        })
        reference = _make_result({
            **INVALID_SAML,
            "assertion_count": 2,
        })
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is None

    def test_single_assertion_keyinfo_is_high_not_critical(self):
        """Single-assertion with manipulated KeyInfo -> HIGH (not CRITICAL)."""
        strategy = SamlKeyInfoPrecedenceStrategy()
        inp = Input(data=b'<ds:KeyInfo/><ds:Signature>x</ds:Signature>')
        primary = _make_result({
            **VALID_SAML,
            "assertion_count": 1,
        })
        reference = _make_result({
            **INVALID_SAML,
            "assertion_count": 1,
        })
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "keyinfo_precedence"
        assert finding.metadata["keyinfo_behavior"] == "ignores_keyinfo"

    def test_no_keyinfo_single_assertion(self):
        """Signature present but no KeyInfo at all, single assertion."""
        strategy = SamlKeyInfoPrecedenceStrategy()
        inp = Input(data=b'<ds:Signature><ds:SignedInfo/></ds:Signature>')
        primary = _make_result({**VALID_SAML, "assertion_count": 1})
        reference = _make_result({**INVALID_SAML, "assertion_count": 1})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["no_keyinfo"] is True

    def test_both_accept_no_finding(self):
        """Both accept with manipulated KeyInfo -> no finding."""
        strategy = SamlKeyInfoPrecedenceStrategy()
        inp = Input(data=b'<ds:KeyInfo/><ds:Signature>x</ds:Signature>')
        primary = _make_result({**VALID_SAML, "assertion_count": 1})
        reference = _make_result({**VALID_SAML, "assertion_count": 1})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is None
