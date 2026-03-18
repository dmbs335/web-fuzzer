"""Tests for validator-focused SAML differential strategies."""

from __future__ import annotations

import json

from webfuzzer.fuzzer.oracles.saml_oracle import SamlValidatorOracle
from webfuzzer.fuzzer.oracles.saml_validator_diff_strategy import (
    SamlValidatorAcceptRejectStrategy,
    SamlValidatorC14NStrategy,
    SamlValidatorDigestStrategy,
    SamlValidatorReferenceTargetStrategy,
    SamlValidatorTransformStrategy,
    get_saml_validator_strategies,
)
from webfuzzer.fuzzer.protocols import ExecutionResult, Input, Severity


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(exit_code=exit_code, stdout=json.dumps(data).encode())


VALIDATOR_BASE = {
    "signature_valid": True,
    "signature_error": None,
    "validated_reference_uri": "#assertion-a",
    "validated_node_id": "assertion-a",
    "validated_node_tag": "Assertion",
    "resolved_id_attribute": "ID",
    "id_resolution_mode": "reference_uri",
    "transform_chain": [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        "http://www.w3.org/2001/10/xml-exc-c14n#",
    ],
    "c14n_method": "http://www.w3.org/2001/10/xml-exc-c14n#",
    "signature_method": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "digest_method": "http://www.w3.org/2001/04/xmlenc#sha256",
    "digest_input_hash": "aaaa1111bbbb2222",
    "signed_info_hash": "cccc3333dddd4444",
    "key_source": "configured_cert",
    "keyinfo_type": "x509data",
}


class TestSamlValidatorOracle:
    def test_name(self):
        assert SamlValidatorOracle().name == "saml_validator"


class TestSamlValidatorStrategies:
    def test_accept_reject(self):
        strategy = SamlValidatorAcceptRejectStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALIDATOR_BASE)
        reference = _make_result({**VALIDATOR_BASE, "signature_valid": False, "signature_error": "Digest mismatch"})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "validator_accept_reject"

    def test_reference_target_divergence(self):
        strategy = SamlValidatorReferenceTargetStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALIDATOR_BASE)
        reference = _make_result({**VALIDATOR_BASE, "validated_node_id": "assertion-b"})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "validator_reference_target_divergence"

    def test_digest_divergence(self):
        strategy = SamlValidatorDigestStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALIDATOR_BASE)
        reference = _make_result({**VALIDATOR_BASE, "digest_input_hash": "ffffeeee11112222"})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "validator_digest_input_divergence"

    def test_c14n_divergence(self):
        strategy = SamlValidatorC14NStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALIDATOR_BASE)
        reference = _make_result({**VALIDATOR_BASE, "signed_info_hash": "9999888877776666"})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "validator_c14n_divergence"

    def test_transform_divergence(self):
        strategy = SamlValidatorTransformStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALIDATOR_BASE)
        reference = _make_result({**VALIDATOR_BASE, "resolved_id_attribute": "xml:id"})
        finding = strategy.compare(inp, primary, reference, ref_index=0)
        assert finding is not None
        assert finding.metadata["category"] == "validator_id_resolution_divergence"

    def test_requires_sig_true_on_both_sides(self):
        strategy = SamlValidatorDigestStrategy()
        inp = Input(data=b"<saml>test</saml>")
        primary = _make_result(VALIDATOR_BASE)
        reference = _make_result({**VALIDATOR_BASE, "signature_valid": False, "digest_input_hash": "ffff"})
        assert strategy.compare(inp, primary, reference, ref_index=0) is None


class TestGetSamlValidatorStrategies:
    def test_strategy_names(self):
        names = {s.name for s in get_saml_validator_strategies()}
        assert "output" not in names
        assert "exit_code" in names
        assert "saml_validator_accept" in names
        assert "saml_validator_reference" in names
        assert "saml_validator_digest" in names
        assert "saml_validator_c14n" in names
        assert "saml_validator_transform" in names
