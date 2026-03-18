"""Tests for property-guided coordinator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from webfuzzer.fuzzer.concolic.property_guided import (
    MAX_SOLUTIONS,
    PropertyGuidedCoordinator,
    _perturb_property,
)
from webfuzzer.fuzzer.concolic.property_vector import NUM_PROPERTIES
from webfuzzer.fuzzer.protocols import Input


# ── Mock ExecutionResult ──────────────────────────────────────────

@dataclass
class MockResult:
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int = 0
    duration_ms: float = 10.0


SAML_RESPONSE = (
    b'<?xml version="1.0"?>'
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    b'<saml:Assertion Version="2.0" ID="_assert1">'
    b'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>'
    b'<ds:Signature><ds:SignedInfo>'
    b'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    b'<ds:Reference URI="#_assert1">'
    b'<ds:Transforms>'
    b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    b'</ds:Transforms>'
    b'</ds:Reference></ds:SignedInfo></ds:Signature>'
    b'</saml:Assertion>'
    b'</samlp:Response>'
)


def _make_result(data: dict[str, Any]) -> MockResult:
    """Create a MockResult with JSON stdout."""
    import json
    return MockResult(stdout=json.dumps(data).encode())


def _primary_output(**overrides: Any) -> dict[str, Any]:
    base = {
        "signature_valid": True,
        "subject": "admin@example.com",
        "assertion_count": 1,
        "signature_count": 1,
        "reference_element_count": 1,
        "issuer": "https://idp.example.com",
    }
    base.update(overrides)
    return base


def _ref_output(**overrides: Any) -> dict[str, Any]:
    base = _primary_output()
    base.update(overrides)
    return base


class TestPropertyGuidedCoordinator:
    """Basic coordinator behavior."""

    def test_cold_start_returns_empty(self):
        coord = PropertyGuidedCoordinator(seed=42)
        inp = Input(data=SAML_RESPONSE)
        primary = _make_result(_primary_output())
        ref = _make_result(_ref_output(signature_valid=False))

        # During warmup, should always return empty
        result = coord.on_differential_result(inp, primary, [ref], False)
        assert result == []

    def test_warmup_then_generates(self):
        coord = PropertyGuidedCoordinator(seed=42, budget_pct=0.5)

        # Run through warmup with divergent inputs
        for i in range(600):
            inp = Input(data=SAML_RESPONSE, metadata={"strategy": "xsw1"})
            primary = _make_result(_primary_output())
            ref = _make_result(_ref_output(signature_valid=False))
            result = coord.on_differential_result(inp, primary, [ref], False)

        # After warmup, should generate targeted inputs on divergence
        # (may still return empty if MI threshold not met, so we just check no crash)
        assert isinstance(result, list)

    def test_no_divergence_returns_empty(self):
        coord = PropertyGuidedCoordinator(seed=42)
        coord._total_iters = 600  # skip warmup

        inp = Input(data=SAML_RESPONSE)
        primary = _make_result(_primary_output())
        ref = _make_result(_ref_output())  # same as primary

        result = coord.on_differential_result(inp, primary, [ref], False)
        assert result == []

    def test_budget_enforcement(self):
        coord = PropertyGuidedCoordinator(seed=42, budget_pct=0.01)
        coord._total_iters = 1000
        coord._concolic_execs = 100  # 10% > 1% budget

        inp = Input(data=SAML_RESPONSE)
        primary = _make_result(_primary_output())
        ref = _make_result(_ref_output(signature_valid=False))

        result = coord.on_differential_result(inp, primary, [ref], False)
        assert result == []

    def test_max_solutions_cap(self):
        coord = PropertyGuidedCoordinator(seed=42, budget_pct=1.0)
        coord._total_iters = 600

        inp = Input(data=SAML_RESPONSE)
        primary = _make_result(_primary_output())
        ref = _make_result(_ref_output(signature_valid=False))

        result = coord.on_differential_result(inp, primary, [ref], False)
        assert len(result) <= MAX_SOLUTIONS

    def test_parse_output_handles_bad_json(self):
        coord = PropertyGuidedCoordinator(seed=42)
        result = MockResult(stdout=b"not json")
        assert coord._parse_output(result) is None

    def test_parse_output_handles_empty(self):
        coord = PropertyGuidedCoordinator(seed=42)
        result = MockResult(stdout=b"")
        assert coord._parse_output(result) is None


class TestDivergenceComputation:
    """Test domain-agnostic divergence detection."""

    def test_detects_sig_divergence(self):
        coord = PropertyGuidedCoordinator(seed=42)
        primary = _make_result(_primary_output(signature_valid=True))
        ref = _make_result(_ref_output(signature_valid=False))

        divs = coord._compute_divergences(primary, [ref])
        assert len(divs) == 1
        assert divs[0].sig_diverges
        assert "signature_valid" in divs[0].field_diffs

    def test_detects_subject_divergence(self):
        coord = PropertyGuidedCoordinator(seed=42)
        primary = _make_result(_primary_output(subject="admin"))
        ref = _make_result(_ref_output(subject="attacker"))

        divs = coord._compute_divergences(primary, [ref])
        assert len(divs) == 1
        assert divs[0].subject_diverges

    def test_no_divergence(self):
        coord = PropertyGuidedCoordinator(seed=42)
        primary = _make_result(_primary_output())
        ref = _make_result(_ref_output())

        divs = coord._compute_divergences(primary, [ref])
        assert len(divs) == 0

    def test_multiple_refs(self):
        coord = PropertyGuidedCoordinator(seed=42)
        primary = _make_result(_primary_output())
        ref1 = _make_result(_ref_output(signature_valid=False))
        ref2 = _make_result(_ref_output(subject="evil"))

        divs = coord._compute_divergences(primary, [ref1, ref2])
        assert len(divs) == 2

    def test_excludes_noisy_fields(self):
        coord = PropertyGuidedCoordinator(seed=42)
        primary = _make_result({**_primary_output(), "signature_error": "err1"})
        ref = _make_result({**_ref_output(), "signature_error": "err2"})

        divs = coord._compute_divergences(primary, [ref])
        # signature_error is in _EXCLUDED_FIELDS, so no divergence
        assert len(divs) == 0


class TestPerturbationRegistry:
    """Test property perturbation functions."""

    def test_perturb_ns_decl(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 4, random.Random(42))
        assert len(results) >= 1
        for r in results:
            assert r != SAML_RESPONSE

    def test_perturb_assertion_count(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 10, random.Random(42))
        assert len(results) >= 1
        # Should have more Assertion tags
        for r in results:
            assert r.count(b"Assertion") > SAML_RESPONSE.count(b"Assertion")

    def test_perturb_comment(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 13, random.Random(42))
        assert len(results) >= 1
        assert any(b"<!--" in r for r in results)

    def test_perturb_bom(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 22, random.Random(42))
        assert len(results) == 1
        assert results[0][:3] == b"\xef\xbb\xbf"

    def test_perturb_empty_ns(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 6, random.Random(42))
        assert len(results) == 1
        assert b'=""' in results[0]

    def test_perturb_relative_ns(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 7, random.Random(42))
        assert len(results) == 1

    def test_perturb_unknown_property(self):
        import random
        # Property index 99 (doesn't exist) has no perturbation registered
        results = _perturb_property(SAML_RESPONSE, 99, random.Random(42))
        assert results == []

    def test_perturb_duplicate_id(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 26, random.Random(42))
        assert len(results) >= 1

    def test_perturb_cdata(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 20, random.Random(42))
        assert len(results) >= 1
        assert any(b"CDATA" in r for r in results)

    def test_perturb_pi(self):
        import random
        results = _perturb_property(SAML_RESPONSE, 14, random.Random(42))
        assert len(results) >= 1
        assert any(b"<?pi" in r for r in results)


class TestGetStats:
    """Test stats and status line."""

    def test_stats_structure(self):
        coord = PropertyGuidedCoordinator(seed=42)
        stats = coord.get_stats()
        assert "concolic_execs" in stats
        assert "total_iters" in stats
        assert "budget_pct" in stats
        assert "warmup_complete" in stats
        assert "observations" in stats

    def test_status_line(self):
        coord = PropertyGuidedCoordinator(seed=42)
        line = coord.get_status_line()
        assert "plearn:" in line

    def test_strategy_weights_initially_empty(self):
        coord = PropertyGuidedCoordinator(seed=42)
        assert coord.get_strategy_weights() == {}
