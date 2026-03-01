"""Tests for the SAML taxonomy-driven mutator."""

import pytest

from webfuzzer.fuzzer.mutators.saml_mutator import (
    SamlMutator,
    EVIL_NAMEIDS,
    XSW_ASSERTION_TEMPLATE,
    _make_evil_assertion,
    _find_element_span,
    _RE_ASSERTION_OPEN,
    _RE_ASSERTION_CLOSE,
    _RE_NAMEID,
    MAX_OUTPUT_SIZE,
)
from webfuzzer.fuzzer.protocols import Input


SAMPLE_SAML = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
    b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    b' ID="_resp_001" Version="2.0" IssueInstant="2025-06-01T00:00:00Z"'
    b' Destination="https://sp.example.com/acs">\n'
    b"<saml:Issuer>https://idp.example.com</saml:Issuer>\n"
    b"<samlp:Status><samlp:StatusCode"
    b' Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
    b"</samlp:Status>\n"
    b'<saml:Assertion Version="2.0" ID="_assert_001"'
    b' IssueInstant="2025-06-01T00:00:00Z">\n'
    b"<saml:Issuer>https://idp.example.com</saml:Issuer>\n"
    b"<saml:Subject>\n"
    b'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
    b"user@example.com</saml:NameID>\n"
    b"</saml:Subject>\n"
    b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">\n'
    b"<ds:SignedInfo>\n"
    b'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n'
    b'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>\n'
    b'<ds:Reference URI="#_assert_001">\n'
    b"<ds:Transforms>\n"
    b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>\n'
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>\n'
    b"</ds:Transforms>\n"
    b'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>\n'
    b"<ds:DigestValue>abc123digest==</ds:DigestValue>\n"
    b"</ds:Reference>\n"
    b"</ds:SignedInfo>\n"
    b"<ds:SignatureValue>fakesig==</ds:SignatureValue>\n"
    b"<ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC...</ds:X509Certificate>"
    b"</ds:X509Data></ds:KeyInfo>\n"
    b"</ds:Signature>\n"
    b"<saml:Conditions"
    b' NotBefore="2025-06-01T00:00:00Z"'
    b' NotOnOrAfter="2025-06-01T01:00:00Z">\n'
    b"<saml:AudienceRestriction>\n"
    b"<saml:Audience>https://sp.example.com</saml:Audience>\n"
    b"</saml:AudienceRestriction>\n"
    b"</saml:Conditions>\n"
    b"</saml:Assertion>\n"
    b"</samlp:Response>\n"
)


@pytest.fixture
def mutator():
    return SamlMutator(seed=42)


class TestSamlMutator:
    def test_name(self, mutator):
        assert mutator.name == "saml"

    def test_mutate_returns_input(self, mutator):
        inp = Input(data=SAMPLE_SAML)
        result = mutator.mutate(inp, [])
        assert isinstance(result, Input)
        assert len(result.data) > 0

    def test_mutate_modifies_input(self, mutator):
        """Mutation should differ from original (at least sometimes)."""
        inp = Input(data=SAMPLE_SAML)
        different = False
        for _ in range(20):
            result = mutator.mutate(inp, [])
            if result.data != SAMPLE_SAML:
                different = True
                break
        assert different, "20 mutations produced no change"

    def test_mutate_respects_max_size(self, mutator):
        inp = Input(data=SAMPLE_SAML)
        for _ in range(50):
            result = mutator.mutate(inp, [])
            assert len(result.data) <= MAX_OUTPUT_SIZE

    def test_strategy_count(self, mutator):
        assert len(mutator._strategies) == 55
        assert len(mutator._weights) == 55

    def test_weights_positive(self, mutator):
        for w in mutator._weights:
            assert w > 0

    def test_evil_assertion_has_nameid(self):
        import random
        rng = random.Random(42)
        evil = _make_evil_assertion(rng)
        assert b"NameID" in evil
        has_evil_name = any(name in evil for name in EVIL_NAMEIDS)
        assert has_evil_name, "Evil assertion missing evil NameID"

    def test_find_element_span(self):
        span = _find_element_span(
            SAMPLE_SAML, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE
        )
        assert span is not None
        start, end = span
        assert start < end
        segment = SAMPLE_SAML[start:end]
        assert b"<saml:Assertion" in segment
        assert b"</saml:Assertion>" in segment

    def test_xsw_strategies_inject_evil(self, mutator):
        """XSW strategies should inject evil assertion content."""
        inp = Input(data=SAMPLE_SAML)
        xsw_found = False
        for _ in range(100):
            result = mutator.mutate(inp, [])
            if b"_evil_" in result.data or b"admin@example.com" in result.data:
                xsw_found = True
                break
        assert xsw_found, "No XSW injection detected in 100 mutations"

    def test_nameid_spoof_present(self, mutator):
        """NameID spoof strategy should replace NameID value."""
        inp = Input(data=SAMPLE_SAML)
        spoofed = False
        for _ in range(200):
            result = mutator.mutate(inp, [])
            if b"user@example.com" not in result.data and _RE_NAMEID.search(result.data):
                spoofed = True
                break
        assert spoofed, "No NameID spoof detected in 200 mutations"

    def test_diverse_strategies(self, mutator):
        """Multiple different strategy categories should fire."""
        inp = Input(data=SAMPLE_SAML)
        seen_xsw = False
        seen_comment = False
        seen_strip = False
        for _ in range(200):
            result = mutator.mutate(inp, [])
            d = result.data
            if b"_evil_" in d:
                seen_xsw = True
            if b"<!--" in d and b"<!--" not in SAMPLE_SAML:
                seen_comment = True
            if b"<ds:Signature" not in d:
                seen_strip = True
        assert seen_xsw, "XSW strategy never fired"
        # At least one other category should fire too
        assert seen_comment or seen_strip, "Only XSW strategies observed"
