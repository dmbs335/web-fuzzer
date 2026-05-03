"""Tests for the SAML taxonomy-driven mutator."""

import os

import pytest

from webfuzzer.fuzzer.mutators.saml_mutator import (
    SamlMutator,
    EVIL_NAMEIDS,
    XSW_ASSERTION_TEMPLATE,
    _make_evil_assertion,
    _find_element_span,
    _resign_assertion_bytes,
    _RESIGN_ACTION,
    _RE_ASSERTION_OPEN,
    _RE_ASSERTION_CLOSE,
    _RE_NAMEID,
    MAX_OUTPUT_SIZE,
)
from webfuzzer.fuzzer.protocols import Input

_FIXTURES_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "targets", "saml_fixtures",
)
_HAS_FIXTURES = os.path.isfile(os.path.join(_FIXTURES_DIR, "idp_key.pem"))

# Try to import signxml for resign tests
try:
    import signxml  # noqa: F401
    _HAS_SIGNXML = True
except ImportError:
    _HAS_SIGNXML = False

_can_resign = _HAS_FIXTURES and _HAS_SIGNXML


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
        assert len(mutator._strategies) == 102
        assert len(mutator._weights) == 102

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

    def test_metadata_has_resigned_field(self, mutator):
        """Every mutation should include 'resigned' in metadata."""
        inp = Input(data=SAMPLE_SAML)
        for _ in range(20):
            result = mutator.mutate(inp, [])
            assert "resigned" in result.metadata

    def test_resign_groups_disjoint(self, mutator):
        """_needs_resign and _blocks_resign must not overlap."""
        overlap = mutator._needs_resign & mutator._blocks_resign
        assert not overlap, f"Overlapping strategy indices: {overlap}"

    def test_resign_indices_in_range(self, mutator):
        """All resign indices must be valid strategy indices."""
        total = len(mutator._strategies)
        for idx in mutator._needs_resign | mutator._blocks_resign:
            assert 0 <= idx < total, f"Index {idx} out of range"

    def test_resign_action_names_exist(self, mutator):
        """Every name in _RESIGN_ACTION must correspond to an actual strategy."""
        strategy_names = set(mutator._strategy_names)
        for name in _RESIGN_ACTION:
            assert name in strategy_names, (
                f"_RESIGN_ACTION references '{name}' but no such strategy exists"
            )

    def test_xsw_indices_cover_s1(self, mutator):
        """XSW indices should include S1 group (first 8 strategies)."""
        s1_indices = set(range(8))
        assert s1_indices.issubset(mutator._xsw_indices)


@pytest.mark.skipif(not _can_resign, reason="signxml or IdP fixtures unavailable")
class TestResigning:
    """Tests for post-mutation re-signing infrastructure."""

    @pytest.fixture(autouse=True)
    def _reset_signer_cache(self):
        """Reset module-level signer cache between tests."""
        import webfuzzer.fuzzer.mutators.saml_mutator as mod
        mod._resign_key = None
        mod._resign_cert = None
        mod._resign_signer = None
        mod._resign_init_failed = False
        yield

    def _make_signed_sample(self) -> bytes:
        """Build a properly signed SAML Response for resign tests."""
        from lxml import etree
        from signxml import XMLSigner
        from signxml.algorithms import (
            CanonicalizationMethod,
            DigestAlgorithm,
            SignatureConstructionMethod,
            SignatureMethod,
        )

        SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
        SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"

        with open(os.path.join(_FIXTURES_DIR, "idp_key.pem"), "rb") as f:
            key_pem = f.read()
        with open(os.path.join(_FIXTURES_DIR, "idp_cert.pem"), "rb") as f:
            cert_pem = f.read()

        resp = etree.Element(
            f"{{{SAMLP_NS}}}Response",
            nsmap={"samlp": SAMLP_NS, "saml": SAML_NS},
        )
        resp.set("ID", "_resp_test")
        resp.set("Version", "2.0")

        iss = etree.SubElement(resp, f"{{{SAML_NS}}}Issuer")
        iss.text = "https://idp.example.com"

        status = etree.SubElement(resp, f"{{{SAMLP_NS}}}Status")
        sc = etree.SubElement(status, f"{{{SAMLP_NS}}}StatusCode")
        sc.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

        assertion = etree.SubElement(resp, f"{{{SAML_NS}}}Assertion")
        assertion.set("Version", "2.0")
        assertion.set("ID", "_assert_test")
        assertion.set("IssueInstant", "2025-06-01T00:00:00Z")

        iss2 = etree.SubElement(assertion, f"{{{SAML_NS}}}Issuer")
        iss2.text = "https://idp.example.com"

        subject = etree.SubElement(assertion, f"{{{SAML_NS}}}Subject")
        nameid = etree.SubElement(subject, f"{{{SAML_NS}}}NameID")
        nameid.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        nameid.text = "user@example.com"

        conditions = etree.SubElement(assertion, f"{{{SAML_NS}}}Conditions")
        conditions.set("NotBefore", "2025-06-01T00:00:00Z")
        conditions.set("NotOnOrAfter", "2099-12-31T23:59:59Z")
        aud_r = etree.SubElement(conditions, f"{{{SAML_NS}}}AudienceRestriction")
        aud = etree.SubElement(aud_r, f"{{{SAML_NS}}}Audience")
        aud.text = "https://sp.example.com"

        signer = XMLSigner(
            method=SignatureConstructionMethod.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
            c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
        )
        signed = signer.sign(assertion, key=key_pem, cert=cert_pem)

        parent = assertion.getparent()
        idx = list(parent).index(assertion)
        parent.remove(assertion)
        parent.insert(idx, signed)

        return etree.tostring(resp, xml_declaration=True, encoding="UTF-8")

    def test_resign_produces_valid_signature(self):
        """Re-signing a modified NameID should produce a verifiable signature."""
        from lxml import etree
        from signxml import XMLVerifier

        signed_xml = self._make_signed_sample()
        assert b"user@example.com" in signed_xml

        # Mutate: replace NameID (Group B strategy #36 equivalent)
        mutated = signed_xml.replace(b"user@example.com", b"admin@example.com")
        assert b"admin@example.com" in mutated

        # Re-sign
        resigned = _resign_assertion_bytes(mutated)
        assert resigned is not None
        assert b"admin@example.com" in resigned

        # Verify signature is valid
        with open(os.path.join(_FIXTURES_DIR, "idp_cert.pem"), "rb") as f:
            cert = f.read()
        root = etree.fromstring(resigned)
        assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        # Should not raise
        XMLVerifier().verify(assertion, x509_cert=cert)

    def test_resign_returns_none_on_garbage(self):
        """Re-signing garbage bytes should return None, not crash."""
        result = _resign_assertion_bytes(b"this is not xml at all")
        assert result is None

    def test_resign_returns_none_on_no_assertion(self):
        """Re-signing XML without Assertion should return None."""
        result = _resign_assertion_bytes(
            b'<?xml version="1.0"?><root><child/></root>'
        )
        assert result is None

    def test_mutate_group_b_produces_resigned(self):
        """Mutations applying only Group B strategies should be re-signed."""
        signed_xml = self._make_signed_sample()
        # Use a seed that reliably produces a Group B strategy
        # Run many mutations and check that at least some get resigned
        mutator = SamlMutator(seed=1)
        inp = Input(data=signed_xml)
        resigned_count = 0
        for _ in range(200):
            result = mutator.mutate(inp, [])
            if result.metadata.get("resigned"):
                resigned_count += 1
        assert resigned_count > 0, (
            "No re-signed mutations in 200 iterations; "
            "Group B strategies should trigger re-signing"
        )

    def test_mutate_group_a_not_resigned(self):
        """Mutations applying only Group A strategies should NOT be re-signed."""
        signed_xml = self._make_signed_sample()
        mutator = SamlMutator(seed=42)
        inp = Input(data=signed_xml)
        # Collect mutations that had only Group A strategies
        group_a_not_resigned = 0
        for _ in range(200):
            result = mutator.mutate(inp, [])
            strategies = result.metadata.get("strategies", [])
            # Map strategy names back to indices
            name_to_idx = {fn.__name__.lstrip("_"): i
                           for i, fn in enumerate(mutator._strategies)}
            indices = {name_to_idx.get(s, -1) for s in strategies}
            has_needs = bool(indices & mutator._needs_resign)
            has_blocks = bool(indices & mutator._blocks_resign)
            if has_blocks and not has_needs:
                assert not result.metadata.get("resigned"), (
                    f"Group A-only mutation should not be resigned: {strategies}"
                )
                group_a_not_resigned += 1
        assert group_a_not_resigned > 0, "No pure Group A mutations observed"

    def test_resigned_metadata_tracks_correctly(self):
        """The 'resigned' metadata field should reflect actual re-signing."""
        signed_xml = self._make_signed_sample()
        mutator = SamlMutator(seed=7)
        inp = Input(data=signed_xml)
        for _ in range(100):
            result = mutator.mutate(inp, [])
            assert isinstance(result.metadata.get("resigned"), bool)

    def test_resign_finds_referenced_assertion(self):
        """Re-sign should follow Reference URI to find the correct assertion."""
        from lxml import etree

        signed_xml = self._make_signed_sample()
        root = etree.fromstring(signed_xml)
        SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

        # Insert evil assertion BEFORE the signed one (XSW1 pattern)
        evil = etree.SubElement(root, f"{{{SAML}}}Assertion")
        evil.set("Version", "2.0")
        evil.set("ID", "_evil_first")
        iss = etree.SubElement(evil, f"{{{SAML}}}Issuer")
        iss.text = "https://evil.com"
        subj = etree.SubElement(evil, f"{{{SAML}}}Subject")
        nid = etree.SubElement(subj, f"{{{SAML}}}NameID")
        nid.text = "attacker@evil.com"

        # Move evil to index 0 (before original assertion)
        root.remove(evil)
        root.insert(0, evil)

        xsw_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8")

        # Re-sign should find _assert_test via Reference URI, not evil_first
        resigned = _resign_assertion_bytes(xsw_xml)
        assert resigned is not None

        # Verify: the signed assertion should be _assert_test
        re_root = etree.fromstring(resigned)
        DS = "http://www.w3.org/2000/09/xmldsig#"
        refs = list(re_root.iter(f"{{{DS}}}Reference"))
        assert len(refs) > 0
        ref_uri = refs[0].get("URI", "")
        assert ref_uri == "#_assert_test", f"Expected #_assert_test, got {ref_uri}"

        # Evil assertion should still be unsigned
        assertions = re_root.findall(f".//{{{SAML}}}Assertion")
        assert len(assertions) >= 2
        evil_a = [a for a in assertions if a.get("ID") == "_evil_first"]
        assert len(evil_a) == 1
        evil_sigs = evil_a[0].findall(f"{{{DS}}}Signature")
        assert len(evil_sigs) == 0, "Evil assertion should not be signed"

    def test_resign_finds_enveloped_assertion(self):
        """When Reference URI is absent, re-sign should find assertion with Signature child."""
        from lxml import etree

        signed_xml = self._make_signed_sample()
        # Remove the Reference URI attribute to force strategy 2
        root = etree.fromstring(signed_xml)
        DS = "http://www.w3.org/2000/09/xmldsig#"
        for ref in root.iter(f"{{{DS}}}Reference"):
            if "URI" in ref.attrib:
                del ref.attrib["URI"]

        modified = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
        resigned = _resign_assertion_bytes(modified)
        assert resigned is not None

        # Should still produce a valid signature
        re_root = etree.fromstring(resigned)
        with open(os.path.join(_FIXTURES_DIR, "idp_cert.pem"), "rb") as f:
            cert = f.read()
        from signxml import XMLVerifier
        SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
        assertion = re_root.find(f"{{{SAML}}}Assertion")
        XMLVerifier().verify(assertion, x509_cert=cert)

    def test_resign_uses_last_assertion_as_fallback(self):
        """When no Signature exists, re-sign should pick the last assertion."""
        from lxml import etree

        SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
        SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"

        # Build a doc with 2 assertions, no Signature at all
        resp = etree.Element(f"{{{SAMLP}}}Response",
                             nsmap={"samlp": SAMLP, "saml": SAML})
        resp.set("ID", "_resp_test")
        resp.set("Version", "2.0")

        evil = etree.SubElement(resp, f"{{{SAML}}}Assertion")
        evil.set("ID", "_evil")
        evil.set("Version", "2.0")
        nid1 = etree.SubElement(
            etree.SubElement(evil, f"{{{SAML}}}Subject"),
            f"{{{SAML}}}NameID")
        nid1.text = "evil@evil.com"

        legit = etree.SubElement(resp, f"{{{SAML}}}Assertion")
        legit.set("ID", "_legit")
        legit.set("Version", "2.0")
        iss = etree.SubElement(legit, f"{{{SAML}}}Issuer")
        iss.text = "https://idp.example.com"
        nid2 = etree.SubElement(
            etree.SubElement(legit, f"{{{SAML}}}Subject"),
            f"{{{SAML}}}NameID")
        nid2.text = "legit@example.com"

        raw = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        resigned = _resign_assertion_bytes(raw)
        assert resigned is not None

        # Signature should be on _legit (last assertion)
        re_root = etree.fromstring(resigned)
        DS = "http://www.w3.org/2000/09/xmldsig#"
        refs = list(re_root.iter(f"{{{DS}}}Reference"))
        assert len(refs) > 0
        ref_uri = refs[0].get("URI", "")
        assert "_legit" in ref_uri, f"Expected _legit in URI, got {ref_uri}"

    def test_xsw_plus_resign_produces_valid_sig(self):
        """XSW1 + re-sign should produce a document where signxml verifies."""
        from lxml import etree
        from signxml import XMLVerifier

        signed_xml = self._make_signed_sample()

        # Simulate XSW1: insert evil assertion before original
        SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
        root = etree.fromstring(signed_xml)
        evil = etree.Element(f"{{{SAML}}}Assertion")
        evil.set("Version", "2.0")
        evil.set("ID", "_evil_xsw1")
        evil.set("IssueInstant", "2025-01-01T00:00:00Z")
        iss = etree.SubElement(evil, f"{{{SAML}}}Issuer")
        iss.text = "https://evil.com"
        subj = etree.SubElement(evil, f"{{{SAML}}}Subject")
        nid = etree.SubElement(subj, f"{{{SAML}}}NameID")
        nid.text = "attacker@evil.com"

        # Insert at position 2 (after Issuer, Status, before Assertion)
        root.insert(2, evil)
        xsw_xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8")

        # Re-sign should sign the original assertion (not evil)
        resigned = _resign_assertion_bytes(xsw_xml)
        assert resigned is not None

        # Verify signature on original assertion
        re_root = etree.fromstring(resigned)
        orig_assertion = re_root.find(f".//{{{SAML}}}Assertion[@ID='_assert_test']")
        assert orig_assertion is not None

        with open(os.path.join(_FIXTURES_DIR, "idp_cert.pem"), "rb") as f:
            cert = f.read()
        XMLVerifier().verify(orig_assertion, x509_cert=cert)

    def test_blocks_still_prevent_resign(self):
        """Strategies in _blocks_resign should prevent re-signing."""
        signed_xml = self._make_signed_sample()
        mutator = SamlMutator(seed=99)
        inp = Input(data=signed_xml)

        # Run many mutations and verify blocks are respected
        for _ in range(200):
            result = mutator.mutate(inp, [])
            strategies = result.metadata.get("strategies", [])
            name_to_idx = {fn.__name__.lstrip("_"): i
                           for i, fn in enumerate(mutator._strategies)}
            indices = {name_to_idx.get(s, -1) for s in strategies}
            has_blocks = bool(indices & mutator._blocks_resign)
            if has_blocks:
                assert not result.metadata.get("resigned"), (
                    f"Blocked strategies {strategies} should prevent re-signing"
                )

    def test_opt_out_resign_increases_rate(self):
        """With opt-out model, resign rate should be significantly higher."""
        signed_xml = self._make_signed_sample()
        mutator = SamlMutator(seed=42)
        inp = Input(data=signed_xml)
        resigned_count = 0
        total = 200
        for _ in range(total):
            result = mutator.mutate(inp, [])
            if result.metadata.get("resigned"):
                resigned_count += 1
        rate = resigned_count / total
        assert rate > 0.2, (
            f"Resign rate {rate:.1%} too low — opt-out model should achieve >20%"
        )
