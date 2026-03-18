"""Tests for symbolic XML models used in SAML concolic execution."""

from __future__ import annotations

import pytest

from webfuzzer.fuzzer.concolic.xml_models import (
    C14NNamespaceModel,
    ElementInfo,
    NsMutation,
    ReferenceResolutionModel,
    SignatureScopeModel,
    TextExtractionModel,
)


# ── Test data ────────────────────────────────────────────────────

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
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">'
    b'<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="saml ds"/>'
    b'</ds:Transform>'
    b'</ds:Transforms>'
    b'</ds:Reference></ds:SignedInfo></ds:Signature>'
    b'</saml:Assertion>'
    b'</samlp:Response>'
)

XSW_RESPONSE = (
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    b'<saml:Assertion ID="_evil">'
    b'<saml:Subject><saml:NameID>evil@attacker.com</saml:NameID></saml:Subject>'
    b'</saml:Assertion>'
    b'<saml:Assertion ID="_assert1">'
    b'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>'
    b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    b'<ds:Reference URI="#_assert1"/>'
    b'</ds:Signature>'
    b'</saml:Assertion>'
    b'</samlp:Response>'
)

MIXED_CONTENT_NAMEID = (
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    b'<saml:Assertion ID="_a">'
    b'<saml:Subject><saml:NameID>admin<t/>@evil.com</saml:NameID></saml:Subject>'
    b'</saml:Assertion></samlp:Response>'
)


class TestC14NNamespaceModel:
    """Tests for C14N namespace scope model."""

    def test_namespaces_in_scope(self):
        model = C14NNamespaceModel()
        ns = model.namespaces_in_scope(SAML_RESPONSE)
        assert "samlp" in ns
        assert "saml" in ns
        assert "ds" in ns
        assert ns["samlp"] == "urn:oasis:names:tc:SAML:2.0:protocol"

    def test_namespaces_scoped_to_element(self):
        model = C14NNamespaceModel()
        # Should find namespaces declared before/on Assertion
        ns = model.namespaces_in_scope(SAML_RESPONSE, "saml:Assertion")
        assert "samlp" in ns
        assert "saml" in ns

    def test_get_c14n_algorithm(self):
        model = C14NNamespaceModel()
        algo = model.get_c14n_algorithm(SAML_RESPONSE)
        assert "exc-c14n" in algo

    def test_get_prefix_list(self):
        model = C14NNamespaceModel()
        pl = model.get_prefix_list(SAML_RESPONSE)
        assert "saml" in pl
        assert "ds" in pl

    def test_predict_void_ns_high_impact(self):
        model = C14NNamespaceModel()
        mutation = NsMutation(
            kind="void", prefix="evil", uri="1",
            target_element="samlp:Response",
            description="void ns",
        )
        score = model.predict_c14n_difference(SAML_RESPONSE, mutation)
        assert score >= 0.8

    def test_predict_undeclare_moderate_impact(self):
        model = C14NNamespaceModel()
        mutation = NsMutation(
            kind="undeclare", prefix="saml", uri="",
            target_element="saml:Assertion",
            description="undeclare saml",
        )
        score = model.predict_c14n_difference(SAML_RESPONSE, mutation)
        assert 0.5 <= score <= 0.9

    def test_predict_add_in_prefixlist_high(self):
        model = C14NNamespaceModel()
        # "saml" is in PrefixList — adding unused saml-prefixed NS
        # should impact exc-c14n output
        mutation = NsMutation(
            kind="add", prefix="saml", uri="urn:test",
            target_element="saml:Assertion",
            description="add saml",
        )
        score = model.predict_c14n_difference(SAML_RESPONSE, mutation)
        assert score >= 0.7

    def test_generate_ns_mutations(self):
        model = C14NNamespaceModel()
        mutations = model.generate_ns_mutations(SAML_RESPONSE)
        assert len(mutations) >= 3
        kinds = {m.kind for m in mutations}
        # Should have diverse mutation types
        assert len(kinds) >= 2

    def test_empty_xml(self):
        model = C14NNamespaceModel()
        ns = model.namespaces_in_scope(b"<root/>")
        assert ns == {}


class TestReferenceResolutionModel:
    """Tests for Reference URI resolution model."""

    def test_resolve_single_reference(self):
        model = ReferenceResolutionModel()
        results = model.resolve_reference(SAML_RESPONSE)
        assert len(results) == 1
        assert results[0].id_value == "_assert1"
        assert results[0].tag.endswith("Assertion")

    def test_resolve_xsw_ambiguity(self):
        model = ReferenceResolutionModel()
        results = model.resolve_reference(XSW_RESPONSE)
        # Only _assert1 matches the URI
        assert len(results) == 1
        assert results[0].id_value == "_assert1"

    def test_find_all_assertions(self):
        model = ReferenceResolutionModel()
        assertions = model._find_all_assertions(XSW_RESPONSE)
        assert len(assertions) == 2
        ids = {a.id_value for a in assertions}
        assert "_evil" in ids
        assert "_assert1" in ids

    def test_find_id_attributes(self):
        model = ReferenceResolutionModel()
        id_map = model.find_id_attributes(SAML_RESPONSE)
        assert any("Assertion" in tag for tag in id_map)

    def test_predict_xsw_effectiveness_multi_assertion(self):
        model = ReferenceResolutionModel()
        score = model.predict_xsw_effectiveness(
            XSW_RESPONSE, "xsw1_pre_assertion_clone"
        )
        # Multiple assertions + first-match variant → higher score
        assert score >= 0.4

    def test_predict_xsw_effectiveness_single(self):
        model = ReferenceResolutionModel()
        score = model.predict_xsw_effectiveness(
            SAML_RESPONSE, "xsw1_pre_assertion_clone"
        )
        # Single assertion, well-formed — lower chance
        assert score <= 0.7

    def test_empty_uri_resolves_to_all_assertions(self):
        xml = (
            b'<Response><Assertion ID="_a1"/>'
            b'<ds:Reference URI=""/>'
            b'<Assertion ID="_a2"/></Response>'
        )
        model = ReferenceResolutionModel()
        results = model.resolve_reference(xml, uri="")
        # Empty URI = all assertions
        assert len(results) >= 2


class TestTextExtractionModel:
    """Tests for text extraction divergence model."""

    def test_text_only_truncates_at_child(self):
        model = TextExtractionModel()
        text = model.predict_extracted_text(
            MIXED_CONTENT_NAMEID, "NameID", "text_only",
        )
        assert text == "admin"

    def test_itertext_includes_all(self):
        model = TextExtractionModel()
        text = model.predict_extracted_text(
            MIXED_CONTENT_NAMEID, "NameID", "itertext",
        )
        assert "@evil.com" in text
        assert "admin" in text

    def test_textcontent_includes_all(self):
        model = TextExtractionModel()
        text = model.predict_extracted_text(
            MIXED_CONTENT_NAMEID, "NameID", "textContent",
        )
        assert "@evil.com" in text

    def test_comment_hidden_in_text_only(self):
        xml = (
            b'<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'admin<!-- hidden -->@evil.com</saml:NameID>'
        )
        model = TextExtractionModel()
        # text_only: comments stripped, then .text (but no child element)
        text = model.predict_extracted_text(xml, "NameID", "text_only")
        assert "admin" in text
        assert "evil.com" in text  # comment stripped, text concatenated

    def test_cdata_section(self):
        xml = (
            b'<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'admin<![CDATA[@evil.com]]></saml:NameID>'
        )
        model = TextExtractionModel()
        text = model.predict_extracted_text(xml, "NameID", "itertext")
        assert "admin@evil.com" in text

    def test_generate_confusion_payloads(self):
        model = TextExtractionModel()
        payloads = model.generate_confusion_payloads("admin@evil.com")
        assert len(payloads) >= 5
        # Should include child element, comment, CDATA, PI variants
        has_child = any(b"<t/>" in p for p in payloads)
        has_comment = any(b"<!--" in p for p in payloads)
        has_cdata = any(b"CDATA" in p for p in payloads)
        assert has_child
        assert has_comment
        assert has_cdata

    def test_profiles_that_diverge(self):
        model = TextExtractionModel()
        divs = model.profiles_that_diverge(MIXED_CONTENT_NAMEID)
        # python3-saml (text_only) should diverge from others
        assert len(divs) >= 1
        lib_names = set()
        for la, _, lb, _ in divs:
            lib_names.add(la)
            lib_names.add(lb)
        assert "python3-saml" in lib_names

    def test_no_divergence_plain_text(self):
        xml = (
            b'<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'admin@example.com</saml:NameID>'
        )
        model = TextExtractionModel()
        divs = model.profiles_that_diverge(xml)
        assert len(divs) == 0

    def test_empty_element(self):
        model = TextExtractionModel()
        text = model.predict_extracted_text(b"<root/>", "NameID", "text_only")
        assert text == ""


class TestSignatureScopeModel:
    """Tests for signature scope model."""

    def test_signed_elements(self):
        model = SignatureScopeModel()
        signed = model.signed_elements(SAML_RESPONSE)
        assert len(signed) >= 1
        assert signed[0].id_value == "_assert1"

    def test_unsigned_elements_in_xsw(self):
        model = SignatureScopeModel()
        unsigned = model.unsigned_parsed_elements(XSW_RESPONSE)
        # The evil assertion (ID="_evil") is not referenced by URI="#_assert1"
        ids = {e.id_value for e in unsigned}
        assert "_evil" in ids

    def test_no_unsigned_in_clean_saml(self):
        model = SignatureScopeModel()
        unsigned = model.unsigned_parsed_elements(SAML_RESPONSE)
        # Single assertion, properly signed
        assert len(unsigned) == 0

    def test_get_transforms(self):
        model = SignatureScopeModel()
        transforms = model.get_transforms(SAML_RESPONSE)
        assert len(transforms) >= 2
        algos = " ".join(transforms)
        assert "enveloped-signature" in algos
        assert "exc-c14n" in algos

    def test_has_enveloped_transform(self):
        model = SignatureScopeModel()
        assert model.has_enveloped_transform(SAML_RESPONSE) is True
        assert model.has_enveloped_transform(b"<root/>") is False

    def test_predict_transform_effect_xpath(self):
        model = SignatureScopeModel()
        result = model.predict_transform_effect(
            SAML_RESPONSE,
            "http://www.w3.org/2002/06/xmldsig-filter2",
        )
        # XPath filter = uncertain scope
        for eid, status in result.items():
            if status != "out_of_scope":
                assert status == "uncertain"

    def test_signature_boundaries(self):
        model = SignatureScopeModel()
        bounds = model.find_signature_boundaries(SAML_RESPONSE)
        assert len(bounds) >= 1
        start, end = bounds[0]
        assert start < end
        # Signature should be within the document
        assert SAML_RESPONSE[start:start + 4] == b"<ds:"

    def test_empty_xml(self):
        model = SignatureScopeModel()
        assert model.signed_elements(b"<root/>") == []
        assert model.unsigned_parsed_elements(b"<root/>") == []
