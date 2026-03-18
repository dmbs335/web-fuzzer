"""Tests for property extractor."""

from __future__ import annotations

import pytest

from webfuzzer.fuzzer.concolic.property_extractor import (
    PROPERTY_NAMES,
    PropertyExtractor,
)
from webfuzzer.fuzzer.concolic.property_vector import NUM_PROPERTIES


SAML_RESPONSE = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" '
    b'ID="_resp_001" Version="2.0">'
    b'<saml:Assertion Version="2.0" ID="_assert_001">'
    b'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>'
    b'<ds:Signature><ds:SignedInfo>'
    b'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    b'<ds:Reference URI="#_assert_001">'
    b'<ds:Transforms>'
    b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    b'</ds:Transforms>'
    b'</ds:Reference></ds:SignedInfo></ds:Signature>'
    b'</saml:Assertion>'
    b'</samlp:Response>'
)


class TestPropertyExtractor:
    """Basic extraction tests."""

    def test_returns_correct_length(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert len(pv.values) == NUM_PROPERTIES

    def test_property_names_count(self):
        assert len(PROPERTY_NAMES) == NUM_PROPERTIES

    def test_empty_input(self):
        ext = PropertyExtractor()
        pv = ext.extract(b"")
        assert len(pv.values) == NUM_PROPERTIES
        assert pv.values[0] == 0.0  # total_bytes
        assert pv.values[28] == 0.0  # byte_entropy

    def test_malformed_input(self):
        ext = PropertyExtractor()
        pv = ext.extract(b"not xml at all, just random bytes")
        assert len(pv.values) == NUM_PROPERTIES

    def test_total_bytes_normalized(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert 0.0 < pv.values[0] < 1.0  # should be len/50000

    def test_tag_count_positive(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[1] > 0.0  # tag_count

    def test_namespace_detection(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[4] > 0.0  # ns_decl_count (3 ns declarations)
        assert pv.values[5] > 0.0  # unique_ns_uri_count

    def test_empty_ns_detection(self):
        ext = PropertyExtractor()
        data = b'<root xmlns:x=""></root>'
        pv = ext.extract(data)
        assert pv.values[6] == 1.0  # has_empty_ns

    def test_relative_ns_detection(self):
        ext = PropertyExtractor()
        data = b'<root xmlns:x="1"></root>'
        pv = ext.extract(data)
        assert pv.values[7] == 1.0  # has_relative_ns

    def test_default_ns_detection(self):
        ext = PropertyExtractor()
        data = b'<root xmlns="urn:test"></root>'
        pv = ext.extract(data)
        assert pv.values[8] == 1.0  # default_ns_present

    def test_structure_detection(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[10] > 0.0  # assertion_count
        assert pv.values[11] > 0.0  # signature_count
        assert pv.values[12] > 0.0  # reference_count

    def test_signature_properties(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[15] > 0.0  # transform_count
        assert pv.values[16] == 1.0  # has_enveloped

    def test_comment_detection(self):
        ext = PropertyExtractor()
        data = b"<root><!-- comment --><child/></root>"
        pv = ext.extract(data)
        assert pv.values[13] > 0.0  # comment_count

    def test_pi_detection(self):
        ext = PropertyExtractor()
        data = b"<?xml version='1.0'?><root><?pi data?></root>"
        pv = ext.extract(data)
        assert pv.values[14] > 0.0  # pi_count

    def test_cdata_detection(self):
        ext = PropertyExtractor()
        data = b"<root><![CDATA[text]]></root>"
        pv = ext.extract(data)
        assert pv.values[20] > 0.0  # cdata_count

    def test_doctype_detection(self):
        ext = PropertyExtractor()
        data = b"<!DOCTYPE root SYSTEM 'test.dtd'><root/>"
        pv = ext.extract(data)
        assert pv.values[21] == 1.0  # doctype_present

    def test_bom_detection(self):
        ext = PropertyExtractor()
        data = b"\xef\xbb\xbf<root/>"
        pv = ext.extract(data)
        assert pv.values[22] == 1.0  # has_bom

    def test_encoding_decl_detection(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[23] == 1.0  # has_encoding_decl (UTF-8)

    def test_id_detection(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[25] > 0.0  # id_attr_count

    def test_duplicate_id_detection(self):
        ext = PropertyExtractor()
        data = b'<root><a ID="x"/><b ID="x"/></root>'
        pv = ext.extract(data)
        assert pv.values[26] == 1.0  # duplicate_id_present

    def test_mixed_id_case_detection(self):
        ext = PropertyExtractor()
        data = b'<root ID="x" Id="y"/>'
        pv = ext.extract(data)
        assert pv.values[27] == 1.0  # mixed_id_case

    def test_byte_entropy_nonzero(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[28] > 0.0  # byte_entropy

    def test_tag_diversity(self):
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        assert pv.values[29] > 0.0  # tag_name_diversity

    def test_all_values_bounded(self):
        """All property values should be in [0, 1]."""
        ext = PropertyExtractor()
        pv = ext.extract(SAML_RESPONSE)
        for i, v in enumerate(pv.values):
            assert 0.0 <= v <= 1.0, f"Property {PROPERTY_NAMES[i]} out of bounds: {v}"

    def test_diff(self):
        ext = PropertyExtractor()
        pv1 = ext.extract(SAML_RESPONSE)
        pv2 = ext.extract(b"<root/>")
        diff = pv1.diff(pv2)
        assert len(diff) == NUM_PROPERTIES
        # tag_count should differ
        assert diff[1] != 0.0


class TestExtractorPerformance:
    """Verify extraction is fast enough."""

    def test_large_input(self):
        ext = PropertyExtractor()
        # 50KB input
        data = b"<root>" + b"<child attr='val'>text</child>" * 1500 + b"</root>"
        pv = ext.extract(data)
        assert len(pv.values) == NUM_PROPERTIES

    def test_repeated_extraction(self):
        ext = PropertyExtractor()
        for _ in range(100):
            pv = ext.extract(SAML_RESPONSE)
        assert len(pv.values) == NUM_PROPERTIES
