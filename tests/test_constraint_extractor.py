"""Tests for concolic constraint extraction from SAML differential results."""

from __future__ import annotations

import json

import pytest

from webfuzzer.fuzzer.concolic.constraint import XmlConstraint
from webfuzzer.fuzzer.concolic.constraint_extractor import ConstraintExtractor
from webfuzzer.fuzzer.protocols import ExecutionResult, Input


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    """Create an ExecutionResult from a SAML output dict."""
    return ExecutionResult(
        exit_code=exit_code,
        stdout=json.dumps(data).encode(),
        stderr=b"",
        duration_ms=10,
    )


def _make_input(xml: bytes) -> Input:
    return Input(data=xml)


# ── Fixtures ─────────────────────────────────────────────────────


BASELINE_SAML = (
    b'<?xml version="1.0"?>'
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    b'<saml:Assertion Version="2.0" ID="_assert1">'
    b'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>'
    b'<ds:Signature><ds:SignedInfo>'
    b'<ds:Reference URI="#_assert1">'
    b'<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
    b'</ds:Transforms></ds:Reference></ds:SignedInfo></ds:Signature>'
    b'</saml:Assertion>'
    b'</samlp:Response>'
)


class TestConstraintExtractorBasic:
    """Basic behavior tests."""

    def test_no_constraints_when_both_agree(self):
        ext = ConstraintExtractor()
        inp = _make_input(BASELINE_SAML)
        primary = _make_result({
            "signature_valid": True,
            "subject": "admin@example.com",
            "assertion_count": 1,
        })
        ref = _make_result({
            "signature_valid": True,
            "subject": "admin@example.com",
            "assertion_count": 1,
        })
        constraints = ext.extract(inp, primary, [ref])
        assert constraints == []

    def test_no_constraints_when_both_fail_parse(self):
        ext = ConstraintExtractor()
        inp = _make_input(b"not xml")
        primary = ExecutionResult(exit_code=1, stdout=b"", stderr=b"", duration_ms=1)
        ref = ExecutionResult(exit_code=1, stdout=b"", stderr=b"", duration_ms=1)
        constraints = ext.extract(inp, primary, [ref])
        assert constraints == []

    def test_stats_tracked(self):
        ext = ConstraintExtractor()
        inp = _make_input(BASELINE_SAML)
        primary = _make_result({"signature_valid": True, "subject": "a", "assertion_count": 1})
        ref = _make_result({"signature_valid": True, "subject": "a", "assertion_count": 1})
        ext.extract(inp, primary, [ref])
        assert ext.stats.total_extractions == 1


class TestC14NDivergence:
    """Heuristic 1: C14N divergence extraction."""

    def test_void_c14n_with_precomputed_digest(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:x="1">'
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a">'
            b'<ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue>'
            b'</saml:Assertion></samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})
        ref = _make_result({"signature_valid": False, "subject": "", "assertion_count": 1,
                            "signature_error": "digest mismatch"})

        constraints = ext.extract(inp, primary, [ref])
        assert len(constraints) >= 1
        c14n = [c for c in constraints if c.domain == "c14n"]
        assert len(c14n) >= 1
        assert c14n[0].predicate == "void_c14n_precomputed"
        assert c14n[0].confidence >= 0.8

    def test_void_c14n_relative_ns(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:evil=".">'
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a">'
            b'</saml:Assertion></samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})
        ref = _make_result({"signature_valid": False, "subject": "", "assertion_count": 1,
                            "signature_error": "invalid digest"})

        constraints = ext.extract(inp, primary, [ref])
        c14n = [c for c in constraints if c.domain == "c14n"]
        assert len(c14n) >= 1
        assert c14n[0].predicate == "ns_in_scope_diverges"

    def test_c14n_keyword_in_error(self):
        ext = ConstraintExtractor()
        inp = _make_input(BASELINE_SAML)
        primary = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})
        ref = _make_result({
            "signature_valid": False, "subject": "", "assertion_count": 1,
            "signature_error": "Canonicalization failed: unsupported algorithm",
        })

        constraints = ext.extract(inp, primary, [ref])
        c14n = [c for c in constraints if c.domain == "c14n"]
        assert len(c14n) >= 1


class TestReferenceResolution:
    """Heuristic 2: Reference resolution extraction."""

    def test_assertion_count_divergence(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Assertion ID="_a1"><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion>'
            b'<saml:Assertion ID="_a2"><saml:Subject><saml:NameID>evil</saml:NameID></saml:Subject></saml:Assertion>'
            b'</samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({
            "signature_valid": False, "subject": "admin",
            "assertion_count": 2,
        })
        ref = _make_result({
            "signature_valid": False, "subject": "evil",
            "assertion_count": 1,  # Only sees one assertion
        })

        constraints = ext.extract(inp, primary, [ref])
        ref_c = [c for c in constraints if c.domain == "reference"]
        assert len(ref_c) >= 1
        assert ref_c[0].predicate == "assertion_count_diverges"

    def test_ref_match_divergence(self):
        ext = ConstraintExtractor()
        inp = _make_input(BASELINE_SAML)
        primary = _make_result({
            "signature_valid": True, "subject": "admin",
            "assertion_count": 1,
            "reference_matches_selected_assertion": True,
        })
        ref = _make_result({
            "signature_valid": False, "subject": "admin",
            "assertion_count": 1,
            "reference_matches_selected_assertion": False,
        })

        constraints = ext.extract(inp, primary, [ref])
        ref_c = [c for c in constraints if c.domain == "reference"]
        assert len(ref_c) >= 1
        assert ref_c[0].predicate == "ref_match_diverges"


class TestTextExtraction:
    """Heuristic 3: Text extraction divergence."""

    def test_child_element_truncation(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Assertion ID="_a">'
            b'<saml:Subject><saml:NameID>admin<t/>@evil.com</saml:NameID></saml:Subject>'
            b'</saml:Assertion></samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({
            "signature_valid": True, "subject": "admin",
            "assertion_count": 1,
        })
        ref = _make_result({
            "signature_valid": True, "subject": "admin@evil.com",
            "assertion_count": 1,
        })

        constraints = ext.extract(inp, primary, [ref])
        ext_c = [c for c in constraints if c.domain == "extraction"]
        assert len(ext_c) == 1
        assert ext_c[0].predicate == "child_element_truncation"
        assert ext_c[0].confidence >= 0.85

    def test_comment_hidden_content(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Assertion ID="_a">'
            b'<saml:Subject><saml:NameID>admin<!-- comment -->@evil.com</saml:NameID></saml:Subject>'
            b'</saml:Assertion></samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})
        ref = _make_result({"signature_valid": True, "subject": "admin@evil.com", "assertion_count": 1})

        constraints = ext.extract(inp, primary, [ref])
        ext_c = [c for c in constraints if c.domain == "extraction"]
        assert len(ext_c) == 1
        assert ext_c[0].predicate == "comment_content_hidden"

    def test_subject_case_divergence(self):
        ext = ConstraintExtractor()
        inp = _make_input(BASELINE_SAML)
        primary = _make_result({"signature_valid": True, "subject": "Admin", "assertion_count": 1})
        ref = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})

        constraints = ext.extract(inp, primary, [ref])
        # case_normalization is low-value: subjects differ only in case
        ext_c = [c for c in constraints if c.domain == "extraction"]
        assert len(ext_c) == 1
        assert ext_c[0].predicate == "case_normalization"
        assert ext_c[0].confidence <= 0.6


class TestSignatureScope:
    """Heuristic 4: Signature scope extraction."""

    def test_xpath_transform_scope(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Assertion ID="_a">'
            b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
            b'<XPath Filter="subtract">//saml:Conditions</XPath>'
            b'</ds:Transform></ds:Signature>'
            b'</saml:Assertion></samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({
            "signature_valid": True, "subject": "admin", "assertion_count": 1,
        })
        ref = _make_result({
            "signature_valid": False, "subject": "", "assertion_count": 1,
            "signature_error": "reference validation failed",
        })

        constraints = ext.extract(inp, primary, [ref])
        scope_c = [c for c in constraints if c.domain == "scope"]
        assert len(scope_c) >= 1
        assert scope_c[0].predicate == "transform_scope_mismatch"

    def test_multiple_assertions_scope(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Assertion ID="_a1"><saml:Subject><saml:NameID>evil</saml:NameID></saml:Subject></saml:Assertion>'
            b'<saml:Assertion ID="_a2"><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion>'
            b'</samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({
            "signature_valid": True, "subject": "evil", "assertion_count": 2,
        })
        ref = _make_result({
            "signature_valid": False, "subject": "admin", "assertion_count": 2,
            "signature_error": "signed assertion does not match selected",
        })

        constraints = ext.extract(inp, primary, [ref])
        scope_c = [c for c in constraints if c.domain == "scope"]
        assert len(scope_c) >= 1


class TestTransformChain:
    """Heuristic 5: Transform chain divergence."""

    def test_xslt_transform(self):
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a">'
            b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">'
            b'</ds:Transform></ds:Signature>'
            b'</saml:Assertion></samlp:Response>'
        )
        ext = ConstraintExtractor()
        inp = _make_input(xml)
        primary = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})
        ref = _make_result({
            "signature_valid": False, "subject": "", "assertion_count": 1,
            "signature_error": "XSLT transform not supported",
        })

        constraints = ext.extract(inp, primary, [ref])
        t_c = [c for c in constraints if c.domain == "transform"]
        assert len(t_c) >= 1
        assert t_c[0].predicate == "xslt_transform_divergence"

    def test_enveloped_sig_error(self):
        ext = ConstraintExtractor()
        inp = _make_input(BASELINE_SAML)
        primary = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})
        ref = _make_result({
            "signature_valid": False, "subject": "", "assertion_count": 1,
            "signature_error": "enveloped-signature transform failed",
        })

        constraints = ext.extract(inp, primary, [ref])
        t_c = [c for c in constraints if c.domain == "transform"]
        assert len(t_c) >= 1


class TestConstraintCapping:
    """Verify max constraint cap and caching."""

    def test_max_constraints_capped(self):
        """Even with many refs, total constraints are capped."""
        ext = ConstraintExtractor()
        # Create input with void c14n + multiple assertions + comments + xpath
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
            b'xmlns:evil="1">'  # void ns
            b'<saml:Assertion ID="_a1">'
            b'<saml:Subject><saml:NameID>admin<t/>@evil.com</saml:NameID></saml:Subject>'
            b'</saml:Assertion>'
            b'<saml:Assertion ID="_a2">'
            b'<saml:Subject><saml:NameID>evil</saml:NameID></saml:Subject>'
            b'</saml:Assertion>'
            b'<!-- comment -->'
            b'</samlp:Response>'
        )
        inp = _make_input(xml)
        primary = _make_result({
            "signature_valid": True, "subject": "admin",
            "assertion_count": 2,
        })
        # 12 refs to exceed cap
        refs = [
            _make_result({
                "signature_valid": False,
                "subject": f"user{i}@evil.com",
                "assertion_count": 1 + (i % 2),
                "signature_error": "namespace c14n failed" if i % 3 == 0 else "",
            })
            for i in range(12)
        ]

        constraints = ext.extract(inp, primary, refs)
        assert len(constraints) <= 10  # _MAX_CONSTRAINTS_PER_INPUT

    def test_cache_hit(self):
        ext = ConstraintExtractor()
        xml = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:evil="1">'
            b'<saml:Assertion ID="_a">'
            b'<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>'
            b'</saml:Assertion></samlp:Response>'
        )
        inp = _make_input(xml)
        primary = _make_result({"signature_valid": True, "subject": "admin", "assertion_count": 1})
        ref = _make_result({"signature_valid": False, "subject": "", "assertion_count": 1,
                            "signature_error": "c14n failed"})

        c1 = ext.extract(inp, primary, [ref])
        c2 = ext.extract(inp, primary, [ref])
        # Same result from cache
        assert len(c1) == len(c2)
        assert ext.stats.total_extractions == 2


class TestXmlConstraintDataclass:
    """Test the XmlConstraint dataclass itself."""

    def test_make_params(self):
        params = XmlConstraint.make_params(a=1, b="two", c=True)
        assert isinstance(params, tuple)
        assert dict(params) == {"a": 1, "b": "two", "c": True}

    def test_to_dict(self):
        c = XmlConstraint(
            domain="c14n",
            predicate="ns_in_scope_diverges",
            library_pair=(0, 1),
            confidence=0.8,
            parameters=XmlConstraint.make_params(ns_prefix="saml"),
            relevant_categories=frozenset({"void_c14n_relative_ns"}),
        )
        d = c.to_dict()
        assert d["domain"] == "c14n"
        assert d["pair"] == [0, 1]
        assert d["parameters"]["ns_prefix"] == "saml"
        assert "void_c14n_relative_ns" in d["relevant_categories"]

    def test_frozen(self):
        c = XmlConstraint(
            domain="c14n", predicate="test",
            library_pair=(0, 1), confidence=0.5,
        )
        with pytest.raises(AttributeError):
            c.domain = "reference"  # type: ignore[misc]

    def test_params_dict(self):
        c = XmlConstraint(
            domain="extraction",
            predicate="child_element_truncation",
            library_pair=(0, 2),
            confidence=0.9,
            parameters=XmlConstraint.make_params(
                child_tag="t", full_text="admin@evil.com",
            ),
        )
        pd = c.params_dict()
        assert pd["child_tag"] == "t"
        assert pd["full_text"] == "admin@evil.com"
