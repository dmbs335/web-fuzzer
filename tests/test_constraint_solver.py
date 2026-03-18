"""Tests for concolic constraint solver."""

from __future__ import annotations

import pytest

from webfuzzer.fuzzer.concolic.constraint import XmlConstraint
from webfuzzer.fuzzer.concolic.solver import ConstraintSolver, MAX_SOLUTIONS
from webfuzzer.fuzzer.protocols import Input


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
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    b'</ds:Transforms>'
    b'</ds:Reference></ds:SignedInfo></ds:Signature>'
    b'</saml:Assertion>'
    b'</samlp:Response>'
)


class TestSolverBasic:
    """Basic solver behavior."""

    def test_empty_constraints_returns_empty(self):
        solver = ConstraintSolver(seed=42)
        result = solver.solve([], SAML_RESPONSE)
        assert result == []

    def test_max_solutions_cap(self):
        solver = ConstraintSolver(seed=42)
        # Create many constraints to trigger cap
        constraints = [
            XmlConstraint(
                domain="c14n", predicate="ns_in_scope_diverges",
                library_pair=(0, i), confidence=0.8,
                relevant_categories=frozenset(),
            )
            for i in range(10)
        ]
        result = solver.solve(constraints, SAML_RESPONSE)
        assert len(result) <= MAX_SOLUTIONS

    def test_deduplication(self):
        solver = ConstraintSolver(seed=42)
        # Same constraint twice should not produce duplicate inputs
        c = XmlConstraint(
            domain="c14n", predicate="ns_in_scope_diverges",
            library_pair=(0, 1), confidence=0.8,
        )
        result = solver.solve([c, c], SAML_RESPONSE)
        data_set = {inp.data for inp in result}
        assert len(data_set) == len(result)

    def test_stats_tracked(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="extraction", predicate="child_element_truncation",
            library_pair=(0, 1), confidence=0.9,
        )
        solver.solve([c], SAML_RESPONSE)
        assert solver.stats.total_solves == 1
        assert solver.stats.total_inputs >= 0


class TestC14NSolver:
    """Tests for c14n constraint solving."""

    def test_generates_ns_mutations(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="c14n", predicate="ns_in_scope_diverges",
            library_pair=(0, 1), confidence=0.8,
        )
        result = solver.solve([c], SAML_RESPONSE)
        assert len(result) >= 1
        for inp in result:
            assert inp.metadata["concolic_domain"] == "c14n"
            # Should have modified the XML (namespace changes)
            assert inp.data != SAML_RESPONSE

    def test_void_c14n_mutation(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="c14n", predicate="void_c14n_precomputed",
            library_pair=(0, 1), confidence=0.9,
        )
        result = solver.solve([c], SAML_RESPONSE)
        assert len(result) >= 1
        # At least one should contain a void namespace
        void_found = any(
            b'xmlns:' in inp.data and (
                b'="1"' in inp.data or b'=""' in inp.data
            )
            for inp in result
        )
        assert void_found


class TestReferenceSolver:
    """Tests for reference resolution constraint solving."""

    def test_generates_xsw_variants(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="reference", predicate="id_resolution_ambiguous",
            library_pair=(0, 1), confidence=0.8,
            parameters=XmlConstraint.make_params(uri="#_assert1"),
        )
        result = solver.solve([c], SAML_RESPONSE)
        assert len(result) >= 1
        for inp in result:
            assert inp.metadata["concolic_domain"] == "reference"

    def test_clones_assertion(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="reference", predicate="assertion_count_diverges",
            library_pair=(0, 1), confidence=0.85,
        )
        result = solver.solve([c], SAML_RESPONSE)
        # Should have at least one input with duplicated assertion
        has_clone = any(
            inp.data.count(b"<saml:Assertion") > 1
            for inp in result
        )
        assert has_clone

    def test_empty_uri_variant(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="reference", predicate="id_resolution_ambiguous",
            library_pair=(0, 1), confidence=0.7,
        )
        result = solver.solve([c], SAML_RESPONSE)
        # One variant should have empty URI
        has_empty_uri = any(
            b'URI=""' in inp.data
            for inp in result
        )
        assert has_empty_uri


class TestExtractionSolver:
    """Tests for text extraction constraint solving."""

    def test_generates_confusion_payloads(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="extraction", predicate="child_element_truncation",
            library_pair=(0, 1), confidence=0.9,
            parameters=XmlConstraint.make_params(
                primary_subject="admin",
                ref_subject="admin@evil.com",
            ),
        )
        result = solver.solve([c], SAML_RESPONSE)
        assert len(result) >= 3

        # Should include child element, comment, CDATA variants
        has_child = any(b"<t/>" in inp.data for inp in result)
        has_comment = any(b"<!--" in inp.data for inp in result)
        assert has_child or has_comment

    def test_preserves_xml_structure(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="extraction", predicate="child_element_truncation",
            library_pair=(0, 1), confidence=0.9,
        )
        result = solver.solve([c], SAML_RESPONSE)
        for inp in result:
            # Should still have NameID tags
            assert b"NameID" in inp.data
            # Should still have Response wrapper
            assert b"Response" in inp.data

    def test_no_inputs_if_no_nameid(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="extraction", predicate="child_element_truncation",
            library_pair=(0, 1), confidence=0.9,
        )
        result = solver.solve([c], b"<root>no nameid here</root>")
        assert result == []


class TestScopeSolver:
    """Tests for signature scope constraint solving."""

    def test_generates_scope_mutations(self):
        # XSW response has unsigned assertion
        xsw = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Assertion ID="_evil">'
            b'<saml:Subject><saml:NameID>victim</saml:NameID></saml:Subject>'
            b'</saml:Assertion>'
            b'<saml:Assertion ID="_signed">'
            b'<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>'
            b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            b'<ds:Reference URI="#_signed"/>'
            b'</ds:Signature>'
            b'</saml:Assertion>'
            b'</samlp:Response>'
        )
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="scope", predicate="unsigned_element_parsed",
            library_pair=(0, 1), confidence=0.75,
        )
        result = solver.solve([c], xsw)
        assert len(result) >= 1
        for inp in result:
            assert inp.metadata["concolic_domain"] == "scope"


class TestTransformSolver:
    """Tests for transform chain constraint solving."""

    def test_removes_enveloped_transform(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="transform", predicate="enveloped_sig_handling",
            library_pair=(0, 1), confidence=0.7,
        )
        result = solver.solve([c], SAML_RESPONSE)
        # One variant should have enveloped-signature removed
        has_no_enveloped = any(
            b"enveloped-signature" not in inp.data
            for inp in result
        )
        assert has_no_enveloped

    def test_swaps_c14n_algorithm(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="transform", predicate="transform_order_divergence",
            library_pair=(0, 1), confidence=0.7,
        )
        result = solver.solve([c], SAML_RESPONSE)
        # One variant should have inclusive c14n instead of exclusive
        has_inclusive = any(
            b"REC-xml-c14n" in inp.data
            for inp in result
        )
        assert has_inclusive

    def test_adds_extra_transform(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="transform", predicate="xpath_filter_divergence",
            library_pair=(0, 1), confidence=0.75,
        )
        result = solver.solve([c], SAML_RESPONSE)
        # Should produce at least one input with added transform
        assert len(result) >= 1


class TestUnknownDomain:
    """Edge cases."""

    def test_unknown_domain_returns_empty(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="unknown", predicate="test",
            library_pair=(0, 1), confidence=0.5,
        )
        result = solver.solve([c], SAML_RESPONSE)
        assert result == []

    def test_malformed_xml_does_not_crash(self):
        solver = ConstraintSolver(seed=42)
        c = XmlConstraint(
            domain="c14n", predicate="ns_in_scope_diverges",
            library_pair=(0, 1), confidence=0.8,
        )
        result = solver.solve([c], b"not xml at all")
        # Should return empty, not crash
        assert isinstance(result, list)
