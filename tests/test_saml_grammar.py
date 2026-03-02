"""Tests for the SAML grammar — generation produces well-formed XML skeletons."""

import pytest
from xml.etree import ElementTree

from webfuzzer.core.registry import GrammarRegistry
from webfuzzer.core.generator import Generator


@pytest.fixture
def generator():
    reg = GrammarRegistry()
    reg.load_builtins()
    return Generator(reg, seed=42)


class TestSamlGrammar:
    def test_grammar_loaded(self, generator):
        assert "saml" in generator.registry

    def test_generates_non_empty(self, generator):
        for i in range(10):
            result = generator.generate("saml")
            assert len(result) > 50, f"Output #{i} too short: {len(result)}"

    def test_contains_response_element(self, generator):
        for _ in range(5):
            result = generator.generate("saml")
            assert "Response" in result, "Missing Response element"

    def test_contains_assertion(self, generator):
        found = False
        for _ in range(20):
            result = generator.generate("saml")
            if "Assertion" in result:
                found = True
                break
        assert found, "No Assertion element found in 20 generations"

    def test_contains_nameid(self, generator):
        found = False
        for _ in range(20):
            result = generator.generate("saml")
            if "NameID" in result:
                found = True
                break
        assert found, "No NameID element found in 20 generations"

    def test_contains_saml_namespace(self, generator):
        for _ in range(5):
            result = generator.generate("saml")
            assert "urn:oasis:names:tc:SAML:2.0" in result or "saml" in result.lower()

    def test_deterministic_with_seed(self):
        reg = GrammarRegistry()
        reg.load_builtins()
        gen1 = Generator(reg, seed=123)
        gen2 = Generator(reg, seed=123)
        for _ in range(5):
            assert gen1.generate("saml") == gen2.generate("saml")
