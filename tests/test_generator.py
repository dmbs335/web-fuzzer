"""Tests for the generation engine."""

import pytest

from webfuzzer.core.generator import Generator, GenerationError
from webfuzzer.core.parser import GrammarParser
from webfuzzer.core.registry import GrammarRegistry


@pytest.fixture
def registry():
    return GrammarRegistry()


@pytest.fixture
def parser():
    return GrammarParser()


def load(registry, parser, text, name="test"):
    g = parser.parse_string(text, name=name)
    registry.register(g)
    return g


class TestBasicGeneration:
    def test_literal_output(self, registry, parser):
        load(registry, parser, "<start> = hello world")
        gen = Generator(registry, seed=42)
        result = gen.generate("test")
        assert result == "hello world"

    def test_rule_reference(self, registry, parser):
        load(registry, parser, "<start> = <greeting>\n<greeting> = hi there")
        gen = Generator(registry, seed=42)
        result = gen.generate("test")
        assert result == "hi there"

    def test_alternatives(self, registry, parser):
        load(
            registry,
            parser,
            "<start> = alpha\n<start> = beta\n<start> = gamma",
        )
        gen = Generator(registry, seed=42)
        results = {gen.generate("test") for _ in range(50)}
        # With 50 attempts, we should hit at least 2 alternatives
        assert len(results) >= 2
        assert results <= {"alpha", "beta", "gamma"}

    def test_weighted_alternatives(self, registry, parser):
        load(
            registry,
            parser,
            "<start> = [weight=100] heavy\n<start> = [weight=1] light",
        )
        gen = Generator(registry, seed=42)
        results = [gen.generate("test") for _ in range(100)]
        heavy_count = results.count("heavy")
        # With 100:1 weight, heavy should dominate
        assert heavy_count > 80

    def test_seed_reproducibility(self, registry, parser):
        load(
            registry,
            parser,
            "<start> = <val>\n<val> = a\n<val> = b\n<val> = c",
        )
        gen1 = Generator(registry, seed=123)
        gen2 = Generator(registry, seed=123)
        results1 = [gen1.generate("test") for _ in range(20)]
        results2 = [gen2.generate("test") for _ in range(20)]
        assert results1 == results2


class TestBuiltins:
    def test_int_generation(self, registry, parser):
        load(registry, parser, "<start> = <int min=10 max=20>")
        gen = Generator(registry, seed=42)
        for _ in range(50):
            result = gen.generate("test")
            assert 10 <= int(result) <= 20

    def test_string_generation(self, registry, parser):
        load(registry, parser, "<start> = <string min=5 max=10>")
        gen = Generator(registry, seed=42)
        for _ in range(20):
            result = gen.generate("test")
            assert 5 <= len(result) <= 10

    def test_hex_generation(self, registry, parser):
        load(registry, parser, "<start> = <hex len=8>")
        gen = Generator(registry, seed=42)
        result = gen.generate("test")
        assert len(result) == 8
        assert all(c in "0123456789abcdef" for c in result)

    def test_oneof_generation(self, registry, parser):
        load(registry, parser, "<start> = <oneof red green blue>")
        gen = Generator(registry, seed=42)
        results = {gen.generate("test") for _ in range(50)}
        assert results <= {"red", "green", "blue"}
        assert len(results) >= 2


class TestModifiers:
    def test_optional_modifier(self, registry, parser):
        load(registry, parser, "<start> = prefix<maybe?>suffix\n<maybe> = X")
        gen = Generator(registry, seed=42)
        results = {gen.generate("test") for _ in range(50)}
        assert "prefixXsuffix" in results or "prefixsuffix" in results

    def test_plus_modifier(self, registry, parser):
        load(registry, parser, "<start> = <letter+>\n<letter> = a")
        gen = Generator(registry, seed=42)
        for _ in range(20):
            result = gen.generate("test")
            assert len(result) >= 1
            assert all(c == "a" for c in result)

    def test_star_modifier(self, registry, parser):
        load(registry, parser, "<start> = [<letter*>]\n<letter> = x")
        gen = Generator(registry, seed=42)
        results = set()
        for _ in range(50):
            result = gen.generate("test")
            results.add(result)
            assert result.startswith("[")
            assert result.endswith("]")
        # Should include the empty case sometimes
        assert "[]" in results or any(len(r) > 2 for r in results)

    def test_bounded_repeat(self, registry, parser):
        load(registry, parser, "<start> = <letter{2,4}>\n<letter> = a")
        gen = Generator(registry, seed=42)
        for _ in range(50):
            result = gen.generate("test")
            assert 2 <= len(result) <= 4


class TestCrossGrammarRef:
    def test_cross_ref_generation(self, registry, parser):
        load(registry, parser, "<start> = hello", name="greet")
        load(
            registry,
            parser,
            "<start> = prefix_@greet:<start>_suffix",
            name="main",
        )
        gen = Generator(registry, seed=42)
        result = gen.generate("main")
        assert result == "prefix_hello_suffix"


class TestDepthControl:
    def test_respects_max_depth(self, registry, parser):
        # Recursive grammar that would infinite-loop without depth control
        load(
            registry,
            parser,
            "!max_depth 5\n<start> = <start> x\n<start> = done",
        )
        gen = Generator(registry, seed=42)
        # Should terminate without error
        result = gen.generate("test")
        assert "done" in result

    def test_max_depth_override(self, registry, parser):
        load(
            registry,
            parser,
            "!max_depth 100\n<start> = <start> x\n<start> = done",
        )
        gen = Generator(registry, seed=42, max_depth_override=3)
        result = gen.generate("test")
        assert "done" in result


class TestErrors:
    def test_unknown_grammar(self, registry):
        gen = Generator(registry, seed=42)
        with pytest.raises(GenerationError, match="not found"):
            gen.generate("nonexistent")

    def test_undefined_rule(self, registry, parser):
        load(registry, parser, "<start> = <missing>")
        gen = Generator(registry, seed=42)
        with pytest.raises(GenerationError, match="Undefined rule"):
            gen.generate("test")

    def test_no_root_rule(self, registry, parser):
        g = parser.parse_string("")
        g.name = "empty"
        g.root = ""
        registry.register(g)
        gen = Generator(registry, seed=42)
        with pytest.raises(GenerationError, match="no root"):
            gen.generate("empty")


class TestIntegration:
    def test_builtin_grammars_load(self):
        """Test that the built-in grammar files parse without error."""
        registry = GrammarRegistry()
        grammars = registry.load_builtins()
        assert len(grammars) >= 1  # At least one grammar should exist

    def test_csp_generation(self):
        """Test end-to-end CSP generation."""
        registry = GrammarRegistry()
        registry.load_builtins()
        if "csp" not in registry:
            pytest.skip("CSP grammar not available")
        gen = Generator(registry, seed=42)
        result = gen.generate("csp")
        # CSP should produce non-empty output
        assert len(result) > 0
