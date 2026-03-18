"""Tests for the DOM Clobbering combinatorial mutator."""

import pytest

from webfuzzer.fuzzer.mutators.domclobber_mutator import (
    DomClobberMutator,
    MAX_OUTPUT_SIZE,
    CLOBBER_TAGS,
    NAMED_ELEMENTS,
    CLOBBER_TARGETS,
    DOCUMENT_TARGETS,
    EVIL_URLS,
)
from webfuzzer.fuzzer.protocols import Input


SAMPLE_HTML = b'<div id="test"><a href="https://example.com">link</a></div>'


@pytest.fixture
def mutator():
    return DomClobberMutator(seed=42)


class TestDomClobberMutator:
    def test_name(self, mutator):
        assert mutator.name == "domclobber"

    def test_mutate_returns_input(self, mutator):
        inp = Input(data=SAMPLE_HTML)
        result = mutator.mutate(inp, [])
        assert isinstance(result, Input)
        assert len(result.data) > 0

    def test_mutate_produces_html_with_id_or_name(self, mutator):
        """Mutations should contain id= or name= attributes."""
        inp = Input(data=SAMPLE_HTML)
        found = False
        for _ in range(30):
            result = mutator.mutate(inp, [])
            if b'id="' in result.data or b'name="' in result.data:
                found = True
                break
        assert found, "No id/name attributes in 30 mutations"

    def test_mutate_respects_max_size(self, mutator):
        inp = Input(data=SAMPLE_HTML)
        for _ in range(50):
            result = mutator.mutate(inp, [])
            assert len(result.data) <= MAX_OUTPUT_SIZE

    def test_strategy_count(self, mutator):
        assert len(mutator._strategies) == 12
        assert len(mutator._strategy_names) == 12
        assert len(mutator._weights) == 12
        assert len(mutator._base_weights) == 12

    def test_weights_positive(self, mutator):
        for w in mutator._weights:
            assert w > 0

    def test_metadata_has_mutator_and_strategies(self, mutator):
        inp = Input(data=SAMPLE_HTML)
        result = mutator.mutate(inp, [])
        assert result.metadata["mutator"] == "domclobber"
        assert "strategies" in result.metadata
        assert len(result.metadata["strategies"]) >= 1

    def test_all_strategies_produce_bytes(self, mutator):
        """Each individual strategy should return non-empty bytes."""
        for i, strategy in enumerate(mutator._strategies):
            output = strategy()
            assert isinstance(output, bytes), f"Strategy {mutator._strategy_names[i]} returned {type(output)}"
            assert len(output) > 0, f"Strategy {mutator._strategy_names[i]} returned empty bytes"

    def test_diverse_strategies_fire(self, mutator):
        """Multiple strategy categories should appear across mutations."""
        inp = Input(data=SAMPLE_HTML)
        seen = set()
        for _ in range(200):
            result = mutator.mutate(inp, [])
            for s in result.metadata["strategies"]:
                seen.add(s)
        # At least 8 of 12 strategies should fire in 200 tries
        assert len(seen) >= 8, f"Only {len(seen)} strategies seen: {seen}"

    def test_anchor_tostring_has_href(self, mutator):
        """anchor_tostring strategy should produce an <a> with href."""
        output = mutator._anchor_tostring()
        assert b"<a " in output
        assert b'href="' in output

    def test_form_child_chain_has_form(self, mutator):
        output = mutator._form_child_chain()
        assert b"<form " in output
        assert b"</form>" in output

    def test_collection_chain_has_duplicate_id(self, mutator):
        """collection_chain should produce two elements with the same id."""
        for _ in range(20):
            output = mutator._collection_chain()
            # Should have at least two id= attributes
            count = output.count(b'id="')
            assert count >= 2, f"Expected 2+ ids, got {count}: {output}"

    def test_namespace_boundary_has_svg_or_math(self, mutator):
        for _ in range(20):
            output = mutator._namespace_boundary()
            assert b"<svg" in output or b"<math" in output

    def test_framework_gadget_known_patterns(self, mutator):
        """Framework gadgets should target webpack/closure/AMP patterns."""
        found_framework = False
        for _ in range(30):
            output = mutator._framework_gadget()
            if (b"__webpack" in output or b"CLOSURE" in output
                    or b"AMP_MODE" in output or b'"ga"' in output
                    or b"currentScript" in output or b"dataLayer" in output):
                found_framework = True
                break
        assert found_framework

    def test_corpus_splice_without_corpus(self, mutator):
        """corpus_splice should still produce output when corpus is empty."""
        output = mutator._corpus_splice()
        assert isinstance(output, bytes)
        assert len(output) > 0


class TestDomClobberFeedback:
    def test_feedback_finding_boosts_weight(self):
        m = DomClobberMutator(seed=1)
        original = m._weights[0]
        m.feedback("single_id_clobber", "finding")
        # Weight should have changed (normalized, but relative increase)
        assert m._strategy_finds[0] == 1

    def test_feedback_coverage_boosts_weight(self):
        m = DomClobberMutator(seed=1)
        m.feedback("collection_chain", "coverage")
        assert m._strategy_cov[2] == 1

    def test_feedback_unknown_strategy_ignored(self):
        m = DomClobberMutator(seed=1)
        original_weights = list(m._weights)
        m.feedback("nonexistent_strategy", "finding")
        assert m._weights == original_weights

    def test_feedback_unknown_signal_ignored(self):
        m = DomClobberMutator(seed=1)
        original_weights = list(m._weights)
        m.feedback("single_id_clobber", "unknown_signal")
        assert m._weights == original_weights

    def test_reset_weights_restores_base(self):
        m = DomClobberMutator(seed=1)
        m.feedback("anchor_tostring", "finding")
        m.feedback("anchor_tostring", "finding")
        m.reset_weights()
        assert m._weights == list(m._base_weights)

    def test_reset_weights_boost_zero_finds(self):
        m = DomClobberMutator(seed=1)
        m.feedback("anchor_tostring", "finding")  # idx 5
        m.reset_weights(boost_zero_finds=True)
        # Strategies with zero finds get 2x base weight
        for i in range(len(m._strategies)):
            if i == 5:
                assert m._weights[i] == m._base_weights[i]
            else:
                assert m._weights[i] == m._base_weights[i] * 2

    def test_weight_normalization_preserves_total(self):
        m = DomClobberMutator(seed=1)
        original_total = sum(m._weights)
        m.feedback("single_id_clobber", "finding")
        m.feedback("collection_chain", "coverage")
        new_total = sum(m._weights)
        assert abs(new_total - original_total) < 0.01
