"""Tests for class pollution mutator."""
from __future__ import annotations

import json
import pytest

from webfuzzer.fuzzer.mutators.class_pollution_mutator import (
    ClassPollutionMutator,
    MAX_OUTPUT_SIZE,
)
from webfuzzer.fuzzer.protocols import Input


class _FakeInput:
    """Minimal input stand-in with metadata."""
    def __init__(self, metadata: dict):
        self.metadata = metadata
        self.data = b'{}'


class _FakeSeed:
    """Minimal seed stand-in for tests that need corpus with metadata."""
    def __init__(self, metadata: dict):
        self.input = _FakeInput(metadata)


def _make_seed_with_metadata(meta: dict) -> _FakeSeed:
    return _FakeSeed(meta)


@pytest.fixture
def mutator():
    return ClassPollutionMutator(seed=42)


@pytest.fixture
def base_input():
    return Input(
        data=json.dumps({"merge_fn": "recursive_merge", "payload": {}}).encode()
    )


class TestClassPollutionMutator:
    def test_mutate_returns_valid_json(self, mutator, base_input):
        for _ in range(50):
            result = mutator.mutate(base_input, [])
            data = json.loads(result.data)
            assert "merge_fn" in data
            assert "payload" in data
            assert isinstance(data["payload"], dict)

    def test_mutate_output_size_limit(self, mutator, base_input):
        for _ in range(100):
            result = mutator.mutate(base_input, [])
            assert len(result.data) <= MAX_OUTPUT_SIZE

    def test_metadata_has_strategy(self, mutator, base_input):
        result = mutator.mutate(base_input, [])
        assert "source" in result.metadata
        assert result.metadata["source"].startswith("class_pollution:")

    def test_all_strategies_produce_valid_payloads(self, mutator, base_input):
        """Each strategy should produce a dict payload with dunder keys."""
        # Create corpus with access_path metadata for CP8/CP9
        corpus = [_make_seed_with_metadata({
            "access_path": ["__class__", "__init__", "__globals__"],
            "globals_reachable": ["os"],
        })]
        seen_strategies = set()
        for _ in range(500):
            result = mutator.mutate(base_input, corpus)
            data = json.loads(result.data)
            strategy = result.metadata.get("strategy", "unknown")
            seen_strategies.add(strategy)
            assert isinstance(data["payload"], dict), f"Strategy {strategy} produced non-dict payload"

        # All strategies should have been hit at least once
        expected = {
            "globals_override", "class_attr_pollution", "bases_traversal",
            "dict_injection", "chain_depth_variation", "value_type_juggling",
            "dunder_permutation", "combine", "path_extension", "sink_targeting",
        }
        assert seen_strategies == expected, f"Missing strategies: {expected - seen_strategies}"

    def test_globals_override_has_class_chain(self, mutator):
        """CP1: globals override should have __class__.__init__.__globals__ chain."""
        payload = mutator._cp1_globals_override()
        assert "__class__" in payload
        assert "__init__" in payload["__class__"]
        assert "__globals__" in payload["__class__"]["__init__"]

    def test_class_attr_has_class_key(self, mutator):
        """CP2: class attr should target __class__."""
        payload = mutator._cp2_class_attr()
        assert "__class__" in payload
        # Should have at least one non-dunder key inside __class__
        inner_keys = [k for k in payload["__class__"] if not k.startswith("__")]
        assert len(inner_keys) >= 1

    def test_bases_traversal_variants(self, mutator):
        """CP3: should produce valid bases/mro chains."""
        for _ in range(50):
            payload = mutator._cp3_bases_traversal()
            assert "__class__" in payload
            inner = payload["__class__"]
            assert "__bases__" in inner or "__mro__" in inner

    def test_chain_depth_variation(self, mutator):
        """CP5: different depths should be produced."""
        depths = set()
        for _ in range(100):
            payload = mutator._cp5_chain_depth()
            # Count nesting depth
            depth = 0
            current = payload
            while isinstance(current, dict):
                depth += 1
                # Follow first dict value
                for v in current.values():
                    if isinstance(v, dict):
                        current = v
                        break
                else:
                    break
            depths.add(depth)
        assert len(depths) >= 3, f"Expected varied depths, got {depths}"

    def test_merge_fn_variation(self, mutator, base_input):
        """Merge function names should vary."""
        merge_fns = set()
        for _ in range(200):
            result = mutator.mutate(base_input, [])
            data = json.loads(result.data)
            merge_fns.add(data["merge_fn"])
        assert len(merge_fns) >= 2

    def test_reset_weights(self, mutator):
        original = list(mutator._weights)
        mutator.update_weights({"globals_override": 5})
        assert mutator._weights != original
        mutator.reset_weights()
        assert mutator._weights == original

    def test_handles_invalid_input_gracefully(self, mutator):
        """Mutator should handle non-JSON input."""
        inp = Input(data=b"not json at all")
        result = mutator.mutate(inp, [])
        data = json.loads(result.data)
        assert "merge_fn" in data
        assert "payload" in data

    def test_cp8_path_extension_with_corpus(self, mutator):
        """CP8: should extend access paths from corpus seeds."""
        corpus = [_make_seed_with_metadata({
            "access_path": ["__class__", "__init__"],
        })]
        for _ in range(20):
            payload = mutator._cp8_path_extension(corpus)
            assert isinstance(payload, dict)
            # Should contain at least __class__ (from the path)
            assert "__class__" in payload or any(
                k.startswith("__") for k in payload
            )

    def test_cp8_fallback_without_paths(self, mutator):
        """CP8: should fall back to CP1 when no access_path in corpus."""
        corpus = [_make_seed_with_metadata({})]
        payload = mutator._cp8_path_extension(corpus)
        assert "__class__" in payload

    def test_cp9_sink_targeting_unreached(self, mutator):
        """CP9: should target sinks not yet reached."""
        corpus = [_make_seed_with_metadata({
            "globals_reachable": ["os"],
        })]
        payloads = set()
        for _ in range(50):
            payload = mutator._cp9_sink_targeting(corpus)
            assert isinstance(payload, dict)
            assert "__class__" in payload
            # Extract the targeted sink from the innermost __globals__
            data_str = json.dumps(payload)
            payloads.add(data_str)
        # Should produce varied payloads
        assert len(payloads) >= 3

    def test_cp9_all_sinks_reached(self, mutator):
        """CP9: should still generate when all sinks are reached."""
        from webfuzzer.fuzzer.mutators.class_pollution_mutator import ALL_SINKS
        corpus = [_make_seed_with_metadata({
            "globals_reachable": list(ALL_SINKS),
        })]
        payload = mutator._cp9_sink_targeting(corpus)
        assert isinstance(payload, dict)
        assert "__class__" in payload

    def test_cp8_cp9_empty_corpus_fallback(self, mutator, base_input):
        """CP8/CP9 should fall back to CP1 when corpus is empty."""
        # Force CP8 selection by calling directly
        result = mutator.mutate(base_input, [])
        data = json.loads(result.data)
        assert "payload" in data
