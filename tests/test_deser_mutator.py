"""Tests for the Java deserialization gadget chain mutator."""

import json

import pytest

from webfuzzer.fuzzer.mutators.deser_mutator import DeserMutator
from webfuzzer.fuzzer.protocols import Input


# Minimal valid IR for testing
MINIMAL_IR = json.dumps({
    "chain_type": "transform_chain",
    "root_class": "java.util.PriorityQueue",
    "root_trigger": "readObject→heapify→comparator.compare",
    "links": [
        {
            "class": "org.apache.commons.collections4.comparators.TransformingComparator",
            "field_overrides": {
                "transformer": {"$ref": "link:1"},
            },
        },
        {
            "class": "org.apache.commons.collections4.functors.InvokerTransformer",
            "field_overrides": {
                "iMethodName": "exec",
                "iParamTypes": ["[Ljava.lang.String;"],
                "iArgs": [["id"]],
            },
        },
    ],
    "sink_method": "Runtime.exec",
}).encode()


CC1_IR = json.dumps({
    "chain_type": "hashcode_chain",
    "root_class": "java.util.HashMap",
    "root_trigger": "readObject→hash→hashCode",
    "links": [
        {
            "class": "org.apache.commons.collections.keyvalue.TiedMapEntry",
            "field_overrides": {
                "map": {"$ref": "link:1"},
                "key": "trigger",
            },
        },
        {
            "class": "org.apache.commons.collections.map.LazyMap",
            "field_overrides": {
                "factory": {"$ref": "link:2"},
            },
        },
        {
            "class": "org.apache.commons.collections.functors.ChainedTransformer",
            "field_overrides": {
                "iTransformers": [
                    {"$ref": "link:3"},
                    {"$ref": "link:4"},
                ],
            },
        },
        {
            "class": "org.apache.commons.collections.functors.ConstantTransformer",
            "field_overrides": {
                "iConstant": "java.lang.Runtime",
            },
        },
        {
            "class": "org.apache.commons.collections.functors.InvokerTransformer",
            "field_overrides": {
                "iMethodName": "exec",
                "iParamTypes": ["[Ljava.lang.String;"],
                "iArgs": [["id"]],
            },
        },
    ],
    "sink_method": "Runtime.exec",
}).encode()


class TestDeserMutator:
    def test_name(self):
        assert DeserMutator().name == "deser"

    def test_strategy_count(self):
        m = DeserMutator(seed=1)
        assert len(m._strategy_names) > 0
        assert len(m._weights) == len(m._strategy_names)

    def test_mutate_returns_valid_json(self):
        m = DeserMutator(seed=42)
        out = m.mutate(Input(data=MINIMAL_IR), [])
        ir = json.loads(out.data)
        assert "root_class" in ir
        assert "links" in ir

    def test_mutate_on_invalid_input_returns_fallback(self):
        m = DeserMutator(seed=1)
        out = m.mutate(Input(data=b"not-json"), [])
        ir = json.loads(out.data)
        assert "root_class" in ir

    def test_mutate_sets_metadata(self):
        m = DeserMutator(seed=7)
        out = m.mutate(Input(data=MINIMAL_IR), [])
        assert out.metadata.get("mutator") == "deser"
        assert "strategies" in out.metadata

    def test_type_swap_changes_class(self):
        m = DeserMutator(seed=1)
        # Run multiple times to find a successful type_swap
        changed = False
        for _ in range(50):
            out = m.mutate(Input(data=MINIMAL_IR), [])
            ir = json.loads(out.data)
            classes = {link["class"] for link in ir.get("links", [])}
            original_classes = {
                "org.apache.commons.collections4.comparators.TransformingComparator",
                "org.apache.commons.collections4.functors.InvokerTransformer",
            }
            if classes != original_classes:
                changed = True
                break
        assert changed, "type_swap should eventually change a class"

    def test_trigger_swap_changes_root(self):
        m = DeserMutator(seed=3)
        seen_roots = set()
        for _ in range(100):
            out = m.mutate(Input(data=MINIMAL_IR), [])
            ir = json.loads(out.data)
            seen_roots.add(ir.get("root_class", ""))
        assert len(seen_roots) > 1, "trigger_swap should produce different root classes"

    def test_chain_extend_adds_link(self):
        m = DeserMutator(seed=1)
        original_ir = json.loads(MINIMAL_IR)
        original_count = len(original_ir["links"])
        extended = False
        for _ in range(100):
            out = m.mutate(Input(data=MINIMAL_IR), [])
            ir = json.loads(out.data)
            if len(ir.get("links", [])) > original_count:
                extended = True
                break
        assert extended, "chain_extend should eventually add a link"

    def test_chain_truncate_removes_link(self):
        m = DeserMutator(seed=2)
        # Use CC1 IR which has 5 links
        original_ir = json.loads(CC1_IR)
        original_count = len(original_ir["links"])
        truncated = False
        for _ in range(100):
            out = m.mutate(Input(data=CC1_IR), [])
            ir = json.loads(out.data)
            if len(ir.get("links", [])) < original_count:
                truncated = True
                break
        assert truncated, "chain_truncate should eventually remove a link"

    def test_output_size_limit(self):
        m = DeserMutator(seed=1)
        for _ in range(20):
            out = m.mutate(Input(data=MINIMAL_IR), [])
            assert len(out.data) <= 16384

    def test_reset_weights(self):
        m = DeserMutator(seed=1)
        # Mutate a few times to change weights
        for _ in range(10):
            m.mutate(Input(data=MINIMAL_IR), [])
        m.reset_weights()
        # After reset, all weights should be back to defaults
        assert len(m._weights) == len(m._strategy_names)

    def test_field_inject_changes_method_name(self):
        m = DeserMutator(seed=5)
        seen_methods = set()
        for _ in range(100):
            out = m.mutate(Input(data=MINIMAL_IR), [])
            ir = json.loads(out.data)
            for link in ir.get("links", []):
                method = link.get("field_overrides", {}).get("iMethodName")
                if method and isinstance(method, str):
                    seen_methods.add(method)
        assert len(seen_methods) > 1, "field_inject should vary method names"

    def test_sink_swap_changes_sink(self):
        m = DeserMutator(seed=4)
        seen_sinks = set()
        for _ in range(100):
            out = m.mutate(Input(data=MINIMAL_IR), [])
            ir = json.loads(out.data)
            seen_sinks.add(ir.get("sink_method", ""))
        assert len(seen_sinks) > 1, "sink_swap should produce different sinks"
