"""Tests for class pollution oracle."""
from __future__ import annotations

import json
import pytest

from webfuzzer.fuzzer.oracles.class_pollution_oracle import ClassPollutionOracle
from webfuzzer.fuzzer.protocols import ExecutionResult, Input, Severity


@pytest.fixture
def oracle():
    return ClassPollutionOracle()


@pytest.fixture
def base_input():
    return Input(data=b'{"merge_fn":"recursive_merge","payload":{"__class__":{"admin":true}}}')


def _make_result(output: dict) -> ExecutionResult:
    return ExecutionResult(
        exit_code=0,
        stdout=json.dumps(output).encode(),
    )


class TestClassPollutionOracle:
    def test_no_finding_on_failed_merge(self, oracle, base_input):
        result = _make_result({"merged": False, "error": "blocked", "merge_impl": "filtered"})
        finding = oracle.check(base_input, result)
        assert finding is None

    def test_no_finding_on_clean_merge(self, oracle, base_input):
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge_filtered",
            "globals_polluted": [], "class_attrs_changed": {},
            "attrs_changed": {}, "chain_depth": 0, "dunder_traversed": [],
        })
        finding = oracle.check(base_input, result)
        assert finding is None

    def test_critical_on_dangerous_globals(self, oracle, base_input):
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": ["os", "SECRET_KEY"],
            "globals_polluted_count": 2,
            "class_attrs_changed": {}, "attrs_changed": {},
            "chain_depth": 3, "dunder_traversed": ["__class__", "__init__", "__globals__"],
        })
        finding = oracle.check(base_input, result)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "os" in finding.title
        assert finding.metadata["category"] == "globals_write"

    def test_high_on_non_dangerous_globals(self, oracle, base_input):
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": ["SECRET_KEY"],
            "globals_polluted_count": 1,
            "class_attrs_changed": {}, "attrs_changed": {},
            "chain_depth": 3, "dunder_traversed": ["__class__", "__init__", "__globals__"],
        })
        finding = oracle.check(base_input, result)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_critical_on_security_class_attrs(self, oracle, base_input):
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": [],
            "class_attrs_changed": {"admin": {"before": False, "after": True}},
            "class_attrs_changed_count": 1,
            "attrs_changed": {}, "chain_depth": 1,
            "dunder_traversed": ["__class__"],
        })
        finding = oracle.check(base_input, result)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "admin" in finding.title

    def test_high_on_generic_class_attrs(self, oracle, base_input):
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": [],
            "class_attrs_changed": {"level": {"before": 1, "after": 9999}},
            "class_attrs_changed_count": 1,
            "attrs_changed": {}, "chain_depth": 1,
            "dunder_traversed": ["__class__"],
        })
        finding = oracle.check(base_input, result)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_medium_on_dunder_traversal_only(self, oracle, base_input):
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": [],
            "class_attrs_changed": {}, "attrs_changed": {},
            "chain_depth": 1,
            "dunder_traversed": ["__class__"],
            "dunder_traversed_count": 1,
        })
        finding = oracle.check(base_input, result)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "dunder_reachability"

    def test_fingerprint_stability(self, oracle, base_input):
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": ["os"],
            "class_attrs_changed": {}, "attrs_changed": {},
            "chain_depth": 3, "dunder_traversed": ["__class__", "__init__", "__globals__"],
        })
        f1 = oracle.check(base_input, result)
        f2 = oracle.check(base_input, result)
        assert f1.fingerprint == f2.fingerprint

    def test_no_finding_on_empty_stdout(self, oracle, base_input):
        result = ExecutionResult(exit_code=0, stdout=b"")
        assert oracle.check(base_input, result) is None

    def test_no_finding_on_non_json(self, oracle, base_input):
        result = ExecutionResult(exit_code=0, stdout=b"not json")
        assert oracle.check(base_input, result) is None

    def test_priority_globals_over_class_attrs(self, oracle, base_input):
        """Globals pollution should have higher priority than class attrs."""
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": ["os"],
            "class_attrs_changed": {"admin": {"before": False, "after": True}},
            "attrs_changed": {}, "chain_depth": 3,
            "dunder_traversed": ["__class__", "__init__", "__globals__"],
        })
        finding = oracle.check(base_input, result)
        assert finding.metadata["category"] == "globals_write"

    def test_callable_sink_detection(self, oracle, base_input):
        """Callable sinks reachable should trigger HIGH finding."""
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": [], "class_attrs_changed": {},
            "attrs_changed": {}, "chain_depth": 3,
            "dunder_traversed": ["__class__", "__init__"],
            "globals_reachable": ["os", "__builtins__.eval"],
            "sink_types": {"os": "module", "__builtins__.eval": "callable"},
            "access_path": ["__class__", "__init__", "__globals__"],
            "access_path_hash": "abc12345",
        })
        finding = oracle.check(base_input, result)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "sink_reachability"
        assert "__builtins__.eval" in finding.metadata["callable_sinks"]

    def test_access_path_in_fingerprint(self, oracle, base_input):
        """Fingerprints should include access_path_hash for dedup."""
        result = _make_result({
            "merged": True, "merge_impl": "recursive_merge",
            "globals_polluted": ["os"],
            "class_attrs_changed": {}, "attrs_changed": {},
            "chain_depth": 3,
            "dunder_traversed": ["__class__", "__init__", "__globals__"],
            "access_path_hash": "deadbeef",
        })
        finding = oracle.check(base_input, result)
        assert "deadbeef" in finding.fingerprint
