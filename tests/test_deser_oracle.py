"""Tests for the Java deserialization gadget chain oracle and diff strategies."""

import json

import pytest

from webfuzzer.fuzzer.protocols import Input, ExecutionResult, Severity


def _make_result(output: dict, exit_code: int = 0) -> ExecutionResult:
    """Create an ExecutionResult from a parsed output dict."""
    return ExecutionResult(
        exit_code=exit_code,
        stdout=json.dumps(output).encode(),
    )


def _open_target_result(**overrides) -> dict:
    """Base output for an open (no filter) deserialization target."""
    base = {
        "compiled": True,
        "deserialized": True,
        "sink_reached": None,
        "sink_depth": 0,
        "chain_classes": ["java.util.PriorityQueue"],
        "chain_class_hash": "abc123",
        "filter_decision": "ALLOWED",
        "filter_rejected_class": None,
        "readObject_calls": 1,
        "method_invocation_hash": "empty",
        "process_spawned": False,
        "jndi_lookup": False,
        "class_loaded": False,
        "file_accessed": False,
        "network_connected": False,
    }
    base.update(overrides)
    return base


class TestDeserDiffStrategies:
    def test_sink_reach_divergence(self):
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import SinkReachDivergenceStrategy

        strategy = SinkReachDivergenceStrategy()
        inp = Input(data=b'{"test": true}')

        # Target A reaches cmd_exec, Target B doesn't
        primary = _make_result(_open_target_result(sink_reached="cmd_exec", process_spawned=True))
        reference = _make_result(_open_target_result(sink_reached=None))

        result = strategy.compare(inp, primary, reference, 0)
        # SinkReachDivergenceStrategy returns list[Finding] | None
        assert result is not None
        findings = result if isinstance(result, list) else [result]
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_sink_reach_no_divergence(self):
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import SinkReachDivergenceStrategy

        strategy = SinkReachDivergenceStrategy()
        inp = Input(data=b'{}')

        primary = _make_result(_open_target_result(sink_reached=None))
        reference = _make_result(_open_target_result(sink_reached=None))

        result = strategy.compare(inp, primary, reference, 0)
        assert result is None or (isinstance(result, list) and len(result) == 0)

    def test_filter_bypass(self):
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import FilterBypassStrategy

        strategy = FilterBypassStrategy()
        inp = Input(data=b'{}')

        # Filtered target expected to reject but allowed
        primary = _make_result(_open_target_result(
            filter_decision="ALLOWED",
            deserialized=True,
        ))
        reference = _make_result(_open_target_result(
            filter_decision="REJECTED",
            filter_rejected_class="InvokerTransformer",
            deserialized=False,
        ))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_chain_depth_divergence(self):
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ChainDepthDivergenceStrategy

        strategy = ChainDepthDivergenceStrategy()
        inp = Input(data=b'{}')

        primary = _make_result(_open_target_result(sink_depth=2))
        reference = _make_result(_open_target_result(sink_depth=8))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None

    def test_chain_depth_no_divergence(self):
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ChainDepthDivergenceStrategy

        strategy = ChainDepthDivergenceStrategy()
        inp = Input(data=b'{}')

        primary = _make_result(_open_target_result(sink_depth=3))
        reference = _make_result(_open_target_result(sink_depth=4))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is None

    def test_class_resolution_divergence(self):
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ClassResolutionDivergenceStrategy

        strategy = ClassResolutionDivergenceStrategy()
        inp = Input(data=b'{}')

        primary = _make_result(_open_target_result(chain_class_hash="abc"))
        reference = _make_result(_open_target_result(chain_class_hash="xyz"))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None

    def test_exception_divergence(self):
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ExceptionDivergenceStrategy

        strategy = ExceptionDivergenceStrategy()
        inp = Input(data=b'{}')

        primary = _make_result(_open_target_result(deserialized=True))
        reference = _make_result(_open_target_result(deserialized=False))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None

    def test_exception_divergence_dead_chain_downgrade(self):
        """Dead chain (no sink, no side effects) → LOW severity.

        Java serialization invariants: empty readObject(), readResolve
        singleton, transient sink fields produce deserialized=true but
        no dangerous behavior.  The oracle should downgrade these to LOW.
        """
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ExceptionDivergenceStrategy

        strategy = ExceptionDivergenceStrategy()
        inp = Input(data=b'{}')

        # Accepting side: deserialized=true, but NO sink, NO side effects
        primary = _make_result(_open_target_result(
            deserialized=True, sink_reached=None,
            process_spawned=False, jndi_lookup=False,
            class_loaded=False, file_accessed=False,
            network_connected=False,
        ))
        reference = _make_result(_open_target_result(deserialized=False))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert "dead_chain" in finding.metadata["mechanism"]

    def test_exception_divergence_with_sink_stays_high(self):
        """Chain reaching a sink must NOT be downgraded."""
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ExceptionDivergenceStrategy

        strategy = ExceptionDivergenceStrategy()
        inp = Input(data=b'{}')

        # Accepting side reaches jndi_lookup sink
        primary = _make_result(_open_target_result(
            deserialized=True, sink_reached="jndi_lookup",
            jndi_lookup=True,
        ))
        reference = _make_result(_open_target_result(deserialized=False))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "dead_chain" not in finding.metadata["mechanism"]

    def test_exception_divergence_partial_deser_no_sink_is_low(self):
        """Partial deserialization (readObject_calls<=2) without sink → LOW.

        Previously escalated to HIGH blindly.  With FP fix, empty
        readObject() chains (readObject_calls=1, no sink) stay LOW.
        """
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ExceptionDivergenceStrategy

        strategy = ExceptionDivergenceStrategy()
        inp = Input(data=b'{}')

        primary = _make_result(_open_target_result(
            deserialized=True, readObject_calls=1,
            sink_reached=None,
            process_spawned=False, jndi_lookup=False,
        ))
        reference = _make_result(_open_target_result(deserialized=False))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.LOW

    def test_exception_divergence_partial_deser_with_sink_is_high(self):
        """Partial deserialization WITH dangerous behavior → HIGH."""
        from webfuzzer.fuzzer.oracles.deser_diff_strategy import ExceptionDivergenceStrategy

        strategy = ExceptionDivergenceStrategy()
        inp = Input(data=b'{}')

        primary = _make_result(_open_target_result(
            deserialized=True, readObject_calls=2,
            sink_reached="cmd_exec", process_spawned=True,
        ))
        reference = _make_result(_open_target_result(deserialized=False))

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["mechanism"] == "partial_deserialization"


class TestDeserOracle:
    def test_oracle_instantiation(self):
        from webfuzzer.fuzzer.oracles.deser_oracle import DeserOracle
        oracle = DeserOracle()
        assert oracle.name == "deser"


class TestDomainProfile:
    def test_deser_profile_registered(self):
        from webfuzzer.fuzzer.domain import get_profile
        profile = get_profile("deser")
        assert profile is not None
        assert profile.name == "deser"
        assert "deserialized" in profile.comparison_keys
        assert "sink_reached" in profile.comparison_keys
        assert len(profile.danger_ladder) == 6
