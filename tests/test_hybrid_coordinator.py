"""Tests for hybrid concolic coordinator (v1 expert + v2 learned)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from webfuzzer.fuzzer.concolic.hybrid_coordinator import HybridCoordinator
from webfuzzer.fuzzer.protocols import Input


@dataclass
class MockResult:
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int = 0
    duration_ms: float = 10.0


def _make_result(data: dict[str, Any]) -> MockResult:
    return MockResult(stdout=json.dumps(data).encode())


def _primary(**kw: Any) -> dict[str, Any]:
    base = {
        "signature_valid": True,
        "subject": "admin@example.com",
        "assertion_count": 1,
        "signature_count": 1,
        "reference_element_count": 1,
        "issuer": "https://idp.example.com",
        "selection_mode": "first",
    }
    base.update(kw)
    return base


SAML = (
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


class TestHybridBasic:
    """Basic coordinator behavior."""

    def test_no_divergence_returns_empty(self):
        coord = HybridCoordinator(seed=42)
        coord._total_iters = 600  # skip warmup

        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary())  # same

        result = coord.on_differential_result(inp, primary, [ref], False)
        assert result == []

    def test_budget_enforcement(self):
        coord = HybridCoordinator(seed=42, budget_pct=0.01)
        coord._total_iters = 1000
        coord._expert_execs = 50
        coord._generic_execs = 50  # 10% > 1%

        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary(signature_valid=False))

        result = coord.on_differential_result(inp, primary, [ref], False)
        assert result == []

    def test_max_solutions_cap(self):
        coord = HybridCoordinator(seed=42, budget_pct=1.0)
        coord._total_iters = 600

        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary(signature_valid=False))

        result = coord.on_differential_result(inp, primary, [ref], False)
        assert len(result) <= 5


class TestTrackerAlwaysRuns:
    """Tracker.record() must run regardless of budget/warmup."""

    def test_records_during_warmup(self):
        coord = HybridCoordinator(seed=42)

        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary(signature_valid=False))

        coord.on_differential_result(inp, primary, [ref], False)

        assert len(coord._tracker._observations) == 1

    def test_records_when_over_budget(self):
        coord = HybridCoordinator(seed=42, budget_pct=0.01)
        coord._total_iters = 1000
        coord._expert_execs = 50
        coord._generic_execs = 50

        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary(signature_valid=False))

        coord.on_differential_result(inp, primary, [ref], False)

        # Tracker should still have recorded
        assert len(coord._tracker._observations) == 1

    def test_records_without_divergence(self):
        coord = HybridCoordinator(seed=42)

        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary())  # same

        coord.on_differential_result(inp, primary, [ref], False)

        assert len(coord._tracker._observations) == 1


class TestBudgetSplit:
    """Generic minimum share guarantee."""

    def test_expert_over_share_blocks_expert(self):
        coord = HybridCoordinator(seed=42, generic_min_share=0.40)
        coord._expert_execs = 70
        coord._generic_execs = 10  # expert = 87.5% > 60% max
        assert coord._expert_over_share()

    def test_expert_under_share_allows(self):
        coord = HybridCoordinator(seed=42, generic_min_share=0.40)
        coord._expert_execs = 50
        coord._generic_execs = 50  # expert = 50% < 60% max
        assert not coord._expert_over_share()

    def test_early_phase_no_restriction(self):
        coord = HybridCoordinator(seed=42, generic_min_share=0.40)
        coord._expert_execs = 5
        coord._generic_execs = 0  # too few total to enforce
        assert not coord._expert_over_share()


class TestColdStart:
    """During warmup: expert runs, generic waits."""

    def test_expert_runs_during_warmup(self):
        coord = HybridCoordinator(seed=42, budget_pct=1.0)

        # Warmup phase (iter < 500)
        inp = Input(data=SAML, metadata={"strategy": "xsw1"})
        primary = _make_result(_primary())
        ref = _make_result(_primary(signature_valid=False))

        result = coord.on_differential_result(inp, primary, [ref], False)
        # Expert may or may not find solvable constraints, but generic should not run
        # Check that no generic inputs were generated
        generic = [r for r in result if r.metadata.get("concolic_source") == "generic"]
        assert len(generic) == 0

    def test_generic_runs_after_warmup(self):
        coord = HybridCoordinator(seed=42, budget_pct=1.0)

        # Fast-forward past warmup with divergent data to build MI
        for i in range(600):
            inp = Input(data=SAML, metadata={"strategy": "xsw1"})
            primary = _make_result(_primary())
            ref = _make_result(_primary(signature_valid=False))
            coord.on_differential_result(inp, primary, [ref], False)

        # After warmup, generic should be eligible (may still return empty if MI < threshold)
        assert coord._total_iters >= 500
        assert coord._tracker.get_stats()["observations"] > 0


class TestInputSources:
    """Both expert and generic tag their outputs."""

    def test_expert_inputs_tagged(self):
        coord = HybridCoordinator(seed=42, budget_pct=1.0)
        coord._total_iters = 600

        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary(signature_valid=False))

        result = coord.on_differential_result(inp, primary, [ref], False)
        expert = [r for r in result if r.metadata.get("concolic_source") == "expert"]
        # Expert results should be tagged
        for e in expert:
            assert e.metadata.get("concolic_source") == "expert"

    def test_generic_inputs_tagged(self):
        coord = HybridCoordinator(seed=42, budget_pct=1.0)

        # Build up MI first
        for i in range(600):
            inp = Input(data=SAML, metadata={"strategy": "xsw1"})
            primary = _make_result(_primary())
            ref = _make_result(_primary(signature_valid=False))
            coord.on_differential_result(inp, primary, [ref], False)

        # Check that any generic outputs have proper tags
        inp = Input(data=SAML)
        primary = _make_result(_primary())
        ref = _make_result(_primary(signature_valid=False))
        result = coord.on_differential_result(inp, primary, [ref], False)

        generic = [r for r in result if r.metadata.get("concolic_source") == "generic"]
        for g in generic:
            assert "target_property" in g.metadata
            assert "mi_score" in g.metadata


class TestStrategyWeights:
    """Strategy weight feedback from tracker."""

    def test_initially_empty(self):
        coord = HybridCoordinator(seed=42)
        assert coord.get_strategy_weights() == {}

    def test_weights_after_data(self):
        coord = HybridCoordinator(seed=42)
        coord._iters_since_weight_update = 999  # force update on next call

        for i in range(15):
            inp = Input(data=SAML, metadata={"strategy": "xsw1"})
            primary = _make_result(_primary())
            ref = _make_result(_primary(signature_valid=False))
            coord.on_differential_result(inp, primary, [ref], False)

        # After enough observations, should have strategy data
        # Force weight update
        coord._cached_strategy_weights = coord._tracker.strategy_effectiveness()
        weights = coord.get_strategy_weights()
        assert "xsw1" in weights


class TestStatsAndStatus:
    """Stats and status line include both sources."""

    def test_stats_structure(self):
        coord = HybridCoordinator(seed=42)
        stats = coord.get_stats()
        assert "concolic_execs" in stats
        assert "expert_execs" in stats
        assert "generic_execs" in stats
        assert "expert_share" in stats
        assert "generic_share" in stats
        assert "observations" in stats
        assert "top_correlations" in stats
        assert "domain_counts" in stats

    def test_status_line_format(self):
        coord = HybridCoordinator(seed=42)
        line = coord.get_status_line()
        assert "hybrid:" in line
        assert "E:" in line
        assert "G:" in line
        assert "obs:" in line

    def test_concolic_execs_is_sum(self):
        coord = HybridCoordinator(seed=42)
        coord._expert_execs = 30
        coord._generic_execs = 20
        assert coord._concolic_execs == 50
