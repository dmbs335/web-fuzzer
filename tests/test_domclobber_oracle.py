"""Tests for the DOM Clobbering oracle and differential strategies."""

import json

import pytest

from webfuzzer.fuzzer.protocols import ExecutionResult, Finding, Input, Severity
from webfuzzer.fuzzer.oracles.domclobber_oracle import DomClobberOracle
from webfuzzer.fuzzer.oracles.domclobber_diff_strategy import (
    ClobberVectorDivergenceStrategy,
    ClobberChainDepthStrategy,
    ClobberAnchorHrefStrategy,
    ClobberBuiltinShadowStrategy,
    ClobberDefenseStrategy,
    get_domclobber_strategies,
)


def _make_result(data: dict) -> ExecutionResult:
    """Create an ExecutionResult with JSON stdout."""
    return ExecutionResult(stdout=json.dumps(data).encode())


def _make_inp(html: str = '<a id="config" href="//evil.com">') -> Input:
    return Input(data=html.encode())


# ── Oracle tests ─────────────────────────────────────────────────


class TestDomClobberOracle:
    @pytest.fixture
    def oracle(self):
        return DomClobberOracle()

    def test_name(self, oracle):
        assert oracle.name == "domclobber"

    def test_no_finding_on_empty(self, oracle):
        inp = _make_inp()
        result = _make_result({})
        assert oracle.check(inp, result) is None

    def test_no_finding_on_zero_clobber(self, oracle):
        inp = _make_inp()
        result = _make_result({"clobber_count": 0, "divergence_count": 0})
        assert oracle.check(inp, result) is None

    def test_critical_dangerous_anchor(self, oracle):
        inp = _make_inp()
        result = _make_result({
            "clobber_count": 2,
            "clobber_chain_depth": 1,
            "clobber_has_anchor_href": True,
            "clobber_dangerous_targets": ["currentScript"],
            "clobber_builtins_shadowed": [],
            "clobber_ids": ["currentScript"],
            "clobber_names": [],
        })
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "currentScript" in finding.title
        assert finding.metadata["category"] == "dangerous_anchor"

    def test_high_form_chain(self, oracle):
        inp = _make_inp()
        result = _make_result({
            "clobber_count": 1,
            "clobber_chain_depth": 2,
            "clobber_has_anchor_href": False,
            "clobber_has_form_children": True,
            "clobber_dangerous_targets": [],
            "clobber_builtins_shadowed": [],
            "clobber_ids": ["config"],
            "clobber_names": [],
        })
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "form_chain"

    def test_high_dangerous_target_no_anchor(self, oracle):
        inp = _make_inp()
        result = _make_result({
            "clobber_count": 1,
            "clobber_chain_depth": 0,
            "clobber_has_anchor_href": False,
            "clobber_dangerous_targets": ["location"],
            "clobber_builtins_shadowed": [],
            "clobber_ids": ["location"],
            "clobber_names": [],
        })
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "dangerous_target"

    def test_high_browser_divergence(self, oracle):
        inp = _make_inp()
        result = _make_result({
            "clobber_count": 0,
            "divergence_count": 3,
            "clobber_has_anchor_href": False,
            "clobber_ids": [],
            "clobber_names": [],
        })
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "browser_divergence"

    def test_medium_builtin_shadow(self, oracle):
        inp = _make_inp()
        result = _make_result({
            "clobber_count": 1,
            "clobber_chain_depth": 0,
            "clobber_has_anchor_href": False,
            "clobber_dangerous_targets": [],
            "clobber_builtins_shadowed": ["getElementById"],
            "clobber_ids": [],
            "clobber_names": ["getElementById"],
        })
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "builtin_shadow"

    def test_low_basic_clobber(self, oracle):
        inp = _make_inp()
        result = _make_result({
            "clobber_count": 1,
            "clobber_chain_depth": 0,
            "clobber_has_anchor_href": False,
            "clobber_dangerous_targets": [],
            "clobber_builtins_shadowed": [],
            "clobber_ids": ["foo"],
            "clobber_names": [],
        })
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert finding.metadata["category"] == "basic_clobber"

    def test_non_json_stdout_returns_none(self, oracle):
        inp = _make_inp()
        result = ExecutionResult(stdout=b"not json at all")
        assert oracle.check(inp, result) is None

    def test_priority_order(self, oracle):
        """CRITICAL (dangerous+anchor) should take priority over lower categories."""
        inp = _make_inp()
        result = _make_result({
            "clobber_count": 3,
            "clobber_chain_depth": 2,
            "clobber_has_anchor_href": True,
            "clobber_has_form_children": True,
            "clobber_dangerous_targets": ["location"],
            "clobber_builtins_shadowed": ["getElementById"],
            "clobber_ids": ["location"],
            "clobber_names": ["getElementById"],
            "divergence_count": 2,
        })
        finding = oracle.check(inp, result)
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "dangerous_anchor"


# ── Diff strategy tests ──────────────────────────────────────────


class TestClobberVectorDivergence:
    def test_no_finding_when_equal(self):
        s = ClobberVectorDivergenceStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_ids": ["config"], "clobber_names": []})
        r = _make_result({"clobber_ids": ["config"], "clobber_names": []})
        assert s.compare(inp, p, r, 0) is None

    def test_finding_when_divergent(self):
        s = ClobberVectorDivergenceStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_ids": ["config", "location"], "clobber_names": []})
        r = _make_result({"clobber_ids": ["config"], "clobber_names": []})
        f = s.compare(inp, p, r, 0)
        assert f is not None
        assert f.metadata["strategy"] == "clobber_vector"

    def test_dangerous_target_is_high(self):
        s = ClobberVectorDivergenceStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_ids": ["currentScript"], "clobber_names": []})
        r = _make_result({"clobber_ids": [], "clobber_names": []})
        f = s.compare(inp, p, r, 0)
        assert f.severity == Severity.HIGH

    def test_custom_target_is_medium(self):
        s = ClobberVectorDivergenceStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_ids": ["myCustomVar"], "clobber_names": []})
        r = _make_result({"clobber_ids": [], "clobber_names": []})
        f = s.compare(inp, p, r, 0)
        assert f.severity == Severity.MEDIUM


class TestClobberChainDepth:
    def test_no_finding_when_equal(self):
        s = ClobberChainDepthStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_chain_depth": 1, "clobber_ids": []})
        r = _make_result({"clobber_chain_depth": 1, "clobber_ids": []})
        assert s.compare(inp, p, r, 0) is None

    def test_finding_when_different(self):
        s = ClobberChainDepthStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_chain_depth": 3, "clobber_ids": ["x"]})
        r = _make_result({"clobber_chain_depth": 1, "clobber_ids": ["x"]})
        f = s.compare(inp, p, r, 0)
        assert f is not None
        assert f.severity == Severity.HIGH
        assert f.metadata["primary_depth"] == 3
        assert f.metadata["ref_depth"] == 1


class TestClobberAnchorHref:
    def test_no_finding_when_equal(self):
        s = ClobberAnchorHrefStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_has_anchor_href": True, "clobber_ids": []})
        r = _make_result({"clobber_has_anchor_href": True, "clobber_ids": []})
        assert s.compare(inp, p, r, 0) is None

    def test_critical_when_divergent(self):
        s = ClobberAnchorHrefStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_has_anchor_href": True, "clobber_ids": ["x"]})
        r = _make_result({"clobber_has_anchor_href": False, "clobber_ids": ["x"]})
        f = s.compare(inp, p, r, 0)
        assert f is not None
        assert f.severity == Severity.CRITICAL
        assert f.metadata["primary_has_href"] is True
        assert f.metadata["ref_has_href"] is False


class TestClobberBuiltinShadow:
    def test_no_finding_when_equal(self):
        s = ClobberBuiltinShadowStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_builtins_shadowed": ["getElementById"]})
        r = _make_result({"clobber_builtins_shadowed": ["getElementById"]})
        assert s.compare(inp, p, r, 0) is None

    def test_finding_when_divergent(self):
        s = ClobberBuiltinShadowStrategy()
        inp = _make_inp()
        p = _make_result({"clobber_builtins_shadowed": ["getElementById", "querySelector"]})
        r = _make_result({"clobber_builtins_shadowed": ["getElementById"]})
        f = s.compare(inp, p, r, 0)
        assert f is not None
        assert f.severity == Severity.HIGH
        assert "querySelector" in f.metadata["only_primary"]


class TestClobberDefense:
    def test_no_finding_when_equal(self):
        s = ClobberDefenseStrategy()
        inp = _make_inp()
        p = _make_result({"sanitize_dom_active": True, "sanitize_named_props_active": False, "clobber_ids": []})
        r = _make_result({"sanitize_dom_active": True, "sanitize_named_props_active": False, "clobber_ids": []})
        assert s.compare(inp, p, r, 0) is None

    def test_finding_when_divergent(self):
        s = ClobberDefenseStrategy()
        inp = _make_inp()
        p = _make_result({"sanitize_dom_active": True, "sanitize_named_props_active": True, "clobber_ids": []})
        r = _make_result({"sanitize_dom_active": False, "sanitize_named_props_active": False, "clobber_ids": []})
        f = s.compare(inp, p, r, 0)
        assert f is not None
        assert f.severity == Severity.MEDIUM
        assert "sanitize_dom" in f.metadata["defense_differences"]

    def test_none_on_unparseable(self):
        s = ClobberDefenseStrategy()
        inp = _make_inp()
        p = ExecutionResult(stdout=b"garbage")
        r = _make_result({"sanitize_dom_active": True, "clobber_ids": []})
        assert s.compare(inp, p, r, 0) is None


class TestGetDomclobberStrategies:
    def test_returns_five_strategies(self):
        strats = get_domclobber_strategies()
        assert len(strats) == 5

    def test_strategy_names(self):
        strats = get_domclobber_strategies()
        names = [s.name for s in strats]
        assert "clobber_vector" in names
        assert "clobber_chain_depth" in names
        assert "clobber_anchor_href" in names
        assert "clobber_builtin_shadow" in names
        assert "clobber_defense" in names

    def test_all_have_compare_method(self):
        for s in get_domclobber_strategies():
            assert callable(getattr(s, "compare", None))
