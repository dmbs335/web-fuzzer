"""Tests for HTML sanitizer differential strategies."""

import json
import pytest

from webfuzzer.fuzzer.protocols import ExecutionResult, Finding, Input, Severity
from webfuzzer.fuzzer.oracles.sanitizer_diff_strategy import (
    SanitizerBypassStrategy,
    SanitizerNamespaceDivergenceStrategy,
    SanitizerStructuralMutationStrategy,
    SanitizerDomClobberingStrategy,
    get_sanitizer_strategies,
    _parse_sanitizer_output,
)


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(
        exit_code=exit_code,
        stdout=json.dumps(data).encode(),
    )


# ── Fixtures ──────────────────────────────────────────────────

SAFE_OUTPUT = {
    "sanitized": "<p>Hello</p>",
    "elements_kept": ["p"],
    "attributes_kept": [],
    "has_script": False,
    "has_event_handler": False,
    "has_javascript_uri": False,
    "has_data_uri": False,
    "has_svg": False,
    "has_math": False,
    "has_style": False,
    "has_form": False,
    "has_base": False,
    "has_iframe": False,
    "has_object_embed": False,
    "has_noscript": False,
    "empty_output": False,
    "error": None,
}

SCRIPT_BYPASS_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": "<p>Hello</p><script>alert(1)</script>",
    "elements_kept": ["p", "script"],
    "has_script": True,
}

EVENT_HANDLER_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": '<img src=x onerror="alert(1)">',
    "elements_kept": ["img"],
    "attributes_kept": ["onerror", "src"],
    "has_event_handler": True,
}

JS_URI_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": '<a href="javascript:alert(1)">click</a>',
    "elements_kept": ["a"],
    "attributes_kept": ["href"],
    "has_javascript_uri": True,
}

SVG_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": "<svg><rect></rect></svg>",
    "elements_kept": ["rect", "svg"],
    "has_svg": True,
}

MATH_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": "<math><mi>x</mi></math>",
    "elements_kept": ["math", "mi"],
    "has_math": True,
}

SVG_MATH_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": "<svg><math><mtext>x</mtext></math></svg>",
    "elements_kept": ["math", "mtext", "svg"],
    "has_svg": True,
    "has_math": True,
}

FORM_CLOBBER_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": '<form id="location"><input name="href"></form>',
    "elements_kept": ["form", "input"],
    "attributes_kept": ["id", "name"],
    "has_form": True,
}

STYLE_FORM_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": "<style>body{color:red}</style><form><input></form>",
    "elements_kept": ["form", "input", "style"],
    "has_style": True,
    "has_form": True,
}

EMPTY_OUTPUT = {
    **SAFE_OUTPUT,
    "sanitized": "",
    "elements_kept": [],
    "attributes_kept": [],
    "empty_output": True,
}


# ── Parse output tests ───────────────────────────────────────


class TestParseOutput:
    def test_valid_json(self):
        data = json.dumps(SAFE_OUTPUT).encode()
        assert _parse_sanitizer_output(data) is not None

    def test_empty_bytes(self):
        assert _parse_sanitizer_output(b"") is None

    def test_invalid_json(self):
        assert _parse_sanitizer_output(b"not json") is None

    def test_unrelated_json(self):
        assert _parse_sanitizer_output(b'{"foo": "bar"}') is None

    def test_error_with_known_key_still_parses(self):
        """Error present but known keys exist → parse succeeds (partial result)."""
        data = json.dumps({"error": "parse failed", "empty_output": True}).encode()
        assert _parse_sanitizer_output(data) is not None

    def test_error_only_returns_none(self):
        """Error without any known key → None."""
        data = json.dumps({"error": "parse failed"}).encode()
        assert _parse_sanitizer_output(data) is None

    def test_partial_with_security_signal(self):
        """Partial output with has_script → parse succeeds."""
        data = json.dumps({"has_script": True, "error": "timeout"}).encode()
        assert _parse_sanitizer_output(data) is not None


# ── SanitizerBypassStrategy tests ─────────────────────────────


class TestSanitizerBypassStrategy:
    @pytest.fixture
    def strategy(self):
        return SanitizerBypassStrategy()

    def test_name(self, strategy):
        assert strategy.name == "sanitizer_bypass"

    def test_both_safe_no_finding(self, strategy):
        """Both sanitizers produce safe output -> no finding."""
        inp = Input(data=b"<script>alert(1)</script>")
        primary = _make_result(SAFE_OUTPUT)
        reference = _make_result(SAFE_OUTPUT)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_script_bypass_critical(self, strategy):
        """Primary allows script, reference blocks -> CRITICAL."""
        inp = Input(data=b"<script>alert(1)</script>")
        primary = _make_result(SCRIPT_BYPASS_OUTPUT)
        reference = _make_result(SAFE_OUTPUT)
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "script_bypass" in finding.metadata["category"]
        assert "primary" in finding.metadata["allowing_side"]

    def test_event_handler_bypass_critical(self, strategy):
        """Reference allows event handler, primary blocks -> CRITICAL."""
        inp = Input(data=b'<img onerror="alert(1)">')
        primary = _make_result(SAFE_OUTPUT)
        reference = _make_result(EVENT_HANDLER_OUTPUT)
        finding = strategy.compare(inp, primary, reference, 1)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "event_handler_bypass"
        assert "ref[1]" in finding.metadata["allowing_side"]

    def test_javascript_uri_bypass_critical(self, strategy):
        """Primary allows javascript: URI -> CRITICAL."""
        inp = Input(data=b'<a href="javascript:alert(1)">x</a>')
        primary = _make_result(JS_URI_OUTPUT)
        reference = _make_result(SAFE_OUTPUT)
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.metadata["category"] == "javascript_uri_bypass"

    def test_both_allow_script_no_finding(self, strategy):
        """Both allow script -> no finding (same behavior)."""
        inp = Input(data=b"<script>alert(1)</script>")
        primary = _make_result(SCRIPT_BYPASS_OUTPUT)
        reference = _make_result(SCRIPT_BYPASS_OUTPUT)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_both_fail_no_finding(self, strategy):
        """Both targets fail to parse -> no finding."""
        inp = Input(data=b"garbage")
        primary = ExecutionResult(exit_code=1, stdout=b"")
        reference = ExecutionResult(exit_code=1, stdout=b"")
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_one_sided_with_dangerous(self, strategy):
        """One target parses with dangerous content, other crashes."""
        inp = Input(data=b"<script>alert(1)</script>")
        primary = _make_result(SCRIPT_BYPASS_OUTPUT)
        reference = ExecutionResult(exit_code=1, stdout=b"")
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_one_sided_no_dangerous_no_finding(self, strategy):
        """One target parses safely, other crashes -> no finding."""
        inp = Input(data=b"<p>hello</p>")
        primary = _make_result(SAFE_OUTPUT)
        reference = ExecutionResult(exit_code=1, stdout=b"")
        assert strategy.compare(inp, primary, reference, 0) is None


# ── SanitizerNamespaceDivergenceStrategy tests ────────────────


class TestNamespaceDivergenceStrategy:
    @pytest.fixture
    def strategy(self):
        return SanitizerNamespaceDivergenceStrategy()

    def test_name(self, strategy):
        assert strategy.name == "sanitizer_namespace"

    def test_same_namespace_no_finding(self, strategy):
        """Both keep SVG -> no finding."""
        inp = Input(data=b"<svg></svg>")
        primary = _make_result(SVG_OUTPUT)
        reference = _make_result(SVG_OUTPUT)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_neither_has_namespace_no_finding(self, strategy):
        """Neither has namespace elements -> no finding."""
        inp = Input(data=b"<p>hello</p>")
        primary = _make_result(SAFE_OUTPUT)
        reference = _make_result(SAFE_OUTPUT)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_primary_keeps_svg_ref_strips(self, strategy):
        """Primary keeps SVG, reference strips -> HIGH."""
        inp = Input(data=b"<svg><style>x</style></svg>")
        primary = _make_result(SVG_OUTPUT)
        reference = _make_result(SAFE_OUTPUT)
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert finding.metadata["category"] == "namespace_divergence"
        assert "svg" in finding.metadata["only_primary"]
        assert "primary_sanitized" in finding.metadata
        assert "ref_sanitized" in finding.metadata

    def test_ref_keeps_math_primary_strips(self, strategy):
        """Reference keeps math, primary strips -> HIGH."""
        inp = Input(data=b"<math><mi>x</mi></math>")
        primary = _make_result(SAFE_OUTPUT)
        reference = _make_result(MATH_OUTPUT)
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_different_namespace_sets(self, strategy):
        """Primary has svg+math, reference has only svg -> HIGH."""
        inp = Input(data=b"<svg><math></math></svg>")
        primary = _make_result(SVG_MATH_OUTPUT)
        ref_data = {**SVG_OUTPUT, "elements_kept": ["svg"]}
        reference = _make_result(ref_data)
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert "math" in finding.metadata["only_primary"] or "mtext" in finding.metadata["only_primary"]


# ── SanitizerStructuralMutationStrategy tests ─────────────────


class TestStructuralMutationStrategy:
    @pytest.fixture
    def strategy(self):
        return SanitizerStructuralMutationStrategy()

    def test_name(self, strategy):
        assert strategy.name == "sanitizer_structural"

    def test_same_elements_no_finding(self, strategy):
        """Same security-relevant elements -> no finding."""
        inp = Input(data=b"<style>x</style>")
        d1 = {**SAFE_OUTPUT, "elements_kept": ["p", "style"], "has_style": True}
        d2 = {**SAFE_OUTPUT, "elements_kept": ["p", "style"], "has_style": True}
        primary = _make_result(d1)
        reference = _make_result(d2)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_cosmetic_diff_no_finding(self, strategy):
        """Different non-security elements (div vs span) -> no finding."""
        inp = Input(data=b"<div>hello</div>")
        d1 = {**SAFE_OUTPUT, "elements_kept": ["div"]}
        d2 = {**SAFE_OUTPUT, "elements_kept": ["span"]}
        primary = _make_result(d1)
        reference = _make_result(d2)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_form_divergence_medium(self, strategy):
        """Primary keeps form, reference strips -> MEDIUM."""
        inp = Input(data=b"<form></form>")
        d1 = {**SAFE_OUTPUT, "elements_kept": ["form", "p"], "has_form": True}
        d2 = {**SAFE_OUTPUT, "elements_kept": ["p"]}
        primary = _make_result(d1)
        reference = _make_result(d2)
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert "form" in finding.metadata["only_primary"]

    def test_namespace_elements_deferred(self, strategy):
        """SVG/math differences handled by namespace strategy, not this one."""
        inp = Input(data=b"<svg></svg>")
        d1 = {**SVG_OUTPUT}
        d2 = {**SAFE_OUTPUT}
        primary = _make_result(d1)
        reference = _make_result(d2)
        # svg is in _NAMESPACE_ELEMENTS, so should be excluded here
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is None


# ── SanitizerDomClobberingStrategy tests ──────────────────────


class TestDomClobberingStrategy:
    @pytest.fixture
    def strategy(self):
        return SanitizerDomClobberingStrategy()

    def test_name(self, strategy):
        assert strategy.name == "sanitizer_clobbering"

    def test_no_clobber_no_finding(self, strategy):
        """Neither has clobbering vectors -> no finding."""
        inp = Input(data=b"<p>hello</p>")
        primary = _make_result(SAFE_OUTPUT)
        reference = _make_result(SAFE_OUTPUT)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_both_clobber_no_finding(self, strategy):
        """Both allow clobbering vectors -> no finding (same behavior)."""
        inp = Input(data=b'<form id="x"><input name="y"></form>')
        primary = _make_result(FORM_CLOBBER_OUTPUT)
        reference = _make_result(FORM_CLOBBER_OUTPUT)
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_primary_clobber_ref_clean(self, strategy):
        """Primary allows clobbering, reference strips -> MEDIUM."""
        inp = Input(data=b'<form id="location"><input name="href"></form>')
        primary = _make_result(FORM_CLOBBER_OUTPUT)
        reference = _make_result(SAFE_OUTPUT)
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM
        assert finding.metadata["category"] == "dom_clobbering"

    def test_clobber_needs_both_attrs_and_elements(self, strategy):
        """Has id but no clobbering element -> no finding."""
        inp = Input(data=b'<p id="x">text</p>')
        d1 = {**SAFE_OUTPUT, "elements_kept": ["p"], "attributes_kept": ["id"]}
        d2 = {**SAFE_OUTPUT}
        primary = _make_result(d1)
        reference = _make_result(d2)
        assert strategy.compare(inp, primary, reference, 0) is None


# ── Factory test ──────────────────────────────────────────────


class TestFactory:
    def test_get_sanitizer_strategies(self):
        strategies = get_sanitizer_strategies()
        assert len(strategies) == 4
        names = [s.name for s in strategies]
        assert "sanitizer_bypass" in names
        assert "sanitizer_namespace" in names
        assert "sanitizer_structural" in names
        assert "sanitizer_clobbering" in names

    def test_strategies_have_compare(self):
        for s in get_sanitizer_strategies():
            assert hasattr(s, "compare")
            assert callable(s.compare)
