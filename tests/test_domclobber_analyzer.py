"""Tests for the DOM Clobbering static analyzer pipeline (JSParser + DomClobberAnalyzer)."""

import pytest

try:
    import tree_sitter_javascript  # noqa: F401
    _HAS_TREESITTER = True
except ImportError:
    _HAS_TREESITTER = False

from webfuzzer.guidance.analyzers.js_ast_parser import (
    JSParser,
    ClobberSource,
    ClobberSink,
    Guard,
    ParseResult,
    ScopeTree,
    FileIndex,
)
from webfuzzer.guidance.analyzers.js_domclobber_analyzer import (
    DomClobberAnalyzer,
    AnalysisResult,
)

pytestmark = pytest.mark.skipif(
    not _HAS_TREESITTER,
    reason="tree-sitter-javascript not installed",
)


@pytest.fixture
def parser():
    return JSParser()


# ── JSParser basic tests ─────────────────────────────────────────


class TestJSParserParse:
    def test_parse_returns_parse_result(self, parser):
        result = parser.parse_file("var x = 1;", file_id=0)
        assert isinstance(result, ParseResult)
        assert result.tree is not None

    def test_scope_tree_has_global(self, parser):
        result = parser.parse_file("var x = 1;", file_id=0)
        assert len(result.scope_tree.scopes) >= 1
        assert result.scope_tree.scopes[0].kind == "global"

    def test_declaration_tracked(self, parser):
        result = parser.parse_file("var myVar = 42;", file_id=0)
        global_scope = result.scope_tree.scopes[0]
        assert "myVar" in global_scope.declarations

    def test_function_creates_scope(self, parser):
        code = "function foo(a) { var b = 1; }"
        result = parser.parse_file(code, file_id=0)
        # Should have at least 2 scopes: global + function
        assert len(result.scope_tree.scopes) >= 2


# ── Source detection ─────────────────────────────────────────────


class TestFindSources:
    def test_p1_window_dot_x(self, parser):
        """P1: window.config should be detected as a source."""
        code = "var url = window.config;"
        result = parser.parse_file(code, file_id=0)
        props = [s.property_name for s in result.sources]
        assert "config" in props

    def test_p1_document_dot_x(self, parser):
        code = "var x = document.baseUrl;"
        result = parser.parse_file(code, file_id=0)
        props = [s.property_name for s in result.sources]
        assert "baseUrl" in props

    def test_p1_safe_props_excluded(self, parser):
        """Safe properties like addEventListener should not be sources."""
        code = "window.addEventListener('click', handler);"
        result = parser.parse_file(code, file_id=0)
        props = [s.property_name for s in result.sources]
        assert "addEventListener" not in props

    def test_p2_bare_global(self, parser):
        """P2: bare undeclared global should be detected."""
        code = "var x = someUndeclaredGlobal + 1;"
        result = parser.parse_file(code, file_id=0)
        patterns = [s.access_pattern for s in result.sources]
        assert any("bare:someUndeclaredGlobal" in p for p in patterns)

    def test_p2_declared_var_not_source(self, parser):
        """Declared variables should NOT be flagged as bare globals."""
        code = "var config = {}; var x = config;"
        result = parser.parse_file(code, file_id=0)
        patterns = [s.access_pattern for s in result.sources]
        assert not any("bare:config" in p for p in patterns)

    def test_p3_this_dot_x_global_scope(self, parser):
        """P3: this.X in global scope should be a source."""
        code = "var url = this.cdnUrl;"
        result = parser.parse_file(code, file_id=0)
        props = [s.property_name for s in result.sources]
        assert "cdnUrl" in props

    def test_priority_ordering(self, parser):
        """P1 (window.X) should have priority=1, P3 (this.X) should have priority=3."""
        code = "var a = window.config; var c = this.cdnUrl;"
        result = parser.parse_file(code, file_id=0)
        p1 = [s for s in result.sources if s.access_pattern.startswith("window.")]
        p3 = [s for s in result.sources if s.access_pattern.startswith("this.")]
        assert p1 and p3
        assert p1[0].priority < p3[0].priority  # 1 < 3


# ── Sink detection ───────────────────────────────────────────────


class TestFindSinks:
    def test_innerhtml_assignment(self, parser):
        code = "el.innerHTML = data;"
        result = parser.parse_file(code, file_id=0)
        types = [s.sink_type for s in result.sinks]
        assert "innerHTML" in types

    def test_eval_call(self, parser):
        code = "eval(payload);"
        result = parser.parse_file(code, file_id=0)
        types = [s.sink_type for s in result.sinks]
        assert "eval" in types

    def test_src_assignment(self, parser):
        code = "script.src = url;"
        result = parser.parse_file(code, file_id=0)
        types = [s.sink_type for s in result.sinks]
        assert "element.src" in types

    def test_document_write(self, parser):
        code = "document.write(html);"
        result = parser.parse_file(code, file_id=0)
        types = [s.sink_type for s in result.sinks]
        assert "document.write" in types

    def test_no_sink_on_safe_code(self, parser):
        code = "var x = 1 + 2; console.log(x);"
        result = parser.parse_file(code, file_id=0)
        assert len(result.sinks) == 0


# ── Guard detection ──────────────────────────────────────────────


class TestFindGuards:
    def test_typeof_check(self, parser):
        code = 'if (typeof config !== "undefined") { use(config); }'
        result = parser.parse_file(code, file_id=0)
        kinds = [g.kind for g in result.guards]
        assert "typeof_check" in kinds
        names = [g.checked_name for g in result.guards]
        assert "config" in names

    def test_or_default(self, parser):
        code = "var url = baseUrl || '/default';"
        result = parser.parse_file(code, file_id=0)
        kinds = [g.kind for g in result.guards]
        assert "or_default" in kinds

    def test_nullish_coalescing(self, parser):
        code = "var url = config ?? defaultConfig;"
        result = parser.parse_file(code, file_id=0)
        kinds = [g.kind for g in result.guards]
        assert "nullish_coalescing" in kinds


# ── DomClobberAnalyzer ───────────────────────────────────────────


class TestDomClobberAnalyzer:
    def test_analyze_file_no_gadgets_on_safe_code(self):
        analyzer = DomClobberAnalyzer()
        gadgets = analyzer.analyze_file("safe.js", content="var x = 1 + 2;")
        assert gadgets == []

    def test_analyze_file_detects_sources_and_sinks(self):
        """File with both sources and sinks should be analysable (PDG built)."""
        code = """\
var url = window.config;
document.getElementById('frame').src = url;
"""
        analyzer = DomClobberAnalyzer()
        # Verify sources and sinks are detected even if taint doesn't connect
        parse_result = analyzer._parser.parse_file(code, file_id=0)
        sources = parse_result.sources
        sinks = parse_result.sinks
        src_props = [s.property_name for s in sources]
        sink_types = [s.sink_type for s in sinks]
        assert "config" in src_props
        assert "element.src" in sink_types

    def test_analyze_file_webpack_sources(self):
        """Webpack-like pattern: __webpack_public_path__ detected as source."""
        code = """\
var publicPath = window.__webpack_public_path__ || '/';
var script = document.createElement('script');
script.src = publicPath + 'chunk.js';
"""
        analyzer = DomClobberAnalyzer()
        parse_result = analyzer._parser.parse_file(code, file_id=0)
        src_props = [s.property_name for s in parse_result.sources]
        sink_types = [s.sink_type for s in parse_result.sinks]
        assert "__webpack_public_path__" in src_props
        assert "element.src" in sink_types

    def test_min_score_filters(self):
        code = """\
var url = window.config;
el.innerHTML = url;
"""
        analyzer = DomClobberAnalyzer(min_score=9999)
        gadgets = analyzer.analyze_file("filtered.js", content=code)
        assert len(gadgets) == 0

    def test_analysis_result_summary(self):
        from webfuzzer.guidance.analyzers.js_taint_tracker import Gadget
        from webfuzzer.guidance.analyzers.js_ast_parser import ClobberSource, ClobberSink, Location
        ar = AnalysisResult(
            gadgets=[],
            total_sources=10,
            total_sinks=5,
            total_files=3,
            files_with_sources=2,
            files_with_sinks=1,
        )
        s = ar.summary()
        assert "Files: 3" in s
        assert "Sources: 10" in s


# ── FileIndex ────────────────────────────────────────────────────


class TestFileIndex:
    def test_add_and_needs_reanalysis(self):
        idx = FileIndex()
        fid = idx.add_file("a.js", "var x = 1;")
        assert fid == 0
        assert not idx.needs_reanalysis("a.js", "var x = 1;")
        assert idx.needs_reanalysis("a.js", "var x = 2;")
        assert idx.needs_reanalysis("b.js", "var y;")
