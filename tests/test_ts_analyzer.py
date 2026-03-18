"""Tests for multi-language tree-sitter AST analyzer and dynamic branch DB."""

from __future__ import annotations

import os
import random
import tempfile

import pytest

from webfuzzer.fuzzer.concolic.ts_analyzer import (
    TreeSitterBranchExtractor,
    supported_extensions,
    _get_parser,
)
from webfuzzer.fuzzer.concolic.ast_analyzer import (
    AstBranchExtractor,
    ExtractedBranch,
    map_branches_to_mutations,
)
from webfuzzer.fuzzer.concolic.dynamic_branch_db import DynamicBranchDB
from webfuzzer.fuzzer.concolic.domain_plugin import DomainPlugin
from webfuzzer.fuzzer.concolic.plugins.saml_plugin import SamlPlugin
from webfuzzer.fuzzer.concolic.plugins.jwt_plugin import JwtPlugin
from webfuzzer.fuzzer.concolic.plugins.cookie_plugin import CookiePlugin
from webfuzzer.fuzzer.concolic.plugins.registry import get_plugin


# ── Fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def ts_extractor():
    return TreeSitterBranchExtractor()


@pytest.fixture
def py_extractor():
    return AstBranchExtractor()


# ── TreeSitterBranchExtractor tests ──────────────────────────────


class TestTreeSitterBasic:
    """Basic tree-sitter parser loading and extraction."""

    def test_supported_extensions(self):
        exts = supported_extensions()
        assert ".py" in exts
        assert ".js" in exts
        assert ".java" in exts
        assert ".go" in exts
        assert ".rs" in exts
        assert ".rb" in exts

    def test_parser_loads_js(self):
        result = _get_parser(".js")
        assert result is not None

    def test_parser_loads_python(self):
        result = _get_parser(".py")
        assert result is not None

    def test_parser_unknown_ext(self):
        result = _get_parser(".xyz")
        assert result is None

    def test_extract_js_if(self, ts_extractor, tmp_path):
        js_file = tmp_path / "test.js"
        js_file.write_text(
            'function verify(sig) {\n'
            '  if (sig.algorithm === "none") { throw new Error("bad alg"); }\n'
            '  if (sig.keyInfo !== null) { return true; }\n'
            '}\n'
        )
        branches = ts_extractor.analyze_file(str(js_file), "test-lib")
        assert len(branches) >= 2
        conds = [b.condition_source for b in branches]
        assert any("algorithm" in c or "none" in c for c in conds)
        assert any("keyInfo" in c for c in conds)

    def test_extract_java_if(self, ts_extractor, tmp_path):
        java_file = tmp_path / "Test.java"
        java_file.write_text(
            'class Test {\n'
            '  void verify(String alg) {\n'
            '    if (alg == null) { throw new Exception(); }\n'
            '    if (alg.startsWith("RS")) { return; }\n'
            '  }\n'
            '}\n'
        )
        branches = ts_extractor.analyze_file(str(java_file), "test-java")
        assert len(branches) >= 1

    def test_extract_go_if(self, ts_extractor, tmp_path):
        go_file = tmp_path / "main.go"
        go_file.write_text(
            'package main\n'
            'func verify(uri string) bool {\n'
            '  if uri == "" { return false }\n'
            '  if len(uri) > 1024 { return false }\n'
            '  return true\n'
            '}\n'
        )
        branches = ts_extractor.analyze_file(str(go_file), "test-go")
        assert len(branches) >= 1

    def test_extract_rust_if(self, ts_extractor, tmp_path):
        rs_file = tmp_path / "main.rs"
        rs_file.write_text(
            'fn verify(key: &str) -> bool {\n'
            '  if key.starts_with("xmlns:") { return true; }\n'
            '  false\n'
            '}\n'
        )
        branches = ts_extractor.analyze_file(str(rs_file), "test-rust")
        assert len(branches) >= 1

    def test_extract_ruby_if(self, ts_extractor, tmp_path):
        rb_file = tmp_path / "test.rb"
        rb_file.write_text(
            'def verify(signature)\n'
            '  if signature.nil?\n'
            '    raise "no sig"\n'
            '  end\n'
            '  unless signature.valid?\n'
            '    raise "invalid"\n'
            '  end\n'
            'end\n'
        )
        branches = ts_extractor.analyze_file(str(rb_file), "test-ruby")
        assert len(branches) >= 1

    def test_empty_file(self, ts_extractor, tmp_path):
        js_file = tmp_path / "empty.js"
        js_file.write_text("")
        branches = ts_extractor.analyze_file(str(js_file), "test")
        assert branches == []

    def test_nonexistent_file(self, ts_extractor):
        branches = ts_extractor.analyze_file("/nonexistent/file.js", "test")
        assert branches == []

    def test_syntax_error_tolerant(self, ts_extractor, tmp_path):
        js_file = tmp_path / "bad.js"
        js_file.write_text("if (( { broken syntax {{{")
        # Should not raise, just return empty or partial
        branches = ts_extractor.analyze_file(str(js_file), "test")
        assert isinstance(branches, list)


class TestTreeSitterPropertyDetection:
    """Test input property detection from conditions."""

    def test_detects_namespace(self, ts_extractor, tmp_path):
        js_file = tmp_path / "test.js"
        js_file.write_text('if (node.namespaceURI === "urn:test") {}')
        branches = ts_extractor.analyze_file(str(js_file), "test")
        assert len(branches) >= 1
        props = branches[0].input_properties
        assert "namespace" in props

    def test_detects_algorithm(self, ts_extractor, tmp_path):
        js_file = tmp_path / "test.js"
        js_file.write_text('if (sig.Algorithm === "rsa-sha256") {}')
        branches = ts_extractor.analyze_file(str(js_file), "test")
        assert any("algorithm" in b.input_properties for b in branches)

    def test_detects_subject(self, ts_extractor, tmp_path):
        js_file = tmp_path / "test.js"
        js_file.write_text('if (assertion.Subject !== null) {}')
        branches = ts_extractor.analyze_file(str(js_file), "test")
        assert any("subject" in b.input_properties for b in branches)

    def test_trivial_condition_skipped(self, ts_extractor, tmp_path):
        js_file = tmp_path / "test.js"
        js_file.write_text('if (typeof module !== "undefined") {}')
        branches = ts_extractor.analyze_file(str(js_file), "test")
        assert len(branches) == 0  # trivial, should be skipped


class TestTreeSitterDirectory:
    """Test directory-level analysis."""

    def test_analyze_directory(self, ts_extractor, tmp_path):
        # Create a mini project
        (tmp_path / "lib").mkdir()
        (tmp_path / "lib" / "verify.js").write_text(
            'if (sig.valid) { return true; }\n'
            'if (sig.algorithm === "none") { throw "bad"; }\n'
        )
        (tmp_path / "lib" / "parse.js").write_text(
            'if (token.header.alg) { decoded = true; }\n'
        )
        # test dir should be skipped
        (tmp_path / "test").mkdir()
        (tmp_path / "test" / "test_verify.js").write_text(
            'if (result === expected) { pass(); }\n'
        )

        branches = ts_extractor.analyze_directory(str(tmp_path), "test-proj")
        # Should include lib/ but not test/
        files = {b.file for b in branches}
        assert "verify.js" in files or "parse.js" in files
        assert "test_verify.js" not in files


# ── Python AST extractor tests (existing + new) ─────────────────


class TestPythonAstExtractor:
    """Test Python-specific AST extractor."""

    def test_analyze_signxml(self, py_extractor):
        try:
            branches = py_extractor.analyze_module("signxml")
        except ImportError:
            pytest.skip("signxml not installed")
        assert len(branches) > 50
        negatable = [b for b in branches if b.negatable]
        assert len(negatable) > 30

    def test_analyze_pyjwt(self, py_extractor):
        try:
            branches = py_extractor.analyze_module("jwt")
        except ImportError:
            pytest.skip("pyjwt not installed")
        assert len(branches) > 30

    def test_mutation_mapping(self, py_extractor):
        try:
            branches = py_extractor.analyze_module("signxml")
        except ImportError:
            pytest.skip("signxml not installed")
        mapped = map_branches_to_mutations(branches)
        assert len(mapped) > 20
        for branch, mutations in mapped:
            assert len(mutations) > 0
            assert all(isinstance(m, str) for m in mutations)


# ── Real library tests ───────────────────────────────────────────


class TestRealNodeModules:
    """Test on actual installed node modules (skip if not available)."""

    def _skip_if_no_module(self, path):
        if not os.path.isdir(path):
            pytest.skip(f"{path} not found")

    def test_xml_crypto(self, ts_extractor):
        path = "targets/node_modules/xml-crypto"
        self._skip_if_no_module(path)
        branches = ts_extractor.analyze_directory(path, "xml-crypto", [".js"])
        assert len(branches) > 50

    def test_node_saml(self, ts_extractor):
        path = "targets/node_modules/@node-saml/node-saml"
        self._skip_if_no_module(path)
        branches = ts_extractor.analyze_directory(path, "node-saml", [".js", ".ts"])
        assert len(branches) > 20

    def test_samlify(self, ts_extractor):
        path = "targets/node_modules/samlify"
        self._skip_if_no_module(path)
        branches = ts_extractor.analyze_directory(path, "samlify", [".js"])
        assert len(branches) > 50


# ── DynamicBranchDB tests ────────────────────────────────────────


class TestDynamicBranchDB:
    """Test dynamic branch DB with plugins."""

    def test_saml_db_creation(self):
        db = DynamicBranchDB(domain_plugin=SamlPlugin())
        try:
            n = db.analyze_module("signxml")
        except ImportError:
            pytest.skip("signxml not installed")
        assert n > 20
        assert db.total_branches > 20

    def test_jwt_db_creation(self):
        db = DynamicBranchDB(domain_plugin=JwtPlugin())
        try:
            n = db.analyze_module("jwt")
        except ImportError:
            pytest.skip("pyjwt not installed")
        assert n > 10
        assert db.total_branches > 10

    def test_generate_targeted_saml(self):
        db = DynamicBranchDB(domain_plugin=SamlPlugin())
        try:
            db.analyze_module("signxml")
        except ImportError:
            pytest.skip("signxml not installed")

        saml_data = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1">'
            b'<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>'
            b'</saml:Assertion></samlp:Response>'
        )
        rng = random.Random(42)
        mutations = db.generate_targeted(saml_data, rng, max_mutations=3)
        assert len(mutations) > 0
        for mutated, branch_info in mutations:
            assert isinstance(mutated, bytes)
            assert mutated != saml_data
            assert branch_info.tried

    def test_generate_targeted_jwt(self):
        db = DynamicBranchDB(domain_plugin=JwtPlugin())
        try:
            db.analyze_module("jwt")
        except ImportError:
            pytest.skip("pyjwt not installed")

        jwt_data = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"
        rng = random.Random(42)
        mutations = db.generate_targeted(jwt_data, rng, max_mutations=3)
        assert len(mutations) > 0
        for mutated, _ in mutations:
            assert isinstance(mutated, bytes)

    def test_round_robin_advances(self):
        db = DynamicBranchDB(domain_plugin=SamlPlugin())
        try:
            db.analyze_module("signxml")
        except ImportError:
            pytest.skip("signxml not installed")

        rng = random.Random(42)
        data = b"<root/>"

        first_batch = db.generate_targeted(data, rng, max_mutations=3)
        second_batch = db.generate_targeted(data, rng, max_mutations=3)
        # Should try different branches (round-robin)
        first_lines = {db.branch.line_start for _, db in first_batch}
        second_lines = {db.branch.line_start for _, db in second_batch}
        # At least some should differ (unless very few branches)
        if db.total_branches > 6:
            assert first_lines != second_lines

    def test_on_result_feedback(self):
        db = DynamicBranchDB(domain_plugin=SamlPlugin())
        try:
            db.analyze_module("signxml")
        except ImportError:
            pytest.skip("signxml not installed")

        rng = random.Random(42)
        mutations = db.generate_targeted(b"<root/>", rng, max_mutations=1)
        if mutations:
            _, branch_info = mutations[0]
            assert branch_info.success_count == 0
            db.on_result(branch_info, True)
            assert branch_info.success_count == 1

    def test_empty_db_returns_empty(self):
        db = DynamicBranchDB(domain_plugin=SamlPlugin())
        rng = random.Random(42)
        mutations = db.generate_targeted(b"<root/>", rng)
        assert mutations == []

    def test_no_plugin_returns_empty(self):
        db = DynamicBranchDB(domain_plugin=None)
        rng = random.Random(42)
        mutations = db.generate_targeted(b"<root/>", rng)
        assert mutations == []

    def test_stats(self):
        db = DynamicBranchDB(domain_plugin=SamlPlugin())
        try:
            db.analyze_module("signxml")
        except ImportError:
            pytest.skip("signxml not installed")

        stats = db.get_stats()
        assert "total_branches" in stats
        assert "tried" in stats
        assert "by_library" in stats
        assert stats["total_branches"] > 0


# ── Plugin registry tests ────────────────────────────────────────


class TestPluginRegistry:
    """Test domain plugin auto-detection."""

    def test_saml_detection(self):
        p = get_plugin(oracle="saml")
        assert isinstance(p, SamlPlugin)

    def test_jwt_detection(self):
        p = get_plugin(oracle="jwt")
        assert isinstance(p, JwtPlugin)

    def test_cookie_detection(self):
        p = get_plugin(oracle="cookie")
        assert isinstance(p, CookiePlugin)

    def test_unknown_returns_none(self):
        p = get_plugin(oracle="graphql")
        assert p is None

    def test_grammar_fallback(self):
        p = get_plugin(grammar="saml")
        assert isinstance(p, SamlPlugin)


# ── Plugin property/perturbation tests ───────────────────────────


class TestPluginPerturbation:
    """Test that each plugin can extract and perturb."""

    def test_saml_extract_perturb(self):
        p = SamlPlugin()
        data = b'<Response><Assertion ID="_a1"><Subject><NameID>user</NameID></Subject></Assertion></Response>'
        pv = p.extract(data)
        assert len(pv.values) == p.num_properties
        mutations = p.perturb(data, 10, random.Random(42))  # assertion_count
        assert len(mutations) >= 1

    def test_jwt_extract_perturb(self):
        p = JwtPlugin()
        data = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"
        pv = p.extract(data)
        assert len(pv.values) == p.num_properties
        mutations = p.perturb(data, 4, random.Random(42))  # alg_is_none
        assert len(mutations) >= 1

    def test_cookie_extract_perturb(self):
        p = CookiePlugin()
        data = b"session=abc; Path=/; Secure; HttpOnly"
        pv = p.extract(data)
        assert len(pv.values) == p.num_properties
        mutations = p.perturb(data, 11, random.Random(42))  # domain
        assert len(mutations) >= 1

    def test_mutation_name_mapping(self):
        """Verify mutation name → property index mappings are valid."""
        for PluginCls in [SamlPlugin, JwtPlugin, CookiePlugin]:
            p = PluginCls()
            mapping = p.mutation_name_to_prop_index
            for name, idx in mapping.items():
                assert 0 <= idx < p.num_properties, (
                    f"{PluginCls.__name__}: {name} -> {idx} out of range "
                    f"(max={p.num_properties - 1})"
                )
