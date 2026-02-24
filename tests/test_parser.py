"""Tests for the DSL parser."""

import pytest
from pathlib import Path

from webfuzzer.core.parser import GrammarParser, ParseError
from webfuzzer.core.grammar import Grammar, Symbol


@pytest.fixture
def parser():
    return GrammarParser()


class TestDirectives:
    def test_root_directive(self, parser):
        g = parser.parse_string("!root <start>\n<start> = hello")
        assert g.root == "start"

    def test_root_directive_no_brackets(self, parser):
        g = parser.parse_string("!root start\n<start> = hello")
        assert g.root == "start"

    def test_max_depth_directive(self, parser):
        g = parser.parse_string("!max_depth 20\n<start> = hello")
        assert g.max_depth == 20

    def test_import_directive(self, parser):
        g = parser.parse_string("!import ecmascript\n<start> = hello")
        assert "ecmascript" in g.imports

    def test_unknown_directive_raises(self, parser):
        with pytest.raises(ParseError):
            parser.parse_string("!unknown value\n<start> = hello")


class TestRuleParsing:
    def test_simple_literal(self, parser):
        g = parser.parse_string("<greeting> = hello world")
        rule = g.get_rule("greeting")
        assert rule is not None
        assert len(rule.productions) == 1
        assert rule.productions[0].symbols[0].kind == "literal"
        assert rule.productions[0].symbols[0].name == "hello world"

    def test_rule_reference(self, parser):
        g = parser.parse_string("<a> = <b>\n<b> = hello")
        rule = g.get_rule("a")
        assert rule is not None
        sym = rule.productions[0].symbols[0]
        assert sym.kind == "rule_ref"
        assert sym.name == "b"

    def test_multiple_alternatives(self, parser):
        g = parser.parse_string("<color> = red\n<color> = blue\n<color> = green")
        rule = g.get_rule("color")
        assert rule is not None
        assert len(rule.productions) == 3

    def test_weight_annotation(self, parser):
        g = parser.parse_string("<val> = [weight=5] important\n<val> = normal")
        rule = g.get_rule("val")
        assert rule.productions[0].weight == 5
        assert rule.productions[1].weight == 1

    def test_auto_root_detection(self, parser):
        g = parser.parse_string("<first> = a\n<second> = b")
        assert g.root == "first"


class TestSymbolParsing:
    def test_builtin_int(self, parser):
        g = parser.parse_string("<val> = <int min=0 max=100>")
        sym = g.get_rule("val").productions[0].symbols[0]
        assert sym.kind == "builtin"
        assert sym.name == "int"
        assert sym.params == {"min": "0", "max": "100"}

    def test_builtin_string(self, parser):
        g = parser.parse_string("<val> = <string min=1 max=10>")
        sym = g.get_rule("val").productions[0].symbols[0]
        assert sym.kind == "builtin"
        assert sym.name == "string"

    def test_builtin_oneof(self, parser):
        g = parser.parse_string("<val> = <oneof red green blue>")
        sym = g.get_rule("val").productions[0].symbols[0]
        assert sym.kind == "builtin"
        assert sym.name == "oneof"
        assert sym.params["_0"] == "red"
        assert sym.params["_1"] == "green"
        assert sym.params["_2"] == "blue"

    def test_cross_reference(self, parser):
        g = parser.parse_string("<body> = @ecmascript:<program>")
        sym = g.get_rule("body").productions[0].symbols[0]
        assert sym.kind == "cross_ref"
        assert sym.grammar_ref == "ecmascript"
        assert sym.name == "program"

    def test_optional_modifier(self, parser):
        g = parser.parse_string("<val> = <thing?>")
        sym = g.get_rule("val").productions[0].symbols[0]
        assert sym.modifier == "?"

    def test_plus_modifier(self, parser):
        g = parser.parse_string("<val> = <item+>")
        sym = g.get_rule("val").productions[0].symbols[0]
        assert sym.modifier == "+"

    def test_star_modifier(self, parser):
        g = parser.parse_string("<val> = <item*>")
        sym = g.get_rule("val").productions[0].symbols[0]
        assert sym.modifier == "*"

    def test_bounded_repeat_modifier(self, parser):
        g = parser.parse_string("<val> = <item{2,5}>")
        sym = g.get_rule("val").productions[0].symbols[0]
        assert sym.modifier == "{2,5}"

    def test_mixed_literal_and_refs(self, parser):
        g = parser.parse_string("<tag> = prefix_<name>_suffix")
        prod = g.get_rule("tag").productions[0]
        assert len(prod.symbols) == 3
        assert prod.symbols[0].kind == "literal"
        assert prod.symbols[0].name == "prefix_"
        assert prod.symbols[1].kind == "rule_ref"
        assert prod.symbols[1].name == "name"
        assert prod.symbols[2].kind == "literal"
        assert prod.symbols[2].name == "_suffix"


class TestComments:
    def test_comment_lines_ignored(self, parser):
        g = parser.parse_string("# this is a comment\n<start> = hello\n# another")
        assert g.get_rule("start") is not None

    def test_empty_lines_ignored(self, parser):
        g = parser.parse_string("\n\n<start> = hello\n\n")
        assert g.get_rule("start") is not None


class TestFileLoading:
    def test_load_simple_grammar(self, parser):
        path = Path(__file__).parent / "test_grammars" / "simple.grammar"
        g = parser.parse_file(path)
        assert g.name == "simple"
        assert g.root == "greeting"
        assert "greeting" in g.rules
        assert "name" in g.rules


class TestEdgeCases:
    def test_invalid_syntax_raises(self, parser):
        with pytest.raises(ParseError):
            parser.parse_string("this is not valid grammar syntax")

    def test_empty_grammar(self, parser):
        g = parser.parse_string("")
        assert len(g.rules) == 0

    def test_comments_only(self, parser):
        g = parser.parse_string("# just a comment\n# another")
        assert len(g.rules) == 0
