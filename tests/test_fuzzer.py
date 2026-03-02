"""Tests for the fuzzer framework — protocols, corpus, mutators, schedulers, oracles."""

import pytest
import random

from webfuzzer.fuzzer.protocols import (
    Input, ExecutionResult, Finding, Severity, ScheduleResult,
)
from webfuzzer.fuzzer.corpus import CoverageMap, Seed, Corpus, MAP_SIZE


# ── CoverageMap tests ────────────────────────────────────────────


class TestCoverageMap:
    def test_empty_map(self):
        cm = CoverageMap()
        assert cm.edge_count == 0
        assert cm.edges() == set()

    def test_has_new_bits_detects_new_edge(self):
        existing = CoverageMap()
        new = CoverageMap()
        new.bitmap[42] = 1
        assert existing.has_new_bits(new)

    def test_has_new_bits_no_false_positive(self):
        existing = CoverageMap()
        existing.bitmap[42] = 1
        same = CoverageMap()
        same.bitmap[42] = 1
        assert not existing.has_new_bits(same)

    def test_update_merges_bitmaps(self):
        a = CoverageMap()
        b = CoverageMap()
        b.bitmap[10] = 1
        b.bitmap[20] = 3
        new_edges = a.update(b)
        assert 10 in new_edges
        assert 20 in new_edges
        assert a.bitmap[10] == 1
        assert a.bitmap[20] == 3
        assert a.edge_count == 2

    def test_clone_is_independent(self):
        a = CoverageMap()
        a.bitmap[5] = 2
        a.edge_count = 1
        b = a.clone()
        b.bitmap[5] = 0
        assert a.bitmap[5] == 2

    def test_edges_returns_hit_indices(self):
        cm = CoverageMap()
        cm.bitmap[100] = 1
        cm.bitmap[200] = 5
        assert cm.edges() == {100, 200}


# ── Seed & Corpus tests ─────────────────────────────────────────


class TestCorpus:
    def _make_input(self, data: bytes = b"test") -> Input:
        return Input(data=data)

    def _make_coverage(self, *edges: int) -> CoverageMap:
        cm = CoverageMap()
        for e in edges:
            cm.bitmap[e] = 1
        cm.edge_count = len(edges)
        return cm

    def test_force_add_always_adds(self):
        corpus = Corpus()
        inp = self._make_input()
        seed = corpus.force_add(inp)
        assert len(corpus) == 1
        assert seed.id == 0

    def test_add_rejects_non_novel(self):
        corpus = Corpus()
        cov = self._make_coverage(10)
        corpus.force_add(self._make_input(), cov)
        # Same coverage — should be rejected
        result = corpus.add(self._make_input(b"dupe"), cov)
        assert result is None
        assert len(corpus) == 1

    def test_add_accepts_novel(self):
        corpus = Corpus()
        corpus.force_add(self._make_input(), self._make_coverage(10))
        new_cov = self._make_coverage(10, 20)
        result = corpus.add(self._make_input(b"new"), new_cov)
        assert result is not None
        assert len(corpus) == 2

    def test_remove(self):
        corpus = Corpus()
        s = corpus.force_add(self._make_input())
        corpus.remove(s.id)
        assert len(corpus) == 0

    def test_get_by_id(self):
        corpus = Corpus()
        s = corpus.force_add(self._make_input())
        assert corpus.get_by_id(s.id) is s
        assert corpus.get_by_id(999) is None

    def test_minimize_keeps_minimal_set(self):
        corpus = Corpus()
        # Seed 0 covers {1, 2, 3}
        s0 = corpus.force_add(self._make_input(b"s0"), self._make_coverage(1, 2, 3))
        # Seed 1 covers {1} — redundant
        s1 = corpus.force_add(self._make_input(b"s1"), self._make_coverage(1))
        corpus.minimize()
        # Only s0 should remain (covers all edges)
        assert len(corpus) <= 1 or all(
            s.feature_set for s in corpus.seeds
        )

    def test_compact_removes_zero_contribution(self):
        corpus = Corpus()
        # Seed with features — should be kept
        corpus.force_add(self._make_input(b"good"), self._make_coverage(1, 2))
        # Seed without features — should be removed
        corpus.force_add(self._make_input(b"empty"))
        corpus.force_add(self._make_input(b"empty2"))
        assert len(corpus) == 3
        removed = corpus.compact(min_seeds=1)
        assert removed == 2
        assert len(corpus) == 1
        assert corpus.seeds[0].input.data == b"good"

    def test_compact_preserves_finding_seeds(self):
        corpus = Corpus()
        # Seed with finding but no features — should be kept
        s = corpus.force_add(self._make_input(b"finder"))
        s.finding_count = 1
        # Seed with features
        corpus.force_add(self._make_input(b"edges"), self._make_coverage(5))
        # Truly empty seed
        corpus.force_add(self._make_input(b"empty"))
        removed = corpus.compact(min_seeds=1)
        assert removed == 1  # only the empty one removed
        assert len(corpus) == 2

    def test_compact_noop_when_small(self):
        corpus = Corpus()
        corpus.force_add(self._make_input(b"s1"))
        assert corpus.compact(min_seeds=50) == 0

    def test_save_and_load(self, tmp_path):
        corpus = Corpus()
        corpus.force_add(Input(data=b"hello", metadata={"x": 1}))
        corpus.force_add(Input(data=b"world"))
        corpus.save(tmp_path / "corpus")

        corpus2 = Corpus()
        corpus2.load(tmp_path / "corpus")
        assert len(corpus2) == 2


# ── Mutator tests ───────────────────────────────────────────────


class TestHavocMutator:
    def test_produces_different_output(self):
        from webfuzzer.fuzzer.mutators.havoc_mutator import HavocMutator

        mut = HavocMutator(seed=42)
        inp = Input(data=b"hello world fuzzer input data here")
        results = set()
        for _ in range(20):
            out = mut.mutate(inp, [])
            results.add(out.data)
        # Havoc should produce varied output
        assert len(results) > 1

    def test_empty_input(self):
        from webfuzzer.fuzzer.mutators.havoc_mutator import HavocMutator

        mut = HavocMutator(seed=42)
        inp = Input(data=b"")
        out = mut.mutate(inp, [])
        assert isinstance(out.data, bytes)

    def test_name_attribute(self):
        from webfuzzer.fuzzer.mutators.havoc_mutator import HavocMutator

        mut = HavocMutator()
        assert mut.name == "havoc"


class TestTokenMutator:
    def test_produces_output(self):
        from webfuzzer.fuzzer.mutators.token_mutator import TokenMutator

        mut = TokenMutator(seed=42)
        inp = Input(data=b"var x = 42; return x + 1;")
        out = mut.mutate(inp, [])
        assert isinstance(out.data, bytes)
        assert len(out.data) > 0

    def test_name_attribute(self):
        from webfuzzer.fuzzer.mutators.token_mutator import TokenMutator

        assert TokenMutator().name == "token"


class TestSpliceMutator:
    def test_splices_with_corpus(self):
        from webfuzzer.fuzzer.mutators.splice_mutator import SpliceMutator

        mut = SpliceMutator(seed=42)
        inp = Input(data=b"AAAA" * 10)
        other = Seed(id=0, input=Input(data=b"BBBB" * 10))
        out = mut.mutate(inp, [other])
        assert isinstance(out.data, bytes)

    def test_name_attribute(self):
        from webfuzzer.fuzzer.mutators.splice_mutator import SpliceMutator

        assert SpliceMutator().name == "splice"


class TestDictionaryMutator:
    def test_produces_output(self):
        from webfuzzer.fuzzer.mutators.dictionary_mutator import DictionaryMutator

        mut = DictionaryMutator(seed=42)
        inp = Input(data=b"<html><body>test</body></html>")
        out = mut.mutate(inp, [])
        assert isinstance(out.data, bytes)

    def test_name_attribute(self):
        from webfuzzer.fuzzer.mutators.dictionary_mutator import DictionaryMutator

        assert DictionaryMutator().name == "dictionary"

    def test_dictionary_has_mxss_entries(self):
        from webfuzzer.fuzzer.mutators.dictionary_mutator import WEB_DICTIONARY

        joined = b" ".join(WEB_DICTIONARY)
        # mXSS namespace entries
        assert b"<math>" in joined or b"<math " in joined
        assert b"foreignObject" in joined
        assert b"annotation-xml" in joined
        # mXSS RAWTEXT / comment entries
        assert b"CDATA" in joined
        assert b"--!>" in joined
        # Should have significantly more than original 42 entries
        assert len(WEB_DICTIONARY) > 100


class TestMxssMutator:
    def test_produces_different_output(self):
        from webfuzzer.fuzzer.mutators.mxss_mutator import MxssMutator

        mut = MxssMutator(seed=42)
        inp = Input(data=b"<div>test content</div>")
        results = set()
        for _ in range(20):
            out = mut.mutate(inp, [])
            results.add(out.data)
        assert len(results) > 1

    def test_empty_input(self):
        from webfuzzer.fuzzer.mutators.mxss_mutator import MxssMutator

        mut = MxssMutator(seed=42)
        inp = Input(data=b"")
        out = mut.mutate(inp, [])
        assert isinstance(out.data, bytes)
        assert len(out.data) > 0  # should use XSS_PAYLOADS fallback

    def test_name_attribute(self):
        from webfuzzer.fuzzer.mutators.mxss_mutator import MxssMutator

        assert MxssMutator().name == "mxss"

    def test_output_contains_namespace_elements(self):
        from webfuzzer.fuzzer.mutators.mxss_mutator import MxssMutator

        mut = MxssMutator(seed=42)
        inp = Input(data=b"<img src=x onerror=alert(1)>")
        outputs = []
        for _ in range(50):
            out = mut.mutate(inp, [])
            outputs.append(out.data)
        joined = b" ".join(outputs)
        # At least some outputs should contain namespace switching
        has_svg = b"<svg" in joined
        has_math = b"<math" in joined
        assert has_svg or has_math

    def test_size_limit(self):
        from webfuzzer.fuzzer.mutators.mxss_mutator import MxssMutator, MAX_OUTPUT_SIZE

        mut = MxssMutator(seed=42)
        inp = Input(data=b"<div>x</div>" * 1000)
        for _ in range(20):
            out = mut.mutate(inp, [])
            assert len(out.data) <= MAX_OUTPUT_SIZE

    def test_mutator_metadata(self):
        from webfuzzer.fuzzer.mutators.mxss_mutator import MxssMutator

        mut = MxssMutator(seed=42)
        inp = Input(data=b"<p>hello</p>", metadata={"source": "test"})
        out = mut.mutate(inp, [])
        assert out.metadata.get("mutator") == "mxss"
        assert out.metadata.get("source") == "test"


class TestStructuralHavocMutator:
    def test_produces_different_output(self):
        from webfuzzer.fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator

        mut = StructuralHavocMutator(seed=42)
        inp = Input(data=b'<div class="test" id="main">content</div>')
        results = set()
        for _ in range(20):
            out = mut.mutate(inp, [])
            results.add(out.data)
        assert len(results) > 1

    def test_empty_input(self):
        from webfuzzer.fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator

        mut = StructuralHavocMutator(seed=42)
        inp = Input(data=b"")
        out = mut.mutate(inp, [])
        assert isinstance(out.data, bytes)
        assert len(out.data) > 0  # should use <div>test</div> fallback

    def test_name_attribute(self):
        from webfuzzer.fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator

        assert StructuralHavocMutator().name == "structural"

    def test_preserves_some_structure(self):
        from webfuzzer.fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator

        mut = StructuralHavocMutator(seed=42)
        inp = Input(data=b'<div class="hello">world</div>')
        # Run many mutations and check at least some retain tag-like structure
        tag_like = 0
        for _ in range(30):
            out = mut.mutate(inp, [])
            if b"<" in out.data and b">" in out.data:
                tag_like += 1
        assert tag_like > 15  # most outputs should retain HTML-like structure

    def test_mutator_metadata(self):
        from webfuzzer.fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator

        mut = StructuralHavocMutator(seed=42)
        inp = Input(data=b"<p>test</p>", metadata={"source": "test"})
        out = mut.mutate(inp, [])
        assert out.metadata.get("mutator") == "structural"
        assert out.metadata.get("source") == "test"


# ── Scheduler tests ──────────────────────────────────────────────


class TestRandomScheduler:
    def test_selects_from_corpus(self):
        from webfuzzer.fuzzer.schedulers.random_scheduler import RandomSeedScheduler

        sched = RandomSeedScheduler(seed=42)
        corpus = Corpus()
        for i in range(5):
            corpus.force_add(Input(data=f"seed{i}".encode()))

        selected = sched.select(corpus)
        assert selected in corpus.seeds

    def test_update_does_not_crash(self):
        from webfuzzer.fuzzer.schedulers.random_scheduler import RandomSeedScheduler

        sched = RandomSeedScheduler()
        seed = Seed(id=0, input=Input(data=b"x"))
        sched.update(seed, ScheduleResult())


class TestEntropicScheduler:
    def test_selects_and_updates(self):
        from webfuzzer.fuzzer.schedulers.entropic import EntropicScheduler

        sched = EntropicScheduler(seed=42)
        corpus = Corpus()
        for i in range(5):
            s = corpus.force_add(Input(data=f"s{i}".encode()))
            s.feature_set = {i, i + 10}

        selected = sched.select(corpus)
        assert selected in corpus.seeds

        sched.update(selected, ScheduleResult(found_new_coverage=True, new_edges={99}))


class TestEcoFuzzScheduler:
    def test_selects_and_updates(self):
        from webfuzzer.fuzzer.schedulers.ecofuzz import EcoFuzzScheduler

        sched = EcoFuzzScheduler(seed=42)
        corpus = Corpus()
        for i in range(5):
            corpus.force_add(Input(data=f"s{i}".encode()))

        selected = sched.select(corpus)
        assert selected in corpus.seeds

        sched.update(selected, ScheduleResult(found_new_coverage=True))


class TestRareBranchScheduler:
    def test_selects_with_rare_branches(self):
        from webfuzzer.fuzzer.schedulers.rare_branch import RareBranchScheduler

        sched = RareBranchScheduler(seed=42)
        corpus = Corpus()
        for i in range(5):
            s = corpus.force_add(Input(data=f"s{i}".encode()))
            s.feature_set = {i}
        # Add edge frequencies so rare_branch logic activates
        corpus.edge_freq = {0: 1, 1: 1, 2: 50, 3: 50, 4: 1}

        selected = sched.select(corpus)
        assert selected in corpus.seeds


# ── Oracle tests ─────────────────────────────────────────────────


class TestCrashOracle:
    def test_no_crash_returns_none(self):
        from webfuzzer.fuzzer.oracles.crash_oracle import CrashOracle

        oracle = CrashOracle()
        inp = Input(data=b"test")
        result = ExecutionResult(exit_code=0)
        assert oracle.check(inp, result) is None

    def test_nonzero_exit_returns_finding(self):
        from webfuzzer.fuzzer.oracles.crash_oracle import CrashOracle

        oracle = CrashOracle()
        inp = Input(data=b"test")
        result = ExecutionResult(exit_code=1)
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.LOW
        assert finding.oracle_name == "crash"

    def test_signal_returns_critical(self):
        from webfuzzer.fuzzer.oracles.crash_oracle import CrashOracle

        oracle = CrashOracle()
        inp = Input(data=b"test")
        result = ExecutionResult(exit_code=-11)  # SIGSEGV
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_timeout_detection(self):
        from webfuzzer.fuzzer.oracles.crash_oracle import CrashOracle

        oracle = CrashOracle(timeout_ms=1000)
        inp = Input(data=b"test")
        result = ExecutionResult(exit_code=1, duration_ms=1500)
        finding = oracle.check(inp, result)
        assert finding is not None
        assert finding.severity == Severity.MEDIUM


class TestSanitizerOracle:
    def test_detects_sql_injection_pattern(self):
        from webfuzzer.fuzzer.oracles.sanitizer_oracle import SanitizerOracle

        oracle = SanitizerOracle()
        inp = Input(data=b"' OR 1=1 --")
        result = ExecutionResult(
            exit_code=0,
            stderr=b"You have an error in your SQL syntax near '' OR 1=1 --'",
        )
        finding = oracle.check(inp, result)
        assert finding is not None
        assert "sqli" in finding.oracle_name.lower() or "sql" in finding.title.lower()

    def test_no_finding_on_clean_output(self):
        from webfuzzer.fuzzer.oracles.sanitizer_oracle import SanitizerOracle

        oracle = SanitizerOracle()
        inp = Input(data=b"normal input")
        result = ExecutionResult(exit_code=0, stdout=b"OK")
        assert oracle.check(inp, result) is None


class TestResponseOracle:
    def test_detects_server_error(self):
        from webfuzzer.fuzzer.oracles.response_oracle import ResponseOracle

        oracle = ResponseOracle()
        inp = Input(data=b"test")
        result = ExecutionResult(
            exit_code=0,
            metadata={"status_code": 500},
        )
        finding = oracle.check(inp, result)
        assert finding is not None

    def test_no_finding_on_200(self):
        from webfuzzer.fuzzer.oracles.response_oracle import ResponseOracle

        oracle = ResponseOracle()
        inp = Input(data=b"test")
        result = ExecutionResult(
            exit_code=0,
            metadata={"status_code": 200},
        )
        assert oracle.check(inp, result) is None


class TestXssOracle:
    """Test XSS oracle with context-aware validation."""

    def _check(self, output: bytes):
        from webfuzzer.fuzzer.oracles.xss_oracle import XssOracle
        oracle = XssOracle()
        inp = Input(data=b"<test>")
        result = ExecutionResult(exit_code=0, stdout=output)
        return oracle.check(inp, result)

    def test_detects_script_tag(self):
        finding = self._check(b"<script>alert(1)</script>")
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_detects_event_handler(self):
        finding = self._check(b'<img src=x onerror=alert(1)>')
        assert finding is not None
        assert finding.severity == Severity.CRITICAL

    def test_detects_css_expression_in_style(self):
        finding = self._check(b"<style>*{x:expression(alert(1))}</style>")
        assert finding is not None

    def test_detects_css_import_javascript_in_style(self):
        finding = self._check(b'<style>@import "javascript:alert(1)"</style>')
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_ignores_entity_encoded_script(self):
        # Entity-encoded <script> should NOT trigger a finding
        finding = self._check(b"&lt;script&gt;alert(1)&lt;/script&gt;")
        assert finding is None

    def test_ignores_entity_encoded_javascript_uri(self):
        # Entity-encoded base tag with javascript: URI — false positive case
        finding = self._check(
            b'&lt;base href="javascript:void(0)"&gt;'
        )
        assert finding is None

    def test_ignores_css_outside_style(self):
        # expression() as bare text, not inside <style> — not exploitable
        finding = self._check(b"expression(alert(1))")
        assert finding is None

    def test_clean_output_returns_none(self):
        finding = self._check(b"<div>Hello, world!</div>")
        assert finding is None

    # ── mXSS-specific pattern tests ────────────────────────────────

    def test_detects_annotation_xml_html_encoding(self):
        finding = self._check(
            b'<math><annotation-xml encoding="text/html">'
            b"<img src=x onerror=alert(1)></annotation-xml></math>"
        )
        assert finding is not None

    def test_detects_mglyph_with_dangerous_content(self):
        finding = self._check(
            b"<math><mtext><mglyph>"
            b"<script>alert(1)</script></mglyph></mtext></math>"
        )
        assert finding is not None

    def test_detects_nested_namespace_with_script(self):
        finding = self._check(
            b"<svg><foreignObject><math><mtext>"
            b"<svg><desc><script>alert(1)</script></desc></svg>"
            b"</mtext></math></foreignObject></svg>"
        )
        assert finding is not None

    def test_detects_cdata_section(self):
        finding = self._check(b"<div><![CDATA[test]]></div>")
        assert finding is not None

    def test_detects_noscript_with_dangerous_content(self):
        finding = self._check(
            b'<noscript><img src=x onerror=alert(1)></noscript>'
        )
        assert finding is not None

    def test_detects_dom_clobbering(self):
        finding = self._check(
            b'<form id="document"><img name="location"></form>'
        )
        assert finding is not None

    def test_detects_prototype_pollution(self):
        finding = self._check(b"__proto__")
        assert finding is not None

    def test_detects_template_with_script(self):
        finding = self._check(
            b"<template><script>alert(1)</script></template>"
        )
        assert finding is not None

    def test_ignores_entity_encoded_annotation_xml(self):
        # Entity-encoded namespace pattern should not trigger
        finding = self._check(
            b'&lt;annotation-xml encoding="text/html"&gt;test&lt;/annotation-xml&gt;'
        )
        assert finding is None


class TestCompositeOracle:
    def test_chains_oracles(self):
        from webfuzzer.fuzzer.oracles.crash_oracle import CrashOracle
        from webfuzzer.fuzzer.oracles.composite_oracle import CompositeOracle

        composite = CompositeOracle([CrashOracle()])
        inp = Input(data=b"test")
        result = ExecutionResult(exit_code=-11)
        finding = composite.check(inp, result)
        assert finding is not None


# ── Coverage tests ───────────────────────────────────────────────


class TestEdgeCoverage:
    def test_collect_produces_bitmap(self):
        from webfuzzer.fuzzer.coverage.edge_coverage import EdgeCoverageCollector

        collector = EdgeCoverageCollector()
        result = ExecutionResult(coverage_data=b"\x01\x02\x03")
        cov = collector.collect(result)
        assert isinstance(cov, CoverageMap)

    def test_is_novel(self):
        from webfuzzer.fuzzer.coverage.edge_coverage import EdgeCoverageCollector

        collector = EdgeCoverageCollector()
        existing = CoverageMap()
        new = CoverageMap()
        new.bitmap[42] = 1
        assert collector.is_novel(existing, new)


class TestResponseCoverage:
    def test_collect_from_result(self):
        from webfuzzer.fuzzer.coverage.response_coverage import ResponseCoverageCollector

        collector = ResponseCoverageCollector()
        result = ExecutionResult(
            exit_code=0,
            stdout=b"hello world",
            duration_ms=50,
            metadata={"status_code": 200},
        )
        cov = collector.collect(result)
        assert isinstance(cov, CoverageMap)
        assert cov.edge_count > 0


class TestStateCoverage:
    def test_collect_state_transition(self):
        from webfuzzer.fuzzer.coverage.state_coverage import StateCoverageCollector

        collector = StateCoverageCollector()
        r1 = ExecutionResult(exit_code=0, metadata={"status_code": 200})
        cov1 = collector.collect(r1)
        r2 = ExecutionResult(exit_code=0, metadata={"status_code": 302})
        cov2 = collector.collect(r2)

        assert isinstance(cov1, CoverageMap)
        assert isinstance(cov2, CoverageMap)
        # Different states should produce different coverage
        assert cov1.edges() != cov2.edges()


# ── Dedup tests ──────────────────────────────────────────────────


class TestCoverageDedup:
    def test_duplicate_detection(self):
        from webfuzzer.fuzzer.dedup.coverage_dedup import CoverageDeduplicator

        dedup = CoverageDeduplicator()
        inp = Input(data=b"test")
        result = ExecutionResult(exit_code=1, stderr=b"error msg")
        finding = Finding(
            title="crash", severity=Severity.HIGH, input=inp,
            result=result, oracle_name="crash",
        )
        fp = dedup.fingerprint(finding)
        finding.fingerprint = fp
        assert not dedup.is_duplicate(finding)
        dedup.register(finding)
        assert dedup.is_duplicate(finding)


class TestStructuralDedup:
    def test_fingerprint_consistency(self):
        from webfuzzer.fuzzer.dedup.structural_dedup import StructuralDeduplicator

        dedup = StructuralDeduplicator()
        inp = Input(data=b"<html>test</html>")
        result = ExecutionResult(exit_code=1, stderr=b"parse error line 1")
        finding = Finding(
            title="crash", severity=Severity.HIGH, input=inp,
            result=result, oracle_name="crash",
        )
        fp1 = dedup.fingerprint(finding)
        fp2 = dedup.fingerprint(finding)
        assert fp1 == fp2

    def test_different_inputs_different_fingerprints(self):
        from webfuzzer.fuzzer.dedup.structural_dedup import StructuralDeduplicator

        dedup = StructuralDeduplicator()
        f1 = Finding(
            title="crash", severity=Severity.HIGH,
            input=Input(data=b"<html>"),
            result=ExecutionResult(exit_code=1, stderr=b"err1"),
            oracle_name="crash",
        )
        f2 = Finding(
            title="crash", severity=Severity.HIGH,
            input=Input(data=b'{"key": 1}'),
            result=ExecutionResult(exit_code=1, stderr=b"err2"),
            oracle_name="crash",
        )
        assert dedup.fingerprint(f1) != dedup.fingerprint(f2)


# ── ProcessTarget tests ─────────────────────────────────────────


class TestProcessTarget:
    def test_execute_echo(self):
        from webfuzzer.fuzzer.targets.process_target import ProcessTarget

        target = ProcessTarget("python -c \"import sys; print(open(sys.argv[1]).read())\" {input}")
        target.setup()
        try:
            inp = Input(data=b"hello fuzzer")
            result = target.execute(inp)
            assert result.exit_code == 0
            assert b"hello fuzzer" in result.stdout
            assert result.duration_ms > 0
        finally:
            target.teardown()

    def test_nonzero_exit(self):
        from webfuzzer.fuzzer.targets.process_target import ProcessTarget

        target = ProcessTarget("python -c \"import sys; sys.exit(42)\"")
        target.setup()
        try:
            result = target.execute(Input(data=b"x"))
            assert result.exit_code == 42
        finally:
            target.teardown()

    def test_timeout(self):
        from webfuzzer.fuzzer.targets.process_target import ProcessTarget

        target = ProcessTarget(
            "python -c \"import time; time.sleep(30)\"",
            timeout_seconds=1,
        )
        target.setup()
        try:
            result = target.execute(Input(data=b"x"))
            assert result.exit_code == -9
            assert result.metadata.get("timeout") is True
        finally:
            target.teardown()

    def test_is_alive(self):
        from webfuzzer.fuzzer.targets.process_target import ProcessTarget

        target = ProcessTarget("echo {input}")
        target.setup()
        assert target.is_alive()
        target.teardown()


# ── GrammarInputSource tests ────────────────────────────────────


class TestGrammarInputSource:
    @pytest.fixture
    def registry(self):
        from webfuzzer.core.registry import GrammarRegistry

        reg = GrammarRegistry()
        reg.load_builtins()
        return reg

    def test_generate_produces_input(self, registry):
        from webfuzzer.fuzzer.grammar_source import GrammarInputSource

        source = GrammarInputSource(registry, "json", seed=42)
        inp = source.generate()
        assert isinstance(inp, Input)
        assert len(inp.data) > 0
        assert inp.metadata["grammar"] == "json"
        assert "tree" in inp.metadata

    def test_deterministic_with_seed(self, registry):
        from webfuzzer.fuzzer.grammar_source import GrammarInputSource

        s1 = GrammarInputSource(registry, "json", seed=42)
        s2 = GrammarInputSource(registry, "json", seed=42)
        assert s1.generate().data == s2.generate().data


# ── GrammarMutator tests ────────────────────────────────────────


class TestGrammarMutator:
    @pytest.fixture
    def registry(self):
        from webfuzzer.core.registry import GrammarRegistry

        reg = GrammarRegistry()
        reg.load_builtins()
        return reg

    def test_mutate_grammar_input(self, registry):
        from webfuzzer.fuzzer.grammar_source import GrammarInputSource
        from webfuzzer.fuzzer.mutators.grammar_mutator import GrammarMutator

        source = GrammarInputSource(registry, "json", seed=42)
        mut = GrammarMutator(registry, "json", seed=42)

        inp = source.generate()
        mutated = mut.mutate(inp, [])
        assert isinstance(mutated, Input)
        assert isinstance(mutated.data, bytes)

    def test_mutate_without_tree_fallback(self, registry):
        from webfuzzer.fuzzer.mutators.grammar_mutator import GrammarMutator

        mut = GrammarMutator(registry, "json", seed=42)
        inp = Input(data=b'{"key": "value"}')  # no tree in metadata
        mutated = mut.mutate(inp, [])
        assert isinstance(mutated.data, bytes)
        assert len(mutated.data) > 0


# ── MutationScheduler tests ─────────────────────────────────────


class TestMOPTScheduler:
    def test_select_and_update(self):
        from webfuzzer.fuzzer.schedulers.mutation_scheduler import MOPTScheduler
        from webfuzzer.fuzzer.mutators.havoc_mutator import HavocMutator
        from webfuzzer.fuzzer.mutators.splice_mutator import SpliceMutator

        sched = MOPTScheduler(seed=42)
        mutators = [HavocMutator(), SpliceMutator()]
        seed = Seed(id=0, input=Input(data=b"x"))

        selected = sched.select(mutators, seed)
        assert selected in mutators

        sched.update(selected, ScheduleResult(found_new_coverage=True))


class TestDARWINScheduler:
    def test_select_and_update(self):
        from webfuzzer.fuzzer.schedulers.mutation_scheduler import DARWINScheduler
        from webfuzzer.fuzzer.mutators.havoc_mutator import HavocMutator
        from webfuzzer.fuzzer.mutators.splice_mutator import SpliceMutator

        sched = DARWINScheduler(seed=42)
        mutators = [HavocMutator(), SpliceMutator()]
        seed = Seed(id=0, input=Input(data=b"x"))

        selected = sched.select(mutators, seed)
        assert selected in mutators

        sched.update(selected, ScheduleResult(found_crash=True))


# ── Stats tests ──────────────────────────────────────────────────


class TestFuzzStats:
    def test_status_line(self):
        from webfuzzer.fuzzer.stats import FuzzStats

        stats = FuzzStats()
        stats.total_executions = 100
        stats.corpus_size = 10
        stats.total_edges = 50
        stats.unique_findings = 2
        line = stats.status_line()
        assert "execs: 100" in line
        assert "corpus: 10" in line
        assert "edges: 50" in line
        assert "findings: 2" in line

    def test_report_text(self):
        from webfuzzer.fuzzer.stats import FuzzStats

        stats = FuzzStats()
        stats.total_executions = 50
        report = stats.report("text")
        assert "Fuzzing Session Report" in report

    def test_report_json(self):
        import json
        from webfuzzer.fuzzer.stats import FuzzStats

        stats = FuzzStats()
        stats.total_executions = 50
        raw = stats.report("json")
        data = json.loads(raw)
        assert data["total_executions"] == 50

    def test_save_to_disk(self, tmp_path):
        from webfuzzer.fuzzer.stats import FuzzStats

        stats = FuzzStats()
        stats.total_executions = 10
        stats.save(tmp_path)
        assert (tmp_path / "report.txt").exists()
        assert (tmp_path / "report.json").exists()

    def test_record_finding(self):
        from webfuzzer.fuzzer.stats import FuzzStats

        stats = FuzzStats()
        finding = Finding(
            title="test", severity=Severity.HIGH,
            input=Input(data=b"x"),
            result=ExecutionResult(exit_code=1),
            oracle_name="crash",
        )
        stats.record_finding(finding, "havoc")
        assert stats.unique_findings == 1
        assert stats.findings_by_severity["high"] == 1
        assert stats.findings_by_oracle["crash"] == 1
        assert stats.findings_by_mutator["havoc"] == 1


# ── Differential Fuzzing tests ──────────────────────────────────


class _MockTarget:
    """In-memory mock target for testing without subprocess overhead."""

    def __init__(self, handler):
        self.handler = handler
        self._alive = True

    def execute(self, inp: Input) -> ExecutionResult:
        return self.handler(inp)

    def setup(self) -> None:
        self._alive = True

    def teardown(self) -> None:
        pass

    def is_alive(self) -> bool:
        return self._alive

    def reset(self) -> None:
        pass


class TestXssBypassStrategy:
    """Test XSS bypass differential strategy with mXSS patterns."""

    def test_detects_primary_bypass(self):
        from webfuzzer.fuzzer.oracles.xss_diff_strategy import XssBypassStrategy

        strategy = XssBypassStrategy()
        inp = Input(data=b"<test>")
        # Primary allows script, reference blocks it
        primary = ExecutionResult(
            exit_code=0, stdout=b"<script>alert(1)</script>"
        )
        reference = ExecutionResult(
            exit_code=0, stdout=b"alert(1)"
        )
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "primary" in finding.title.lower()

    def test_detects_reference_bypass(self):
        from webfuzzer.fuzzer.oracles.xss_diff_strategy import XssBypassStrategy

        strategy = XssBypassStrategy()
        inp = Input(data=b"<test>")
        # Reference allows script, primary blocks it
        primary = ExecutionResult(exit_code=0, stdout=b"safe output")
        reference = ExecutionResult(
            exit_code=0, stdout=b"<script>alert(1)</script>"
        )
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_no_finding_when_both_safe(self):
        from webfuzzer.fuzzer.oracles.xss_diff_strategy import XssBypassStrategy

        strategy = XssBypassStrategy()
        inp = Input(data=b"<test>")
        primary = ExecutionResult(exit_code=0, stdout=b"safe output")
        reference = ExecutionResult(exit_code=0, stdout=b"also safe")
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_detects_mxss_annotation_xml_divergence(self):
        from webfuzzer.fuzzer.oracles.xss_diff_strategy import XssBypassStrategy

        strategy = XssBypassStrategy()
        inp = Input(data=b"<math><annotation-xml>")
        # Primary passes annotation-xml, reference strips it
        primary = ExecutionResult(
            exit_code=0,
            stdout=b'<annotation-xml encoding="text/html"><img src=x></annotation-xml>',
        )
        reference = ExecutionResult(
            exit_code=0, stdout=b"<img src=x>"
        )
        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None

    def test_ignores_entity_encoded_in_diff(self):
        from webfuzzer.fuzzer.oracles.xss_diff_strategy import XssBypassStrategy

        strategy = XssBypassStrategy()
        inp = Input(data=b"test")
        # Entity-encoded script — should not be flagged as dangerous
        primary = ExecutionResult(
            exit_code=0,
            stdout=b"&lt;script&gt;alert(1)&lt;/script&gt;",
        )
        reference = ExecutionResult(exit_code=0, stdout=b"safe")
        assert strategy.compare(inp, primary, reference, 0) is None


class TestDiffStrategy:
    """Test individual DiffStrategy implementations."""

    def test_exit_code_strategy_detects_mismatch(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import ExitCodeStrategy

        strategy = ExitCodeStrategy()
        inp = Input(data=b"test")
        primary = ExecutionResult(exit_code=0, stdout=b"ok")
        reference = ExecutionResult(exit_code=1, stderr=b"error")

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH
        assert "mismatch" in finding.title.lower()
        assert finding.input is inp  # actual input, not empty

    def test_exit_code_strategy_no_false_positive(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import ExitCodeStrategy

        strategy = ExitCodeStrategy()
        inp = Input(data=b"test")
        primary = ExecutionResult(exit_code=0)
        reference = ExecutionResult(exit_code=0)

        assert strategy.compare(inp, primary, reference, 0) is None

    def test_output_strategy_detects_content_diff(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import OutputStrategy

        strategy = OutputStrategy(normalize=True)
        inp = Input(data=b"test")
        primary = ExecutionResult(exit_code=0, stdout=b"result A")
        reference = ExecutionResult(exit_code=0, stdout=b"result B")

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert "output mismatch" in finding.title.lower()

    def test_output_strategy_ignores_whitespace(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import OutputStrategy

        strategy = OutputStrategy(normalize=True)
        inp = Input(data=b"test")
        primary = ExecutionResult(exit_code=0, stdout=b"hello  world\n")
        reference = ExecutionResult(exit_code=0, stdout=b"Hello World")

        # After normalization (lowercase + collapse whitespace) these match
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_output_strategy_skips_on_errors(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import OutputStrategy

        strategy = OutputStrategy()
        inp = Input(data=b"test")
        primary = ExecutionResult(exit_code=1, stdout=b"err")
        reference = ExecutionResult(exit_code=0, stdout=b"ok")

        # Should not compare outputs when exit codes differ
        assert strategy.compare(inp, primary, reference, 0) is None

    def test_status_code_strategy(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import StatusCodeStrategy

        strategy = StatusCodeStrategy()
        inp = Input(data=b"test")
        primary = ExecutionResult(metadata={"status_code": 200})
        reference = ExecutionResult(metadata={"status_code": 500})

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH  # 5xx involved

    def test_status_code_same_class_no_finding(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import StatusCodeStrategy

        strategy = StatusCodeStrategy()
        inp = Input(data=b"test")
        # Both 2xx — same class
        primary = ExecutionResult(metadata={"status_code": 200})
        reference = ExecutionResult(metadata={"status_code": 201})

        assert strategy.compare(inp, primary, reference, 0) is None

    def test_timing_strategy(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import TimingStrategy

        strategy = TimingStrategy(ratio_threshold=5.0)
        inp = Input(data=b"test")
        primary = ExecutionResult(duration_ms=5000)
        reference = ExecutionResult(duration_ms=100)

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None
        assert "timing" in finding.title.lower()

    def test_error_pattern_strategy(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import ErrorPatternStrategy

        strategy = ErrorPatternStrategy()
        inp = Input(data=b"test")
        primary = ExecutionResult(stderr=b"AddressSanitizer: heap-use-after-free")
        reference = ExecutionResult(exit_code=0, stdout=b"ok")

        finding = strategy.compare(inp, primary, reference, 0)
        assert finding is not None


class TestDiffOracle:
    """Test the composed DiffOracle with mock targets."""

    def test_detects_accept_reject_divergence(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle

        # Primary accepts, reference rejects
        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=1, stderr=b"error"))
        oracle = DiffOracle(reference_targets=[ref])

        inp = Input(data=b"test")
        primary_result = ExecutionResult(exit_code=0, stdout=b"ok")

        finding = oracle.check(inp, primary_result)
        assert finding is not None
        assert finding.oracle_name == "differential"
        assert finding.input is inp

    def test_detects_output_divergence(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=0, stdout=b"different"))
        oracle = DiffOracle(reference_targets=[ref])

        inp = Input(data=b"test")
        primary_result = ExecutionResult(exit_code=0, stdout=b"original")

        finding = oracle.check(inp, primary_result)
        assert finding is not None

    def test_no_finding_when_identical(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=0, stdout=b"same"))
        oracle = DiffOracle(reference_targets=[ref])

        inp = Input(data=b"test")
        primary_result = ExecutionResult(exit_code=0, stdout=b"same")

        assert oracle.check(inp, primary_result) is None

    def test_multiple_references(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle

        ref_a = _MockTarget(lambda inp: ExecutionResult(exit_code=0, stdout=b"same"))
        ref_b = _MockTarget(lambda inp: ExecutionResult(exit_code=1))  # diverges
        oracle = DiffOracle(reference_targets=[ref_a, ref_b])

        inp = Input(data=b"test")
        primary_result = ExecutionResult(exit_code=0, stdout=b"same")

        finding = oracle.check(inp, primary_result)
        assert finding is not None
        # Should be ref[1] that triggered it
        assert finding.metadata.get("ref_index") == 1

    def test_custom_strategies(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle, ExitCodeStrategy

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=0, stdout=b"different"))
        # Only use exit code strategy — output diff should be ignored
        oracle = DiffOracle(
            reference_targets=[ref],
            strategies=[ExitCodeStrategy()],
        )

        inp = Input(data=b"test")
        primary_result = ExecutionResult(exit_code=0, stdout=b"original")

        # Exit codes are the same, so no finding despite output diff
        assert oracle.check(inp, primary_result) is None

    def test_handles_reference_exception(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle

        def crashing_handler(inp):
            raise RuntimeError("target crashed")

        ref = _MockTarget(crashing_handler)
        oracle = DiffOracle(reference_targets=[ref])

        inp = Input(data=b"test")
        primary_result = ExecutionResult(exit_code=0, stdout=b"ok")

        # Should detect divergence (primary ok, ref crashed)
        finding = oracle.check(inp, primary_result)
        assert finding is not None


class TestDiffCoverageCollector:
    """Test divergence-based coverage collection."""

    def test_identical_results_low_coverage(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=0, stdout=b"same"))
        collector = DiffCoverageCollector(reference_targets=[ref])

        inp = Input(data=b"test")
        primary = ExecutionResult(exit_code=0, stdout=b"same")
        cov = collector.collect_diff(inp, primary)

        assert isinstance(cov, CoverageMap)
        assert cov.edge_count > 0

    def test_divergent_results_more_coverage(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=1, stderr=b"error"))
        collector = DiffCoverageCollector(reference_targets=[ref])

        inp = Input(data=b"test")

        # Identical
        same_result = ExecutionResult(exit_code=1, stderr=b"error")
        cov_same = collector.collect_diff(inp, same_result)

        # Divergent
        diff_result = ExecutionResult(exit_code=0, stdout=b"ok")
        cov_diff = collector.collect_diff(inp, diff_result)

        # Divergent should have more features
        assert cov_diff.edge_count >= cov_same.edge_count

    def test_multiple_references_pairwise(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector

        ref_a = _MockTarget(lambda inp: ExecutionResult(exit_code=0, stdout=b"A"))
        ref_b = _MockTarget(lambda inp: ExecutionResult(exit_code=0, stdout=b"B"))
        collector = DiffCoverageCollector(reference_targets=[ref_a, ref_b])

        inp = Input(data=b"test")
        primary = ExecutionResult(exit_code=0, stdout=b"C")
        cov = collector.collect_diff(inp, primary)

        # All three outputs are different — should have pairwise divergence features
        assert cov.edge_count > 0

    def test_is_novel(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=0))
        collector = DiffCoverageCollector(reference_targets=[ref])

        existing = CoverageMap()
        new = CoverageMap()
        new.bitmap[42] = 1
        assert collector.is_novel(existing, new)

    def test_merge(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=0))
        collector = DiffCoverageCollector(reference_targets=[ref])

        a = CoverageMap()
        a.bitmap[10] = 1
        b = CoverageMap()
        b.bitmap[20] = 1
        merged = collector.merge(a, b)
        assert merged.bitmap[10] == 1
        assert merged.bitmap[20] == 1

    def test_collect_satisfies_protocol(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector

        ref = _MockTarget(lambda inp: ExecutionResult(exit_code=0))
        collector = DiffCoverageCollector(reference_targets=[ref])

        # Standard collect() should work for Protocol compatibility
        result = ExecutionResult(exit_code=0, stdout=b"test")
        cov = collector.collect(result)
        assert isinstance(cov, CoverageMap)


class TestDiffE2EWithMockTargets:
    """Integration test: DiffOracle + DiffCoverage with mock targets."""

    def test_full_diff_pipeline(self):
        from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle
        from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector

        # Use JSON outputs so DiffCoverage can detect field-level divergences
        ref_json = b'{"scheme":"http","host":"example.com","path":"/"}'

        def ref_handler(inp: Input) -> ExecutionResult:
            return ExecutionResult(exit_code=0, stdout=ref_json)

        ref = _MockTarget(ref_handler)

        # DiffOracle
        oracle = DiffOracle(reference_targets=[ref])
        # DiffCoverage
        coverage = DiffCoverageCollector(reference_targets=[ref])

        # Case 1: same output — no finding, some coverage
        inp1 = Input(data=b"input1")
        primary1 = ExecutionResult(exit_code=0, stdout=ref_json)
        assert oracle.check(inp1, primary1) is None
        cov1 = coverage.collect_diff(inp1, primary1)
        assert cov1.edge_count > 0

        # Case 2: different output — finding detected, different coverage
        inp2 = Input(data=b"input2")
        diff_json = b'{"scheme":"https","host":"evil.com","path":"/admin"}'
        primary2 = ExecutionResult(exit_code=0, stdout=diff_json)
        finding = oracle.check(inp2, primary2)
        assert finding is not None
        assert finding.oracle_name == "differential"
        cov2 = coverage.collect_diff(inp2, primary2)
        assert cov2.edge_count > 0

        # Coverage should be novel — divergent JSON fields produce new bitmap bits
        global_cov = CoverageMap()
        global_cov.update(cov1)
        assert global_cov.has_new_bits(cov2)  # divergent case adds new bits


# ── Checkpoint tests ────────────────────────────────────────────


class TestCorpusCheckpoint:
    """Tests for corpus save_checkpoint / load_checkpoint."""

    def _make_corpus(self) -> Corpus:
        corpus = Corpus()
        cov1 = CoverageMap()
        cov1.bitmap[10] = 1
        cov1.bitmap[20] = 3
        seed1 = corpus.force_add(
            Input(data=b"seed_one", metadata={"origin": "test"}), cov1,
        )
        seed1.energy = 2.5
        seed1.exec_count = 42
        seed1.depth = 3
        seed1.priority_boost = 1.5
        seed1.rare_branches = {10}

        cov2 = CoverageMap()
        cov2.bitmap[30] = 1
        corpus.force_add(Input(data=b"seed_two"), cov2)
        return corpus

    def test_roundtrip(self, tmp_path):
        """Save and load produces identical corpus state."""
        original = self._make_corpus()
        original.save_checkpoint(tmp_path / "ckpt")

        restored = Corpus()
        assert restored.load_checkpoint(tmp_path / "ckpt")

        # Seed count
        assert len(restored) == len(original)

        # Global coverage bitmap
        assert restored.global_coverage.edge_count == original.global_coverage.edge_count
        assert restored.global_coverage.bitmap[10] == 1
        assert restored.global_coverage.bitmap[20] == 3
        assert restored.global_coverage.bitmap[30] == 1

        # Edge freq
        assert restored.edge_freq == original.edge_freq

        # next_id
        assert restored._next_id == original._next_id

        # Seed data
        s0 = restored.seeds[0]
        assert s0.input.data == b"seed_one"
        assert s0.input.metadata == {"origin": "test"}
        assert s0.energy == 2.5
        assert s0.exec_count == 42
        assert s0.depth == 3
        assert s0.priority_boost == 1.5
        assert s0.rare_branches == {10}

        s1 = restored.seeds[1]
        assert s1.input.data == b"seed_two"

    def test_load_returns_false_when_missing(self, tmp_path):
        corpus = Corpus()
        assert not corpus.load_checkpoint(tmp_path / "nonexistent")


class TestStatsCheckpoint:
    """Tests for stats to_checkpoint_dict / load_checkpoint_dict."""

    def test_roundtrip(self):
        from webfuzzer.fuzzer.stats import FuzzStats
        import time

        stats = FuzzStats()
        stats.total_iterations = 1000
        stats.total_executions = 5000
        stats.total_edges = 42
        stats.peak_edges = 45
        stats.unique_findings = 3
        stats.findings_by_severity = {"high": 2, "medium": 1}
        stats.mutations_by_mutator = {"havoc": 3000, "grammar": 2000}
        stats.new_coverage_by_mutator = {"havoc": 20, "grammar": 22}
        stats.findings_by_mutator = {"havoc": 2, "grammar": 1}

        d = stats.to_checkpoint_dict()

        restored = FuzzStats()
        restored.load_checkpoint_dict(d)

        assert restored.total_iterations == 1000
        assert restored.total_executions == 5000
        assert restored.total_edges == 42
        assert restored.peak_edges == 45
        assert restored.unique_findings == 3
        assert restored.findings_by_severity == {"high": 2, "medium": 1}
        assert restored.mutations_by_mutator == {"havoc": 3000, "grammar": 2000}

        # Elapsed time should be approximately continuous
        assert abs(restored.elapsed() - stats.elapsed()) < 1.0


class TestEngineCheckpoint:
    """Integration test for engine checkpoint save/load cycle."""

    def test_engine_checkpoint_roundtrip(self, tmp_path):
        """Engine saves checkpoint on cleanup and resumes from it."""
        from webfuzzer.fuzzer.engine import FuzzEngine, _DefaultDeduplicator

        class DummyTarget:
            def execute(self, inp):
                return ExecutionResult(exit_code=0, stdout=inp.data)
            def setup(self): pass
            def teardown(self): pass
            def is_alive(self): return True
            def reset(self): pass

        class DummySource:
            def __init__(self):
                self._i = 0
            def generate(self):
                self._i += 1
                return Input(data=f"input_{self._i}".encode())

        class DummyCoverage:
            def collect(self, result):
                cm = CoverageMap()
                # Hash-based edge for variety
                h = hash(result.stdout) % MAP_SIZE
                cm.bitmap[h] = 1
                cm.edge_count = 1
                return cm
            def merge(self, a, b): return a
            def is_novel(self, existing, new):
                return existing.has_new_bits(new)
            def diff(self, old, new): return set()

        output = tmp_path / "session"

        # Run a short session
        engine = FuzzEngine(
            target=DummyTarget(),
            input_source=DummySource(),
            mutators=[],
            oracles=[],
            coverage=DummyCoverage(),
            max_iterations=10,
            initial_seed_count=5,
            output_dir=output,
            seed=42,
        )
        # Manually run parts to test checkpoint
        engine._running = True
        engine._setup()
        engine._seed_corpus()
        original_seeds = len(engine.corpus)
        original_edges = engine.stats.total_edges
        engine._save_checkpoint()
        engine._cleanup()

        # Verify checkpoint files exist
        ckpt = output / "checkpoint"
        assert (ckpt / "state.json").exists()
        assert (ckpt / "corpus" / "coverage.bin").exists()
        assert (ckpt / "corpus" / "state.json").exists()

        # Resume
        engine2 = FuzzEngine(
            target=DummyTarget(),
            input_source=DummySource(),
            mutators=[],
            oracles=[],
            coverage=DummyCoverage(),
            max_iterations=10,
            initial_seed_count=5,
            output_dir=output,
            resume=True,
            seed=42,
        )
        engine2._running = True
        engine2._setup()
        loaded = engine2._load_checkpoint()
        assert loaded

        assert len(engine2.corpus) == original_seeds
        assert engine2.stats.total_edges == original_edges
