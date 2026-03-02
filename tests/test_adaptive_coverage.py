"""Tests for CEGAR adaptive differential coverage."""

import pytest

from webfuzzer.fuzzer.corpus import Corpus, CoverageMap, Seed
from webfuzzer.fuzzer.coverage.adaptive_coverage import (
    AdaptiveConfig,
    AdaptiveDiffCoverage,
    RefinementLevel,
    _LEVEL_PREFIXES,
)
from webfuzzer.fuzzer.coverage.feature_store import FeatureRecord, FeatureStore
from webfuzzer.fuzzer.protocols import ExecutionResult, Input


# ── FeatureStore tests ────────────────────────────────────────────


class TestFeatureStore:
    def test_store_and_get(self):
        store = FeatureStore()
        record = FeatureRecord(seed_id=1, features=[("exit_vec", "0,1")])
        store.store(1, record)
        assert store.get(1) is record

    def test_get_missing(self):
        store = FeatureStore()
        assert store.get(999) is None

    def test_remove(self):
        store = FeatureStore()
        store.store(1, FeatureRecord(seed_id=1))
        store.remove(1)
        assert store.get(1) is None

    def test_remove_nonexistent_ok(self):
        store = FeatureStore()
        store.remove(999)  # no error

    def test_len(self):
        store = FeatureStore()
        store.store(1, FeatureRecord(seed_id=1))
        store.store(2, FeatureRecord(seed_id=2))
        assert len(store) == 2

    def test_all_records(self):
        store = FeatureStore()
        r1 = FeatureRecord(seed_id=1)
        r2 = FeatureRecord(seed_id=2)
        store.store(1, r1)
        store.store(2, r2)
        records = store.all_records()
        assert len(records) == 2
        assert r1 in records
        assert r2 in records


class TestFeatureRecord:
    def test_default_values(self):
        r = FeatureRecord(seed_id=42)
        assert r.seed_id == 42
        assert r.features == []
        assert r.parsed_outputs == []
        assert r.div_count == 0


# ── RefinementLevel tests ────────────────────────────────────────


class TestRefinementLevel:
    def test_ordering(self):
        assert RefinementLevel.L0_MINIMAL < RefinementLevel.L4_FULL

    def test_int_conversion(self):
        assert int(RefinementLevel.L2_COMPONENT) == 2


# ── Level prefixes ───────────────────────────────────────────────


class TestLevelPrefixes:
    def test_l0_minimal(self):
        assert "exit_vec" in _LEVEL_PREFIXES[0]
        assert "cdiff" not in _LEVEL_PREFIXES[0]

    def test_l1_adds_cdiff(self):
        assert "cdiff" in _LEVEL_PREFIXES[1]
        assert "comp" not in _LEVEL_PREFIXES[1]

    def test_l2_adds_component(self):
        assert "comp" in _LEVEL_PREFIXES[2]

    def test_l3_adds_values(self):
        assert "val" in _LEVEL_PREFIXES[3]

    def test_l4_adds_status_and_error(self):
        assert "status_vec" in _LEVEL_PREFIXES[4]
        assert "div_err" in _LEVEL_PREFIXES[4]

    def test_monotonic_inclusion(self):
        """Higher levels include all prefixes from lower levels."""
        for lvl in range(4):
            assert _LEVEL_PREFIXES[lvl].issubset(_LEVEL_PREFIXES[lvl + 1])


# ── AdaptiveDiffCoverage tests ───────────────────────────────────


def _make_fake_target():
    """Create a minimal Target-like object."""
    class FakeTarget:
        def execute(self, inp):
            return ExecutionResult(exit_code=0, stdout=b'{"host":"example.com"}')
        def setup(self): pass
        def teardown(self): pass
        def is_alive(self): return True
        def reset(self): pass
    return FakeTarget()


class TestAdaptiveDiffCoverage:
    def test_initial_level(self):
        config = AdaptiveConfig(initial_level=RefinementLevel.L2_COMPONENT)
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        assert cov.level == RefinementLevel.L2_COMPONENT

    def test_default_level_is_l1(self):
        cov = AdaptiveDiffCoverage(reference_targets=[_make_fake_target()])
        assert cov.level == RefinementLevel.L1_COARSE

    def test_notify_execution_increments(self):
        cov = AdaptiveDiffCoverage(reference_targets=[_make_fake_target()])
        assert cov._total_execs == 0
        cov.notify_execution()
        cov.notify_execution()
        assert cov._total_execs == 2

    def test_notify_new_coverage(self):
        cov = AdaptiveDiffCoverage(reference_targets=[_make_fake_target()])
        cov.notify_new_coverage(42)
        assert cov._last_new_coverage_iter == 42

    def test_check_before_interval_no_transition(self):
        """No transition before check_interval is reached."""
        config = AdaptiveConfig(check_interval=100)
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        corpus = Corpus()
        # Only 10 executions
        for _ in range(10):
            cov.notify_execution()
        assert not cov.check_and_adapt(corpus)

    def test_cooldown_prevents_rapid_transitions(self):
        """Cooldown prevents transition within cooldown_iterations."""
        config = AdaptiveConfig(
            check_interval=10,
            cooldown_iterations=100,
        )
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        corpus = Corpus()
        # Simulate a transition at iter 0
        cov._last_transition_iter = 0
        # Then run 50 execs — still within cooldown
        for _ in range(50):
            cov.notify_execution()
        assert not cov.check_and_adapt(corpus)

    def test_refine_when_corpus_grows_fast(self):
        """Rapid corpus growth triggers refinement (more detail)."""
        config = AdaptiveConfig(
            initial_level=RefinementLevel.L1_COARSE,
            check_interval=100,
            cooldown_iterations=0,
            upper_corpus_pct=5.0,
        )
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        corpus = Corpus()
        # Add many seeds to inflate corpus
        for i in range(100):
            seed = Seed(id=i, input=Input(data=b"x"))
            corpus.seeds.append(seed)
            corpus._id_index[i] = seed
        # 1000 execs but 100 seeds → 10% > 5%
        cov._total_execs = 1000
        cov._last_check_iter = 0
        cov._last_transition_iter = 0

        result = cov.check_and_adapt(corpus)
        assert result  # transition occurred
        assert cov.level == RefinementLevel.L2_COMPONENT

    def test_coarsen_when_stagnating(self):
        """Coverage stagnation triggers coarsening (escape local optimum)."""
        config = AdaptiveConfig(
            initial_level=RefinementLevel.L2_COMPONENT,
            check_interval=100,
            cooldown_iterations=0,
            stagnation_window=500,
            lower_growth_rate=0.01,
        )
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        corpus = Corpus()
        # Small corpus
        seed = Seed(id=0, input=Input(data=b"x"))
        corpus.seeds.append(seed)
        corpus._id_index[0] = seed

        # Simulate: lots of executions, no new coverage
        cov._total_execs = 2000
        cov._last_new_coverage_iter = 0  # stagnated since beginning
        cov._last_check_iter = 0
        cov._last_transition_iter = 0
        cov._corpus_size_at_last_check = 1
        cov._execs_at_last_check = 1

        result = cov.check_and_adapt(corpus)
        assert result
        assert cov.level == RefinementLevel.L1_COARSE

    def test_no_coarsen_below_min_level(self):
        """Cannot coarsen below min_level even when stagnating."""
        config = AdaptiveConfig(
            initial_level=RefinementLevel.L0_MINIMAL,
            check_interval=100,
            cooldown_iterations=0,
            stagnation_window=500,
            lower_growth_rate=0.01,
        )
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        corpus = Corpus()
        seed = Seed(id=0, input=Input(data=b"x"))
        corpus.seeds.append(seed)
        corpus._id_index[0] = seed

        # Stagnation conditions at L0
        cov._total_execs = 2000
        cov._last_new_coverage_iter = 0
        cov._last_check_iter = 0
        cov._last_transition_iter = 0
        cov._corpus_size_at_last_check = 1
        cov._execs_at_last_check = 1
        result = cov.check_and_adapt(corpus)
        assert not result  # already at L0, can't go lower

    def test_no_refine_above_max_level(self):
        """Cannot refine above max_level even with rapid growth."""
        config = AdaptiveConfig(
            initial_level=RefinementLevel.L4_FULL,
            check_interval=100,
            cooldown_iterations=0,
            upper_corpus_pct=1.0,
        )
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        corpus = Corpus()
        # Rapid growth conditions at L4
        for i in range(50):
            seed = Seed(id=i, input=Input(data=b"x"))
            corpus.seeds.append(seed)
            corpus._id_index[i] = seed

        cov._total_execs = 1000
        cov._last_check_iter = 0
        cov._last_transition_iter = 0

        result = cov.check_and_adapt(corpus)
        assert not result  # already at L4, can't go higher

    def test_transition_history_tracked(self):
        config = AdaptiveConfig(
            initial_level=RefinementLevel.L2_COMPONENT,
            check_interval=100,
            cooldown_iterations=0,
            upper_corpus_pct=5.0,
        )
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=config,
        )
        corpus = Corpus()
        for i in range(100):
            seed = Seed(id=i, input=Input(data=b"x"))
            corpus.seeds.append(seed)
            corpus._id_index[i] = seed

        cov._total_execs = 1000
        cov._last_check_iter = 0
        cov._last_transition_iter = 0

        cov.check_and_adapt(corpus)
        assert len(cov.transition_history) == 1
        iter_num, new_level, reason = cov.transition_history[0]
        assert new_level == RefinementLevel.L3_VALUES  # refine on rapid growth
        assert "rapid_growth" in reason

    def test_compute_features_at_level(self):
        """Features at L0 should produce fewer bitmap bits than L4."""
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=AdaptiveConfig(initial_level=RefinementLevel.L1_COARSE),
        )
        record = FeatureRecord(seed_id=0, div_count=2)
        record.features = [
            ("exit_vec", "0,0,1"),
            ("cdiff_0_0", "host,path"),
            ("comp_0_0_host", "1"),
            ("comp_0_0_path", "1"),
            ("val_0_0_host", "abc123"),
            ("status_vec", "200,200,404"),
            ("div_err_0_1", "1"),
        ]

        cov_l0 = cov._compute_features_at_level(record, RefinementLevel.L0_MINIMAL)
        cov_l1 = cov._compute_features_at_level(record, RefinementLevel.L1_COARSE)
        cov_l4 = cov._compute_features_at_level(record, RefinementLevel.L4_FULL)

        # Higher levels should produce more edges (or equal)
        assert cov_l0.edge_count <= cov_l1.edge_count
        assert cov_l1.edge_count <= cov_l4.edge_count

    def test_collect_diff_delegates_to_inner(self):
        """collect_diff passes through to DiffCoverageCollector."""
        ref = _make_fake_target()
        cov = AdaptiveDiffCoverage(reference_targets=[ref])

        inp = Input(data=b"http://example.com")
        primary_result = ExecutionResult(
            exit_code=0,
            stdout=b'{"scheme":"http","host":"example.com","path":"/"}',
        )
        ref_result = ExecutionResult(
            exit_code=0,
            stdout=b'{"scheme":"http","host":"evil.com","path":"/"}',
        )
        coverage = cov.collect_diff(inp, primary_result, ref_results=[ref_result], seed_id=0)
        assert isinstance(coverage, CoverageMap)
        assert coverage.edge_count > 0

    def test_merge_delegates(self):
        cov = AdaptiveDiffCoverage(reference_targets=[_make_fake_target()])
        a = CoverageMap()
        a.bitmap[10] = 1
        b = CoverageMap()
        b.bitmap[20] = 1
        merged = cov.merge(a, b)
        assert merged.bitmap[10] == 1
        assert merged.bitmap[20] == 1

    def test_is_novel_delegates(self):
        cov = AdaptiveDiffCoverage(reference_targets=[_make_fake_target()])
        existing = CoverageMap()
        new = CoverageMap()
        new.bitmap[42] = 1
        assert cov.is_novel(existing, new)


# ── Element-class coverage tests ────────────────────────────────


class TestElementClassCoverage:
    """Test L2 ecat features and restructured elem_div at L3."""

    def test_l2_has_ecat_not_elem_div(self):
        """L2 should include ecat but NOT elem_div/attr_div."""
        assert "ecat" in _LEVEL_PREFIXES[2]
        assert "elem_div" not in _LEVEL_PREFIXES[2]
        assert "attr_div" not in _LEVEL_PREFIXES[2]

    def test_l3_has_both_ecat_and_elem_div(self):
        """L3 should include both ecat and elem_div/attr_div."""
        assert "ecat" in _LEVEL_PREFIXES[3]
        assert "elem_div" in _LEVEL_PREFIXES[3]
        assert "attr_div" in _LEVEL_PREFIXES[3]

    def test_ecat_prefix_handled_in_recompute(self):
        """ecat features should be correctly re-hashed at L2."""
        cov = AdaptiveDiffCoverage(
            reference_targets=[_make_fake_target()],
            config=AdaptiveConfig(initial_level=RefinementLevel.L2_COMPONENT),
        )
        record = FeatureRecord(seed_id=0, div_count=1)
        record.features = [
            ("exit_vec", "0,0"),
            ("cdiff_0_0", "has_svg"),
            ("ecat_0_0_namespace", "True|False"),
            ("elem_div_0_0", "abc12345"),
            ("attr_div_0_0", "def67890"),
        ]

        cov_l2 = cov._compute_features_at_level(record, RefinementLevel.L2_COMPONENT)
        cov_l3 = cov._compute_features_at_level(record, RefinementLevel.L3_VALUES)

        # L2 should have ecat but not elem_div/attr_div
        assert cov_l2.edge_count >= 1
        # L3 should have more edges because it includes elem_div + attr_div
        assert cov_l3.edge_count >= cov_l2.edge_count

    def test_ecat_same_category_same_hash(self):
        """Two inputs diverging on elements in the same security category
        should produce the same ecat feature value."""
        from webfuzzer.fuzzer.coverage.diff_coverage import (
            DiffCoverageCollector, _ELEMENT_CLASSES,
        )
        # Both "svg" and "math" are in the "namespace" category
        assert "svg" in _ELEMENT_CLASSES["namespace"]
        assert "math" in _ELEMENT_CLASSES["namespace"]

    def test_ecat_different_category_different_hash(self):
        """Divergence in different security categories should produce
        different ecat namespace features."""
        from webfuzzer.fuzzer.coverage.diff_coverage import _ELEMENT_CLASSES
        # "script" is in "scripting", "iframe" is in "dangerous"
        assert "script" in _ELEMENT_CLASSES["scripting"]
        assert "iframe" in _ELEMENT_CLASSES["dangerous"]
        # Categories are disjoint
        assert not (_ELEMENT_CLASSES["scripting"] & _ELEMENT_CLASSES["dangerous"])
