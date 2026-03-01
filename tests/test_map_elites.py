"""Tests for MAP-Elites quality-diversity scheduler."""

import pytest

from webfuzzer.fuzzer.corpus import Corpus, CoverageMap, Seed
from webfuzzer.fuzzer.protocols import Input, ScheduleResult
from webfuzzer.fuzzer.schedulers.map_elites import (
    CATEGORIES,
    MAX_REF_INDEX,
    MapElitesArchive,
    MapElitesScheduler,
)
from webfuzzer.fuzzer.schedulers.composite import CompositeScheduler


def _make_seed(seed_id: int, feature_count: int = 3) -> Seed:
    s = Seed(id=seed_id, input=Input(data=b"test"))
    s.feature_set = set(range(feature_count))
    return s


class TestMapElitesArchive:
    def test_insert_into_empty_cell(self):
        archive = MapElitesArchive()
        seed = _make_seed(0)
        assert archive.try_insert(seed, "ssrf_host_confusion", 0)
        assert archive.filled_cells == 1

    def test_insert_richer_replaces(self):
        archive = MapElitesArchive()
        weak = _make_seed(0, feature_count=2)
        strong = _make_seed(1, feature_count=5)
        archive.try_insert(weak, "ssrf_host_confusion", 0)
        assert archive.try_insert(strong, "ssrf_host_confusion", 0)
        assert archive._grid[(0, 0)].id == 1

    def test_insert_weaker_rejected(self):
        archive = MapElitesArchive()
        strong = _make_seed(0, feature_count=5)
        weak = _make_seed(1, feature_count=2)
        archive.try_insert(strong, "ssrf_host_confusion", 0)
        assert not archive.try_insert(weak, "ssrf_host_confusion", 0)
        assert archive._grid[(0, 0)].id == 0

    def test_unknown_category_maps_to_no_finding(self):
        archive = MapElitesArchive()
        seed = _make_seed(0)
        archive.try_insert(seed, "totally_unknown_category", 0)
        # Unknown → last category index (no_finding)
        expected_cat_idx = len(CATEGORIES) - 1
        assert (expected_cat_idx, 0) in archive._grid

    def test_ref_index_clamped(self):
        archive = MapElitesArchive()
        seed = _make_seed(0)
        archive.try_insert(seed, "ssrf_host_confusion", 100)
        # Clamped to MAX_REF_INDEX - 1
        assert (0, MAX_REF_INDEX - 1) in archive._grid

    def test_negative_ref_index_clamped(self):
        archive = MapElitesArchive()
        seed = _make_seed(0)
        archive.try_insert(seed, "ssrf_host_confusion", -5)
        assert (0, 0) in archive._grid

    def test_total_cells(self):
        archive = MapElitesArchive()
        assert archive.total_cells == len(CATEGORIES) * MAX_REF_INDEX

    def test_coverage_ratio(self):
        archive = MapElitesArchive()
        archive.try_insert(_make_seed(0), "ssrf_host_confusion", 0)
        assert archive.coverage_ratio() == pytest.approx(1 / archive.total_cells)

    def test_frontier_seeds_near_empty(self):
        archive = MapElitesArchive()
        seed = _make_seed(0)
        archive.try_insert(seed, "ssrf_host_confusion", 0)
        frontier = archive.frontier_seeds()
        # Cell (0,0) has empty neighbours → it's frontier
        assert seed in frontier

    def test_frontier_fallback_when_all_surrounded(self):
        """When no empty neighbours exist, return all seeds."""
        archive = MapElitesArchive()
        # Fill a 3×3 block so center (1,1) has no empty neighbours
        seeds = []
        for cat_i in range(3):
            for ref_i in range(3):
                s = _make_seed(cat_i * 3 + ref_i)
                key = (cat_i, ref_i)
                archive._grid[key] = s
                seeds.append(s)
        # Center cell's neighbours are all filled
        # But the border cells still have empty neighbours, so frontier is non-empty
        frontier = archive.frontier_seeds()
        assert len(frontier) > 0

    def test_all_seeds(self):
        archive = MapElitesArchive()
        s1 = _make_seed(0)
        s2 = _make_seed(1)
        archive.try_insert(s1, "ssrf_host_confusion", 0)
        archive.try_insert(s2, "open_redirect", 1)
        assert len(archive.all_seeds()) == 2


class TestMapElitesScheduler:
    def test_select_from_archive(self):
        scheduler = MapElitesScheduler(seed=42)
        corpus = Corpus()
        seed = _make_seed(0)
        corpus.seeds = [seed]
        # Insert into archive so frontier has something
        scheduler.archive.try_insert(seed, "ssrf_host_confusion", 0)
        selected = scheduler.select(corpus)
        assert selected.id == 0

    def test_select_fallback_to_corpus(self):
        scheduler = MapElitesScheduler(seed=42)
        corpus = Corpus()
        seed = _make_seed(0)
        corpus.seeds = [seed]
        # Empty archive → fallback to corpus
        selected = scheduler.select(corpus)
        assert selected.id == 0

    def test_select_empty_corpus_raises(self):
        scheduler = MapElitesScheduler(seed=42)
        corpus = Corpus()
        with pytest.raises(RuntimeError):
            scheduler.select(corpus)

    def test_update_with_finding_metadata(self):
        scheduler = MapElitesScheduler(seed=42)
        seed = _make_seed(0, feature_count=5)
        result = ScheduleResult(
            found_new_coverage=True,
            finding_metadata=[
                {"category": "ssrf_host_confusion", "ref_index": 0, "severity": "high"},
            ],
        )
        scheduler.update(seed, result)
        assert scheduler.archive.filled_cells == 1

    def test_update_without_findings_uses_no_finding(self):
        scheduler = MapElitesScheduler(seed=42)
        seed = _make_seed(0)
        result = ScheduleResult(found_new_coverage=True)
        scheduler.update(seed, result)
        assert scheduler.archive.filled_cells == 1

    def test_update_multiple_findings(self):
        scheduler = MapElitesScheduler(seed=42)
        seed = _make_seed(0, feature_count=5)
        result = ScheduleResult(
            found_new_coverage=True,
            finding_metadata=[
                {"category": "ssrf_host_confusion", "ref_index": 0},
                {"category": "open_redirect", "ref_index": 1},
            ],
        )
        scheduler.update(seed, result)
        assert scheduler.archive.filled_cells == 2


class TestCompositeScheduler:
    def _make_mock_scheduler(self, seed_to_return):
        class MockScheduler:
            selected = False
            updated = False
            def select(self, corpus):
                self.selected = True
                return seed_to_return
            def update(self, seed, result):
                self.updated = True
        return MockScheduler()

    def test_forwards_update_to_both(self):
        seed = _make_seed(0)
        primary = self._make_mock_scheduler(seed)
        secondary = self._make_mock_scheduler(seed)
        comp = CompositeScheduler(primary, secondary, p_secondary=0.5, seed=42)

        result = ScheduleResult()
        comp.update(seed, result)
        assert primary.updated
        assert secondary.updated

    def test_selects_from_one_scheduler(self):
        seed = _make_seed(0)
        primary = self._make_mock_scheduler(seed)
        secondary = self._make_mock_scheduler(seed)
        comp = CompositeScheduler(primary, secondary, p_secondary=0.0, seed=42)

        corpus = Corpus()
        corpus.seeds = [seed]
        selected = comp.select(corpus)
        assert selected.id == 0
        # With p_secondary=0, should always pick primary
        assert primary.selected

    def test_p_secondary_1_always_secondary(self):
        seed = _make_seed(0)
        primary = self._make_mock_scheduler(seed)
        secondary = self._make_mock_scheduler(seed)
        comp = CompositeScheduler(primary, secondary, p_secondary=1.0, seed=42)

        corpus = Corpus()
        corpus.seeds = [seed]
        comp.select(corpus)
        assert secondary.selected
