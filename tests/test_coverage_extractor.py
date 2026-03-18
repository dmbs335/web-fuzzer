"""Tests for coverage feature extractor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from webfuzzer.fuzzer.concolic.coverage_extractor import (
    TARGET_COV_SIZE,
    NUM_COV_FEATURES,
    COV_FEATURE_NAMES,
    CoverageFeatureExtractor,
)


@dataclass
class MockResult:
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: int = 0
    duration_ms: float = 10.0
    metadata: dict[str, Any] = field(default_factory=dict)


class TestExtractDelta:
    def test_no_coverage_data(self):
        ext = CoverageFeatureExtractor()
        result = MockResult()
        total, new, indices = ext.extract_delta(0, result)
        assert total == 0
        assert new == 0
        assert indices == frozenset()

    def test_first_execution_all_new(self):
        ext = CoverageFeatureExtractor()
        bitmap = bytearray(TARGET_COV_SIZE)
        bitmap[0] = 1
        bitmap[10] = 1
        bitmap[100] = 1
        result = MockResult(metadata={"target_coverage": bytes(bitmap)})
        total, new, indices = ext.extract_delta(0, result)
        assert total == 3
        assert new == 3
        assert indices == frozenset({0, 10, 100})

    def test_second_execution_no_new(self):
        ext = CoverageFeatureExtractor()
        bitmap = bytearray(TARGET_COV_SIZE)
        bitmap[0] = 1
        bitmap[10] = 1
        result = MockResult(metadata={"target_coverage": bytes(bitmap)})

        ext.extract_delta(0, result)  # first
        total, new, indices = ext.extract_delta(0, result)  # second (same)
        assert total == 2
        assert new == 0
        assert indices == frozenset()

    def test_incremental_new(self):
        ext = CoverageFeatureExtractor()
        bitmap1 = bytearray(TARGET_COV_SIZE)
        bitmap1[0] = 1
        r1 = MockResult(metadata={"target_coverage": bytes(bitmap1)})
        ext.extract_delta(0, r1)

        bitmap2 = bytearray(TARGET_COV_SIZE)
        bitmap2[0] = 1  # already seen
        bitmap2[5] = 1  # new
        r2 = MockResult(metadata={"target_coverage": bytes(bitmap2)})
        total, new, indices = ext.extract_delta(0, r2)
        assert total == 2
        assert new == 1
        assert indices == frozenset({5})

    def test_per_library_isolation(self):
        ext = CoverageFeatureExtractor()
        bitmap = bytearray(TARGET_COV_SIZE)
        bitmap[42] = 1
        result = MockResult(metadata={"target_coverage": bytes(bitmap)})

        ext.extract_delta(0, result)  # lib 0
        total, new, indices = ext.extract_delta(1, result)  # lib 1 (separate)
        assert new == 1  # new for lib 1


class TestCoverageFeatures:
    def test_no_coverage_returns_zeros(self):
        ext = CoverageFeatureExtractor()
        primary = MockResult()
        refs = [MockResult(), MockResult()]
        features = ext.coverage_features(primary, refs)
        assert len(features) == NUM_COV_FEATURES
        assert all(f == 0.0 for f in features)

    def test_with_coverage_data(self):
        ext = CoverageFeatureExtractor()
        bitmap = bytearray(TARGET_COV_SIZE)
        for i in range(50):
            bitmap[i] = 1
        primary = MockResult(metadata={"target_coverage": bytes(bitmap)})
        ref = MockResult(metadata={"target_coverage": bytes(bitmap)})
        features = ext.coverage_features(primary, [ref])
        assert len(features) == NUM_COV_FEATURES
        assert features[0] > 0  # primary_branches_hit
        assert features[9] == 1.0  # any_new_branch (first call)

    def test_feature_names_count(self):
        assert len(COV_FEATURE_NAMES) == NUM_COV_FEATURES

    def test_second_call_no_new(self):
        ext = CoverageFeatureExtractor()
        bitmap = bytearray(TARGET_COV_SIZE)
        bitmap[0] = 1
        primary = MockResult(metadata={"target_coverage": bytes(bitmap)})
        ref = MockResult()

        ext.coverage_features(primary, [ref])  # first
        features = ext.coverage_features(primary, [ref])  # second
        assert features[1] == 0.0  # primary_new_branches = 0
        assert features[9] == 0.0  # any_new_branch = false


class TestGetStats:
    def test_stats_structure(self):
        ext = CoverageFeatureExtractor()
        stats = ext.get_stats()
        assert "libraries_tracked" in stats
        assert "cumulative_branches" in stats

    def test_stats_after_extraction(self):
        ext = CoverageFeatureExtractor()
        bitmap = bytearray(TARGET_COV_SIZE)
        bitmap[0] = 1
        bitmap[1] = 1
        result = MockResult(metadata={"target_coverage": bytes(bitmap)})
        ext.extract_delta(0, result)
        stats = ext.get_stats()
        assert stats["libraries_tracked"] == 1
        assert stats["cumulative_branches"]["lib_0"] == 2
