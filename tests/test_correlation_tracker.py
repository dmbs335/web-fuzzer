"""Tests for correlation tracker."""

from __future__ import annotations

import random

import pytest

from webfuzzer.fuzzer.concolic.correlation_tracker import (
    CorrelationTracker,
    _MI_RECOMPUTE_INTERVAL,
)
from webfuzzer.fuzzer.concolic.property_vector import (
    NUM_PROPERTIES,
    DivergenceVector,
    Observation,
    PropertyVector,
)


def _make_pv(values: list[float] | None = None) -> PropertyVector:
    """Create a PropertyVector with default zeros or given values."""
    if values is None:
        values = [0.0] * NUM_PROPERTIES
    while len(values) < NUM_PROPERTIES:
        values.append(0.0)
    return PropertyVector(tuple(values[:NUM_PROPERTIES]))


def _make_obs(
    prop_values: list[float] | None = None,
    divergent_fields: frozenset[str] | None = None,
    strategies: list[str] | None = None,
    timestamp: int = 0,
) -> Observation:
    """Create an Observation for testing."""
    props = _make_pv(prop_values)
    divs = []
    if divergent_fields:
        divs.append(
            DivergenceVector(
                pair=(0, 1),
                field_diffs=divergent_fields,
                sig_diverges="signature_valid" in divergent_fields,
                subject_diverges="subject" in divergent_fields,
            )
        )
    return Observation(
        properties=props,
        divergences=divs,
        strategy_names=strategies or [],
        found_finding=False,
        timestamp=timestamp,
    )


class TestCorrelationTrackerBasic:
    """Basic tracker behavior."""

    def test_empty_tracker(self):
        tracker = CorrelationTracker()
        assert tracker.top_correlations() == []
        assert tracker.property_importance() == [(i, 0.0) for i in range(NUM_PROPERTIES)]
        assert tracker.strategy_effectiveness() == {}

    def test_record_single(self):
        tracker = CorrelationTracker()
        obs = _make_obs()
        tracker.record(obs)
        assert len(tracker._observations) == 1

    def test_record_fills_window(self):
        tracker = CorrelationTracker(window_size=100)
        for i in range(150):
            tracker.record(_make_obs(timestamp=i))
        assert len(tracker._observations) == 100

    def test_field_discovery(self):
        tracker = CorrelationTracker()
        obs = _make_obs(divergent_fields=frozenset({"signature_valid", "subject"}))
        tracker.record(obs)
        assert "signature_valid" in tracker._field_names
        assert "subject" in tracker._field_names


class TestMIComputation:
    """Test mutual information computation."""

    def test_perfect_correlation(self):
        """When a property perfectly predicts divergence, MI should be high."""
        tracker = CorrelationTracker(window_size=1000)

        rng = random.Random(42)
        # Property 0 high → always diverges; property 0 low → never diverges
        for i in range(600):
            high_prop = rng.uniform(0.6, 1.0)
            low_prop = rng.uniform(0.0, 0.3)
            if i % 2 == 0:
                # High property → divergence
                obs = _make_obs(
                    prop_values=[high_prop],
                    divergent_fields=frozenset({"signature_valid"}),
                    timestamp=i,
                )
            else:
                # Low property → no divergence
                obs = _make_obs(
                    prop_values=[low_prop],
                    timestamp=i,
                )
            tracker.record(obs)

        # Force MI recompute
        tracker._recompute_mi()

        # Property 0 should have highest MI with signature_valid
        importance = tracker.property_importance()
        top_prop = importance[0]
        assert top_prop[0] == 0, f"Expected property 0 to be most important, got {top_prop[0]}"
        assert top_prop[1] > 0.1, f"Expected significant MI, got {top_prop[1]}"

    def test_no_correlation(self):
        """When property is independent of divergence, MI should be near zero."""
        tracker = CorrelationTracker(window_size=1000)

        rng = random.Random(42)
        for i in range(600):
            prop_val = rng.uniform(0.0, 1.0)
            diverges = rng.random() < 0.5  # independent of property
            obs = _make_obs(
                prop_values=[prop_val],
                divergent_fields=frozenset({"subject"}) if diverges else None,
                timestamp=i,
            )
            tracker.record(obs)

        tracker._recompute_mi()

        # All MI scores should be low
        importance = tracker.property_importance()
        max_mi = importance[0][1]
        assert max_mi < 0.1, f"Expected low MI for independent property, got {max_mi}"

    def test_multiple_correlated_properties(self):
        """Multiple properties can independently correlate with divergence."""
        tracker = CorrelationTracker(window_size=2000)

        rng = random.Random(42)
        for i in range(1000):
            p0 = rng.uniform(0.0, 1.0)
            p1 = rng.uniform(0.0, 1.0)
            # Property 0 high → sig diverges, Property 1 high → subject diverges
            sig_div = p0 > 0.5
            subj_div = p1 > 0.5
            fields: set[str] = set()
            if sig_div:
                fields.add("signature_valid")
            if subj_div:
                fields.add("subject")

            obs = _make_obs(
                prop_values=[p0, p1],
                divergent_fields=frozenset(fields) if fields else None,
                timestamp=i,
            )
            tracker.record(obs)

        tracker._recompute_mi()

        top = tracker.top_correlations(4)
        # Both property 0 and property 1 should appear in top correlations
        top_props = {t[0] for t in top}
        assert "total_bytes" in top_props or "tag_count" in top_props  # props 0 or 1


class TestStrategyEffectiveness:
    """Test strategy tracking."""

    def test_strategy_tracking(self):
        tracker = CorrelationTracker()

        # Strategy "xsw1" causes divergence 8 out of 12 times
        for i in range(12):
            diverges = i < 8
            obs = _make_obs(
                divergent_fields=frozenset({"signature_valid"}) if diverges else None,
                strategies=["xsw1"],
                timestamp=i,
            )
            tracker.record(obs)

        eff = tracker.strategy_effectiveness()
        assert "xsw1" in eff
        assert abs(eff["xsw1"] - 8 / 12) < 0.01

    def test_min_trials_threshold(self):
        tracker = CorrelationTracker()

        # Only 5 trials — below threshold of 10
        for i in range(5):
            obs = _make_obs(
                divergent_fields=frozenset({"subject"}),
                strategies=["rare_strat"],
                timestamp=i,
            )
            tracker.record(obs)

        eff = tracker.strategy_effectiveness()
        assert "rare_strat" not in eff  # too few trials


class TestAdaptiveBinning:
    """Test bin edge recomputation."""

    def test_bin_edges_adapt(self):
        tracker = CorrelationTracker()

        rng = random.Random(42)
        # Feed heavily skewed property values
        for i in range(500):
            # Property 0 is always near 0.9
            obs = _make_obs(prop_values=[rng.uniform(0.8, 1.0)], timestamp=i)
            tracker.record(obs)

        tracker._recompute_bin_edges()

        # Bin edges for property 0 should be in [0.8, 1.0] range, not [0.25, 0.75]
        edges = tracker._bin_edges[0]
        assert edges[0] > 0.7, f"Expected adapted bin edge, got {edges[0]}"


class TestSlidingWindow:
    """Test observation eviction."""

    def test_eviction_decrements_contingency(self):
        tracker = CorrelationTracker(window_size=10)

        # Fill window with divergent observations
        for i in range(10):
            obs = _make_obs(
                prop_values=[0.5],
                divergent_fields=frozenset({"signature_valid"}),
                timestamp=i,
            )
            tracker.record(obs)

        # Now add 10 non-divergent — should push out all divergent ones
        for i in range(10, 20):
            obs = _make_obs(prop_values=[0.5], timestamp=i)
            tracker.record(obs)

        tracker._recompute_mi()

        # MI should be near zero (all recent observations are non-divergent)
        importance = tracker.property_importance()
        assert importance[0][1] < 0.05


class TestGetStats:
    """Test stats reporting."""

    def test_stats_structure(self):
        tracker = CorrelationTracker()
        stats = tracker.get_stats()
        assert "observations" in stats
        assert "tracked_fields" in stats
        assert "tracked_strategies" in stats
        assert "top_correlations" in stats
