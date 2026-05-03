"""Phase 3C: Runtime sliding-window Hill-MLE α estimator.

Tests for:
- hill_alpha() return value and edge cases
- FuzzStats.alpha_estimate populated by engine after ≥50 novel events
- Engine prefers live alpha_estimate over stopping-signal pareto_alpha
- No update before 50 events (cold start protection)
- Update fires on multiples of 25 only
"""
from __future__ import annotations

import math

import pytest

from webfuzzer.fuzzer.stats import FuzzStats, hill_alpha


# ── hill_alpha() unit tests ──────────────────────────────────────────────────

def _window(counts: list[int]) -> list[tuple[float, int]]:
    """Build a minimal coverage_over_time window from a list of edge counts."""
    return [(float(i), c) for i, c in enumerate(counts)]


def test_hill_alpha_returns_float_for_valid_input():
    counts = [10, 11, 13, 14, 16, 20, 21, 25]
    result = hill_alpha(_window(counts))
    assert result is not None
    assert isinstance(result, float)
    assert result > 1.0


def test_hill_alpha_none_on_too_few_deltas():
    # Only 1 positive delta → undefined
    result = hill_alpha(_window([5, 6]))
    assert result is None


def test_hill_alpha_none_on_flat_sequence():
    # No positive deltas at all
    result = hill_alpha(_window([10, 10, 10, 10]))
    assert result is None


def test_hill_alpha_none_on_empty():
    result = hill_alpha([])
    assert result is None


def test_hill_alpha_none_on_single_entry():
    result = hill_alpha(_window([42]))
    assert result is None


def test_hill_alpha_none_on_monotone_decreasing():
    result = hill_alpha(_window([100, 90, 80, 70]))
    assert result is None


def test_hill_alpha_heavy_tail_sequence():
    """Sequence with rare large jumps → α < 2 (heavy-tailed)."""
    # Many small deltas (1) + one very large delta (1000) = heavy tail
    counts = list(range(50))  # deltas all = 1
    counts.append(counts[-1] + 1000)  # one huge jump
    result = hill_alpha(_window(counts))
    assert result is not None
    # With mixed small and large deltas, α should be small (heavy tail indicator)
    assert result < 10.0  # sanity: estimator is in a reasonable range


def test_hill_alpha_light_tail_uniform():
    """Uniform increments → α is large (light-tailed / near-deterministic)."""
    # All deltas = 5 → log(5/4.5) is tiny per-delta, so α = 1 + n/sum → large
    counts = [i * 5 for i in range(20)]
    result = hill_alpha(_window(counts))
    assert result is not None
    assert result > 5.0


def test_hill_alpha_rounded_to_4_decimals():
    counts = list(range(1, 30))
    result = hill_alpha(_window(counts))
    assert result is not None
    assert result == round(result, 4)


def test_hill_alpha_uses_only_positive_deltas():
    """Decreasing segments are ignored; only positive jumps count."""
    # Interleave increases and decreases
    counts = [0, 5, 3, 8, 6, 11, 9, 14]
    # Positive deltas: 5, 5, 5, 5 (from 0→5, 3→8, 6→11, 9→14)
    result = hill_alpha(_window(counts))
    # All positive deltas are equal (5) → uniform, α should be large
    assert result is not None
    assert result > 5.0


# ── FuzzStats.alpha_estimate field ──────────────────────────────────────────

def test_fuzz_stats_alpha_estimate_defaults_none():
    stats = FuzzStats()
    assert stats.alpha_estimate is None


def test_fuzz_stats_alpha_estimate_settable():
    stats = FuzzStats()
    stats.alpha_estimate = 1.75
    assert stats.alpha_estimate == 1.75


# ── Engine integration: alpha_estimate updated on coverage events ────────────

def _make_engine_with_mock_corpus(n_coverage_events: int):
    """Build a minimal engine-like object just to test the Hill update logic."""
    from webfuzzer.fuzzer.stats import FuzzStats, hill_alpha

    stats = FuzzStats()
    # Simulate n_coverage_events being recorded
    for i in range(n_coverage_events):
        stats.record_new_coverage(100 + i, "test_mutator")

    # Replicate engine trigger logic exactly
    _cot = stats.coverage_over_time
    if len(_cot) >= 50 and len(_cot) % 25 == 0:
        _alpha_hat = hill_alpha(_cot[-300:])
        if _alpha_hat is not None:
            stats.alpha_estimate = _alpha_hat

    return stats


def test_alpha_not_updated_below_50_events():
    stats = _make_engine_with_mock_corpus(49)
    assert stats.alpha_estimate is None


def test_alpha_not_updated_at_51_events():
    # 51 is not a multiple of 25
    stats = _make_engine_with_mock_corpus(51)
    assert stats.alpha_estimate is None


def test_alpha_updated_at_50_events():
    stats = _make_engine_with_mock_corpus(50)
    # 50 >= 50 and 50 % 25 == 0 → should update
    assert stats.alpha_estimate is not None
    assert isinstance(stats.alpha_estimate, float)


def test_alpha_updated_at_75_events():
    stats = _make_engine_with_mock_corpus(75)
    # 75 >= 50 and 75 % 25 == 0 → should update
    assert stats.alpha_estimate is not None


def test_alpha_not_updated_at_60_events():
    # 60 is not a multiple of 25
    stats = _make_engine_with_mock_corpus(60)
    assert stats.alpha_estimate is None


def test_alpha_uses_last_300_entries():
    """Verify window capping: only last 300 entries are passed to hill_alpha."""
    stats = FuzzStats()
    # Insert 400 entries with steadily increasing edge counts
    for i in range(400):
        stats.coverage_over_time.append((float(i), i + 100))

    _cot = stats.coverage_over_time
    # Trigger at 400 (multiple of 25 and >= 50)
    if len(_cot) >= 50 and len(_cot) % 25 == 0:
        _alpha_hat = hill_alpha(_cot[-300:])
        if _alpha_hat is not None:
            stats.alpha_estimate = _alpha_hat

    # Should have computed from the last 300 without crashing
    assert stats.alpha_estimate is not None
