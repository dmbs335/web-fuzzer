"""Tests for MCTS-guided grammar production selection."""

import math

import pytest

from webfuzzer.fuzzer.mcts import UCBTable


class TestUCBTable:
    def test_unvisited_arms_selected(self):
        """Unvisited arms get infinite UCB1 → selected preferentially."""
        table = UCBTable(exploration_weight=1.41, seed=42)
        weights = [1.0, 1.0, 1.0]
        # All unvisited — should pick one of them
        idx = table.select_production("rule_a", 3, weights)
        assert 0 <= idx < 3

    def test_visit_tracking(self):
        table = UCBTable(seed=42)
        table.record_visit("rule_a", 0)
        table.record_visit("rule_a", 0)
        table.record_visit("rule_a", 1)
        stats = table.stats_summary()
        assert stats["total_arms"] == 2
        assert stats["total_visits"] == 3
        assert stats["rules_tracked"] == 1

    def test_exploitation_after_visits(self):
        """With c=0 (pure exploitation), always pick the highest reward arm."""
        table = UCBTable(exploration_weight=0.0, seed=42)
        # Visit all arms so none are infinity
        for i in range(3):
            table.record_visit("rule_a", i)

        # Backpropagate high reward to arm 1
        table.backpropagate([("rule_a", 1)], 10.0)

        # With c=0, should consistently pick arm 1
        choices = set()
        for _ in range(20):
            idx = table.select_production("rule_a", 3, [1.0, 1.0, 1.0])
            choices.add(idx)
        assert choices == {1}

    def test_exploration_with_high_c(self):
        """With very high c, exploration dominates — less-visited arms get picked."""
        table = UCBTable(exploration_weight=100.0, seed=42)
        # Visit arm 0 many times, arm 1 once, arm 2 once
        for _ in range(100):
            table.record_visit("rule_a", 0)
        table.record_visit("rule_a", 1)
        table.record_visit("rule_a", 2)

        # Backpropagate reward to arm 0 so it has best mean
        table.backpropagate([("rule_a", 0)], 5.0)

        # With c=100, arms 1 and 2 should get picked due to exploration
        choices = set()
        for _ in range(50):
            idx = table.select_production("rule_a", 3, [1.0, 1.0, 1.0])
            choices.add(idx)
        assert 1 in choices or 2 in choices

    def test_backpropagation(self):
        """Reward propagates to all nodes in derivation path."""
        table = UCBTable(seed=42)
        path = [("rule_a", 0), ("rule_b", 1), ("rule_c", 2)]
        table.backpropagate(path, 5.0)

        # All arms should have reward
        for rule, prod in path:
            key = (rule, prod)
            assert key in table._stats
            assert table._stats[key].total_reward == 5.0

    def test_backpropagation_zero_reward_skipped(self):
        """Zero reward doesn't create entries."""
        table = UCBTable(seed=42)
        table.backpropagate([("rule_a", 0)], 0.0)
        assert len(table._stats) == 0

    def test_ucb1_formula(self):
        """Verify the UCB1 score computation manually."""
        table = UCBTable(exploration_weight=1.0, seed=42)
        table.record_visit("r", 0)
        table.record_visit("r", 0)
        table.record_visit("r", 1)
        table.backpropagate([("r", 0)], 2.0)
        table.backpropagate([("r", 1)], 1.0)

        # Arm 0: mean = 2.0/2 = 1.0, visits=2, rule_total=3
        # Arm 1: mean = 1.0/1 = 1.0, visits=1, rule_total=3
        score_0 = table._ucb1_score("r", 0)
        score_1 = table._ucb1_score("r", 1)

        expected_0 = 1.0 + 1.0 * math.sqrt(math.log(3) / 2)
        expected_1 = 1.0 + 1.0 * math.sqrt(math.log(3) / 1)
        assert abs(score_0 - expected_0) < 1e-9
        assert abs(score_1 - expected_1) < 1e-9

    def test_unvisited_score_is_infinity(self):
        table = UCBTable(seed=42)
        assert math.isinf(table._ucb1_score("r", 0))

    def test_weighted_unvisited_selection(self):
        """Unvisited arms use grammar weights for selection."""
        table = UCBTable(seed=42)
        # Visit arm 0, leave 1 and 2 unvisited
        table.record_visit("r", 0)
        # Weight arm 2 very heavily
        weights = [1.0, 0.0001, 100.0]
        picks = [table.select_production("r", 3, weights) for _ in range(100)]
        # Arm 2 should be picked much more than arm 1
        count_2 = picks.count(2)
        count_1 = picks.count(1)
        assert count_2 > count_1

    def test_determinism_with_seed(self):
        """Same seed produces identical selections."""
        def run_selections(rng_seed):
            table = UCBTable(seed=rng_seed)
            for i in range(3):
                table.record_visit("r", i)
            table.backpropagate([("r", 0)], 1.0)
            return [table.select_production("r", 3, [1.0, 1.0, 1.0]) for _ in range(10)]

        assert run_selections(42) == run_selections(42)

    def test_multiple_rules_independent(self):
        """Stats for different rules are independent."""
        table = UCBTable(seed=42)
        table.record_visit("rule_a", 0)
        table.backpropagate([("rule_a", 0)], 10.0)

        # rule_b arm 0 is unvisited
        assert math.isinf(table._ucb1_score("rule_b", 0))
