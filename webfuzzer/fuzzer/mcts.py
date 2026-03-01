"""MCTS-guided production selection for grammar derivation.

Tracks UCB1 scores per (rule_name, production_idx) pair.
Used by TreeGenerator to balance exploitation (high-reward productions)
vs exploration (untried productions) during grammar-based input generation.

The key idea: grammar derivation is a sequential decision problem.
Each rule expansion is a choice point.  MCTS learns which production
alternatives lead to inputs that discover new coverage or findings.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field


@dataclass
class _ArmStats:
    """Statistics for one production arm."""

    visits: int = 0
    total_reward: float = 0.0

    @property
    def mean_reward(self) -> float:
        return self.total_reward / self.visits if self.visits else 0.0


class UCBTable:
    """UCB1 scores for grammar production selection.

    Key: ``(rule_name, production_idx)``

    Tracks visit counts and cumulative reward per arm.  The exploration
    weight *c* controls the exploitation/exploration trade-off:

    - ``c = 0``: pure exploitation (always pick best-known production)
    - ``c = 1.41`` (default, √2): balanced UCB1
    - ``c > 2``: aggressive exploration
    """

    def __init__(
        self,
        exploration_weight: float = 1.41,
        seed: int | None = None,
    ) -> None:
        self.c = exploration_weight
        self._stats: dict[tuple[str, int], _ArmStats] = {}
        self._rule_visits: dict[str, int] = {}
        self._rng = random.Random(seed)

    # ── Public API ────────────────────────────────────────────────

    def select_production(
        self,
        rule_name: str,
        num_productions: int,
        production_weights: list[float],
    ) -> int:
        """Select a production index using UCB1.

        For rules with unvisited arms, picks among unvisited weighted by
        the grammar's production weights (preserving the grammar author's
        intent for rarely-seen rules).

        For fully-visited rules, picks the arm with the highest UCB1 score.
        """
        # Inline UCB1 computation to avoid per-arm function call overhead.
        _stats = self._stats
        rule_total = self._rule_visits.get(rule_name, 0)
        _c = self.c
        _log = math.log
        _sqrt = math.sqrt
        _inf = float("inf")

        unvisited = []
        scores = []
        has_unvisited = False

        if rule_total == 0:
            # No visits to this rule at all — all arms are unvisited.
            return self._rng.choices(
                range(num_productions), weights=production_weights, k=1,
            )[0] if sum(production_weights) > 0 else self._rng.randrange(num_productions)

        log_total = _log(rule_total)

        for i in range(num_productions):
            arm = _stats.get((rule_name, i))
            if arm is None or arm.visits == 0:
                unvisited.append(i)
                has_unvisited = True
            else:
                scores.append((i, arm.total_reward / arm.visits + _c * _sqrt(log_total / arm.visits)))

        if has_unvisited:
            weights = [production_weights[i] for i in unvisited]
            total = sum(weights)
            if total > 0:
                return self._rng.choices(unvisited, weights=weights, k=1)[0]
            return self._rng.choice(unvisited)

        # All visited — pick highest UCB1, break ties randomly.
        max_score = max(s for _, s in scores)
        best = [i for i, s in scores if abs(s - max_score) < 1e-9]
        return self._rng.choice(best)

    def record_visit(self, rule_name: str, production_idx: int) -> None:
        """Record that a production was chosen (before reward is known)."""
        key = (rule_name, production_idx)
        if key not in self._stats:
            self._stats[key] = _ArmStats()
        self._stats[key].visits += 1
        self._rule_visits[rule_name] = self._rule_visits.get(rule_name, 0) + 1

    def backpropagate(
        self,
        derivation_path: list[tuple[str, int]],
        reward: float,
    ) -> None:
        """Backpropagate reward along the derivation path.

        Args:
            derivation_path: Sequence of ``(rule_name, production_idx)``
                from the derivation tree.
            reward: Scalar reward (e.g. 1.0 for new coverage, 5.0 for
                crash/finding, 0.0 for nothing).
        """
        if reward == 0.0:
            return
        for rule_name, prod_idx in derivation_path:
            key = (rule_name, prod_idx)
            if key not in self._stats:
                self._stats[key] = _ArmStats()
                self._stats[key].visits = 1
                self._rule_visits[rule_name] = self._rule_visits.get(rule_name, 0) + 1
            self._stats[key].total_reward += reward

    def stats_summary(self) -> dict[str, int]:
        """Return summary for logging/debugging."""
        return {
            "total_arms": len(self._stats),
            "total_visits": sum(s.visits for s in self._stats.values()),
            "rules_tracked": len(self._rule_visits),
        }

    # ── Internal ──────────────────────────────────────────────────

    def _ucb1_score(self, rule_name: str, production_idx: int) -> float:
        """Compute UCB1 score for a (rule, production) pair."""
        key = (rule_name, production_idx)
        stats = self._stats.get(key)
        if stats is None or stats.visits == 0:
            return float("inf")

        rule_total = self._rule_visits.get(rule_name, 1)
        exploitation = stats.mean_reward
        exploration = self.c * math.sqrt(math.log(rule_total) / stats.visits)
        return exploitation + exploration
