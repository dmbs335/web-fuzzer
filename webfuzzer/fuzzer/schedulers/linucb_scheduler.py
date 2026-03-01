"""LinUCB contextual bandit for mutator scheduling.

Learns context-dependent mutator selection: which mutator works best
for which *kind* of seed.  Context features are extracted from the seed
being mutated (AST depth, energy, finding count, etc.).

Pure Python with manual 8×8 matrix operations — no numpy dependency.
Sherman-Morrison incremental inverse keeps updates O(d²).

Reference:
  Li et al., "A Contextual-Bandit Approach to Personalized News Article
  Recommendation", WWW 2010.
"""

from __future__ import annotations

import math
import random
import time
from typing import TYPE_CHECKING

from ..protocols import Mutator, ScheduleResult

if TYPE_CHECKING:
    from ..corpus import Seed

# Dimension of context feature vector.
_D = 8


class LinUCBScheduler:
    """LinUCB contextual bandit for mutator selection.

    Per-arm linear model:
      - ``A_a`` (d × d): feature outer-product accumulator
      - ``b_a`` (d-vector): reward-weighted feature accumulator
      - ``theta_a = A_a^{-1} b_a``: estimated reward weights

    Selection:
      ``p_a = x^T theta_a + alpha * sqrt(x^T A_a^{-1} x)``

    Pick the arm with the highest ``p_a``.
    """

    def __init__(
        self,
        alpha: float = 1.0,
        seed: int | None = None,
    ) -> None:
        self.alpha = alpha
        self._initialized = False
        self._k = 0

        self._A: list[list[list[float]]] = []
        self._b: list[list[float]] = []
        self._A_inv: list[list[list[float]]] = []

        self._last_context: list[float] | None = None
        self._last_arm: int = -1

        self._rng = random.Random(seed)

    # ── MutatorScheduler Protocol ────────────────────────────────

    def select(self, mutators: list[Mutator], seed: Seed) -> Mutator:
        """Select mutator using LinUCB."""
        if not self._initialized or self._k != len(mutators):
            self._init_arms(len(mutators))

        x = self._extract_context(seed)
        self._last_context = x

        best_score = -float("inf")
        best_arms: list[int] = []

        for a in range(self._k):
            A_inv = self._A_inv[a]
            b = self._b[a]

            # theta_a = A_inv @ b
            theta = _matvec(A_inv, b)

            # exploitation: x^T theta
            exploit = _dot(x, theta)

            # exploration: alpha * sqrt(x^T A_inv x)
            A_inv_x = _matvec(A_inv, x)
            explore = self.alpha * math.sqrt(max(_dot(x, A_inv_x), 0.0))

            score = exploit + explore

            if score > best_score + 1e-9:
                best_score = score
                best_arms = [a]
            elif abs(score - best_score) < 1e-9:
                best_arms.append(a)

        chosen_arm = self._rng.choice(best_arms)
        self._last_arm = chosen_arm
        return mutators[chosen_arm]

    def update(self, mutator: Mutator, result: ScheduleResult) -> None:
        """Update LinUCB model with observed reward."""
        if self._last_context is None or self._last_arm < 0:
            return

        x = self._last_context
        a = self._last_arm
        reward = self._compute_reward(result)

        # A_a += x @ x^T  (rank-1 update)
        for i in range(_D):
            for j in range(_D):
                self._A[a][i][j] += x[i] * x[j]

        # b_a += reward * x
        for i in range(_D):
            self._b[a][i] += reward * x[i]

        # Sherman-Morrison incremental inverse:
        # (A + xx^T)^{-1} = A^{-1} - (A^{-1} x)(x^T A^{-1}) / (1 + x^T A^{-1} x)
        A_inv = self._A_inv[a]
        A_inv_x = _matvec(A_inv, x)
        denom = 1.0 + _dot(x, A_inv_x)

        for i in range(_D):
            for j in range(_D):
                A_inv[i][j] -= (A_inv_x[i] * A_inv_x[j]) / denom

        self._last_context = None
        self._last_arm = -1

    # ── Context feature extraction ───────────────────────────────

    def _extract_context(self, seed: Seed) -> list[float]:
        """Extract d-dimensional context vector from seed.

        Features (d=8):
          [0] tree_depth:      Normalised AST depth (0–1)
          [1] has_findings:    1.0 if finding_count > 0
          [2] rule_diversity:  Unique rule names / total nodes (0–1)
          [3] exec_count_log:  log2(exec_count + 1) / 20
          [4] energy:          seed.energy / 10 (clamped to 1)
          [5] age:             hours since creation / 24 (clamped)
          [6] depth:           mutation chain depth / 20 (clamped)
          [7] bias:            1.0 (intercept term)
        """
        meta = seed.input.metadata if seed.input.metadata else {}
        tree = meta.get("tree")

        # Feature 0: tree depth
        if tree is not None:
            try:
                raw_depth = tree.root.depth()
                tree_depth = min(raw_depth / 20.0, 1.0)
            except Exception:
                tree_depth = 0.5
        else:
            tree_depth = 0.5

        # Feature 1: has findings
        has_findings = 1.0 if seed.finding_count > 0 else 0.0

        # Feature 2: rule diversity
        if tree is not None:
            try:
                rule_nodes = tree.root.all_rule_nodes()
                if rule_nodes:
                    unique = len({n.rule_name for n in rule_nodes})
                    rule_diversity = min(unique / max(len(rule_nodes), 1), 1.0)
                else:
                    rule_diversity = 0.0
            except Exception:
                rule_diversity = 0.5
        else:
            rule_diversity = 0.5

        # Feature 3: exec count (log normalised)
        exec_log = math.log2(seed.exec_count + 1) / 20.0

        # Feature 4: energy (clamped)
        energy = min(seed.energy / 10.0, 1.0)

        # Feature 5: age in hours (clamped)
        age_hours = (time.time() - seed.created_at) / 3600.0
        age = min(age_hours / 24.0, 1.0)

        # Feature 6: mutation chain depth
        chain_depth = min(seed.depth / 20.0, 1.0)

        # Feature 7: bias
        bias = 1.0

        return [tree_depth, has_findings, rule_diversity, exec_log,
                energy, age, chain_depth, bias]

    # ── Internal helpers ─────────────────────────────────────────

    def _init_arms(self, k: int) -> None:
        self._k = k
        self._A = []
        self._b = []
        self._A_inv = []
        for _ in range(k):
            self._A.append(_identity(_D))
            self._b.append([0.0] * _D)
            self._A_inv.append(_identity(_D))
        self._initialized = True

    @staticmethod
    def _compute_reward(result: ScheduleResult) -> float:
        reward = 0.0
        if result.found_new_coverage:
            reward += 1.0
        if result.found_crash:
            reward += 5.0
        if reward == 0.0:
            reward = -0.01
        return reward


# ── Pure-Python linear algebra for small matrices ────────────────


def _identity(d: int) -> list[list[float]]:
    return [[1.0 if i == j else 0.0 for j in range(d)] for i in range(d)]


def _dot(a: list[float], b: list[float]) -> float:
    return sum(ai * bi for ai, bi in zip(a, b))


def _matvec(A: list[list[float]], x: list[float]) -> list[float]:
    return [_dot(row, x) for row in A]
