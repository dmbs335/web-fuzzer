"""ConcolicCoordinator: budget-controlled concolic loop for the engine.

Sits between the engine and the constraint extraction/solving pipeline.
Called after each differential execution to optionally generate targeted
inputs.  Enforces a configurable budget cap to guarantee bounded overhead.
"""

from __future__ import annotations

import hashlib
import logging
from collections import deque
from typing import Any

from ..protocols import ExecutionResult, Input
from .constraint import XmlConstraint
from .constraint_extractor import ConstraintExtractor
from .solver import ConstraintSolver

logger = logging.getLogger(__name__)


class ConcolicCoordinator:
    """Coordinates the concolic loop: extract -> model -> solve -> execute.

    Trigger policy:
        Only extracts constraints when at least one (primary, ref) pair
        shows a differential divergence on ``signature_valid`` or ``subject``.
        Non-divergent results skip extraction entirely (zero overhead).

    Budget control:
        Tracks ``concolic_execs / total_execs``.  When the ratio exceeds
        ``budget_pct``, stops generating targeted inputs until the ratio
        drops back below the threshold.
    """

    def __init__(
        self,
        extractor: ConstraintExtractor | None = None,
        solver: ConstraintSolver | None = None,
        budget_pct: float = 0.10,
    ) -> None:
        self._extractor = extractor or ConstraintExtractor()
        self._solver = solver or ConstraintSolver()
        self._budget_pct = budget_pct

        # Constraint database: recent constraints for replay/analysis
        self._constraint_db: deque[tuple[XmlConstraint, bytes]] = deque(maxlen=500)

        # Prevent re-solving identical constraint sets
        self._solved_hashes: set[str] = set()
        self._solved_hashes_max = 5000

        # Counters
        self._concolic_execs = 0
        self._total_iters = 0

        # Domain constraint counts (for reporting)
        self._domain_counts: dict[str, int] = {}

    def on_differential_result(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
        found_finding: bool,
    ) -> list[Input]:
        """Called after each differential execution.

        Returns a list of targeted inputs to execute (0 to MAX_SOLUTIONS).
        Returns empty list if:
          - No divergence detected (fast path)
          - Budget exhausted
          - Constraints already solved (dedup)
        """
        self._total_iters += 1

        # Budget check: don't generate if over budget
        if self._is_over_budget():
            return []

        # Extract constraints (only fires on divergence)
        constraints = self._extractor.extract(inp, primary_result, ref_results)
        if not constraints:
            return []

        # Track domain counts
        for c in constraints:
            self._domain_counts[c.domain] = self._domain_counts.get(c.domain, 0) + 1

        # Store in constraint DB
        for c in constraints:
            self._constraint_db.append((c, inp.data[:256]))

        # Store constraints on the input for coverage features
        inp.metadata["constraints"] = [c.to_dict() for c in constraints]

        # Dedup: don't re-solve identical constraint sets
        constraint_hash = self._hash_constraints(constraints)
        if constraint_hash in self._solved_hashes:
            return []
        self._solved_hashes.add(constraint_hash)
        if len(self._solved_hashes) > self._solved_hashes_max:
            # Evict oldest half
            to_keep = list(self._solved_hashes)[-self._solved_hashes_max // 2:]
            self._solved_hashes = set(to_keep)

        # Solve constraints → generate targeted inputs
        targeted = self._solver.solve(constraints, inp.data)

        # Track concolic execution count (will be incremented by engine)
        self._concolic_execs += len(targeted)

        if targeted:
            logger.debug(
                "Concolic: %d constraints → %d targeted inputs "
                "(budget: %.1f%%)",
                len(constraints), len(targeted),
                self._budget_ratio() * 100,
            )

        return targeted

    def get_stats(self) -> dict[str, Any]:
        """Return stats for status line and report.json."""
        return {
            "concolic_execs": self._concolic_execs,
            "total_iters": self._total_iters,
            "budget_pct": round(self._budget_ratio() * 100, 1),
            "constraints_extracted": self._extractor.stats.total_constraints,
            "solves": self._solver.stats.total_solves,
            "inputs_generated": self._solver.stats.total_inputs,
            "constraint_db_size": len(self._constraint_db),
            "solved_hashes": len(self._solved_hashes),
            "domain_counts": dict(self._domain_counts),
        }

    def get_status_line(self) -> str:
        """Short status string for the engine's periodic status output."""
        ratio = self._budget_ratio() * 100
        total_c = self._extractor.stats.total_constraints
        return f"concolic:{self._concolic_execs}({ratio:.0f}%) cstr:{total_c}"

    # ── Internal ─────────────────────────────────────────────────

    def _is_over_budget(self) -> bool:
        if self._total_iters < 100:
            return False  # Always allow during warmup
        return self._budget_ratio() > self._budget_pct

    def _budget_ratio(self) -> float:
        if self._total_iters == 0:
            return 0.0
        return self._concolic_execs / self._total_iters

    @staticmethod
    def _hash_constraints(constraints: list[XmlConstraint]) -> str:
        parts = sorted(
            f"{c.domain}:{c.predicate}:{c.library_pair}"
            for c in constraints
        )
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
