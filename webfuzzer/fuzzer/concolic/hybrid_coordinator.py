"""Hybrid concolic coordinator: v1 expert gadgets + v2 learned feedback.

Combines:
- v1 Expert: ConstraintExtractor → ConstraintSolver → targeted inputs (strong for known patterns)
- v2 Learned: CorrelationTracker → property perturbation + strategy weight feedback (strong for discovery)

Budget split: expert gets max (1 - generic_min_share) of concolic budget,
generic gets at least generic_min_share. Learning (tracker.record) runs
unconditionally on every iteration.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
from collections import deque
from typing import Any

from ..protocols import ExecutionResult, Input
from .constraint import XmlConstraint
from .constraint_extractor import ConstraintExtractor
from .correlation_tracker import CorrelationTracker
from .concolic_engine import ConcolicEngine
from .real_concolic import RealConcolicEngine
from .coverage_extractor import CoverageFeatureExtractor
from .domain_plugin import DomainPlugin
from .property_extractor import PROPERTY_NAMES, PropertyExtractor
from .property_guided import _EXCLUDED_FIELDS, _perturb_property
from .property_vector import DivergenceVector, Observation
from .solver import ConstraintSolver

logger = logging.getLogger(__name__)

MAX_SOLUTIONS = 5
_WARMUP_ITERS = 500
_MI_THRESHOLD = 0.02
_WEIGHT_UPDATE_INTERVAL = 1000


class HybridCoordinator:
    """Merged v1 expert + v2 learned coordinator.

    Same API as ConcolicCoordinator and PropertyGuidedCoordinator:
    ``on_differential_result() -> list[Input]``
    """

    def __init__(
        self,
        extractor: ConstraintExtractor | None = None,
        solver: ConstraintSolver | None = None,
        budget_pct: float = 0.10,
        generic_min_share: float = 0.40,
        seed: int | None = None,
        use_expert: bool = True,
        use_coverage: bool = False,
        domain_plugin: DomainPlugin | None = None,
    ) -> None:
        # Domain plugin (generalizes property extraction + perturbation)
        self._plugin = domain_plugin

        # v1 expert components (disabled in whitebox mode)
        self._use_expert = use_expert
        self._extractor = extractor or ConstraintExtractor() if use_expert else None
        self._solver = solver or ConstraintSolver(seed=seed) if use_expert else None

        # v2 learned components — use plugin if available, else SAML default
        if self._plugin is not None:
            self._prop_extractor = self._plugin  # DomainPlugin.extract() compatible
            self._prop_names = self._plugin.property_names
            self._tracker = CorrelationTracker(num_properties=self._plugin.num_properties)
        else:
            self._prop_extractor = PropertyExtractor()
            self._prop_names = PROPERTY_NAMES
            self._tracker = CorrelationTracker()
        self._rng = random.Random(seed)

        # v3 coverage components
        self._use_coverage = use_coverage
        self._cov_extractor = CoverageFeatureExtractor() if use_coverage else None

        # v4 concolic engines
        self._concolic_engine = ConcolicEngine(seed=seed) if use_coverage else None
        # v5 real concolic (source-line → AST condition → semantic negation)
        self._real_concolic = RealConcolicEngine(seed=seed) if use_coverage else None

        # Budget
        self._budget_pct = budget_pct
        self._generic_min_share = generic_min_share
        self._total_iters = 0
        self._expert_execs = 0
        self._generic_execs = 0

        # v1 dedup
        self._solved_hashes: set[str] = set()
        self._solved_hashes_max = 5000
        self._constraint_db: deque[tuple[XmlConstraint, bytes]] = deque(maxlen=500)
        self._domain_counts: dict[str, int] = {}

        # Strategy weight cache
        self._cached_strategy_weights: dict[str, float] = {}
        self._iters_since_weight_update = 0

    def on_differential_result(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
        found_finding: bool,
    ) -> list[Input]:
        """Called after each differential execution.

        Returns 0-5 targeted inputs combining expert gadgets and
        learned property perturbations.
        """
        self._total_iters += 1

        # ── ALWAYS: learning (runs regardless of budget/warmup) ──
        props = self._prop_extractor.extract(inp.data)
        divergences = self._compute_divergences(primary_result, ref_results)
        strategies = _extract_strategies(inp)

        # Coverage features (whitebox mode)
        cov_features = None
        if self._cov_extractor is not None:
            cov_features = self._cov_extractor.coverage_features(
                primary_result, ref_results,
            )

        obs = Observation(
            properties=props,
            divergences=divergences,
            strategy_names=strategies,
            found_finding=found_finding,
            timestamp=self._total_iters,
            coverage_features=cov_features,
        )
        self._tracker.record(obs)

        # Periodic strategy weight update
        self._iters_since_weight_update += 1
        if self._iters_since_weight_update >= _WEIGHT_UPDATE_INTERVAL:
            self._cached_strategy_weights = self._tracker.strategy_effectiveness()
            self._iters_since_weight_update = 0

        # ── Budget check ──
        if self._is_over_budget():
            return []

        # No divergence → nothing to target
        has_divergence = any(d.field_diffs for d in divergences)
        if not has_divergence:
            return []

        targeted: list[Input] = []

        # ── Real concolic (v5) — AST condition negation + source-line coverage ──
        if self._real_concolic is not None:
            rc_inputs = self._real_concolic.generate_targeted(
                inp, primary_result, ref_results,
            )
            targeted.extend(rc_inputs)

        # ── Concolic engine (v4) — keyword-based branch targeting (fallback) ──
        if self._concolic_engine is not None and len(targeted) < MAX_SOLUTIONS:
            concolic_inputs = self._concolic_engine.generate_targeted(
                inp, primary_result, ref_results,
            )
            targeted.extend(concolic_inputs)

        # ── Expert path (v1) — disabled in whitebox mode ──
        if self._use_expert and not self._expert_over_share():
            expert_inputs = self._run_expert(inp, primary_result, ref_results)
            targeted.extend(expert_inputs)

        # ── Generic path (v2) ──
        if self._total_iters >= _WARMUP_ITERS:
            generic_inputs = self._run_generic(inp, targeted)
            targeted.extend(generic_inputs)

        result = targeted[:MAX_SOLUTIONS]

        if result:
            expert_n = sum(1 for t in result if t.metadata.get("concolic_source") == "expert")
            generic_n = len(result) - expert_n
            logger.debug(
                "Hybrid: %d targeted (expert=%d, generic=%d, budget=%.1f%%)",
                len(result), expert_n, generic_n,
                self._budget_ratio() * 100,
            )

        return result

    def get_strategy_weights(self) -> dict[str, float]:
        """Return empirical strategy -> divergence_rate for mutator weight adjustment."""
        return self._cached_strategy_weights

    def get_stats(self) -> dict[str, Any]:
        """Return combined stats for status line and report.json."""
        tracker_stats = self._tracker.get_stats()
        stats: dict[str, Any] = {
            "concolic_execs": self._concolic_execs,
            "expert_execs": self._expert_execs,
            "generic_execs": self._generic_execs,
            "total_iters": self._total_iters,
            "budget_pct": round(self._budget_ratio() * 100, 1),
            "warmup_complete": self._total_iters >= _WARMUP_ITERS,
            "expert_share": round(
                self._expert_execs / max(self._concolic_execs, 1) * 100, 1
            ),
            "generic_share": round(
                self._generic_execs / max(self._concolic_execs, 1) * 100, 1
            ),
            "use_expert": self._use_expert,
            "use_coverage": self._use_coverage,
            "domain_counts": dict(self._domain_counts),
            **tracker_stats,
        }
        if self._use_expert and self._extractor:
            stats["constraints_extracted"] = self._extractor.stats.total_constraints
            stats["solves"] = self._solver.stats.total_solves
        if self._cov_extractor:
            stats["coverage"] = self._cov_extractor.get_stats()
        if self._concolic_engine:
            stats["concolic_engine"] = self._concolic_engine.get_stats()
        if self._real_concolic:
            stats["real_concolic"] = self._real_concolic.get_stats()
        return stats

    def get_status_line(self) -> str:
        """Short status string for the engine's periodic status output."""
        ratio = self._budget_ratio() * 100
        top = self._tracker.top_correlations(1)
        top_str = ""
        if top:
            p, f, mi = top[0]
            top_str = f" top:{p}->{f}({mi:.3f})"
        ce_str = ""
        if self._concolic_engine:
            ce = self._concolic_engine
            ce_str = f" CE:{ce._total_generated}({ce._total_new_coverage}hit)"
        rc_str = ""
        if self._real_concolic:
            rc_str = f" {self._real_concolic.get_status_line()}"
        return (
            f"hybrid:{self._concolic_execs}({ratio:.0f}%) "
            f"E:{self._expert_execs} G:{self._generic_execs}{ce_str}{rc_str} "
            f"obs:{len(self._tracker._observations)}{top_str}"
        )

    # ── Expert path (v1) ────────────────────────────────────────

    def _run_expert(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
    ) -> list[Input]:
        """Extract constraints and solve them using v1 expert system."""
        constraints = self._extractor.extract(inp, primary_result, ref_results)
        if not constraints:
            return []

        # Store constraints on input for coverage features
        inp.metadata["constraints"] = [c.to_dict() for c in constraints]

        # Track domain counts
        for c in constraints:
            self._domain_counts[c.domain] = self._domain_counts.get(c.domain, 0) + 1
            self._constraint_db.append((c, inp.data[:256]))

        # Dedup: don't re-solve identical constraint sets
        c_hash = self._hash_constraints(constraints)
        if c_hash in self._solved_hashes:
            return []
        self._solved_hashes.add(c_hash)
        if len(self._solved_hashes) > self._solved_hashes_max:
            to_keep = list(self._solved_hashes)[-self._solved_hashes_max // 2 :]
            self._solved_hashes = set(to_keep)

        # Solve
        expert_inputs = self._solver.solve(constraints, inp.data)
        for ei in expert_inputs:
            ei.metadata["concolic_source"] = "expert"
        self._expert_execs += len(expert_inputs)
        return expert_inputs

    # ── Generic path (v2) ───────────────────────────────────────

    def _run_generic(
        self,
        inp: Input,
        already_targeted: list[Input],
    ) -> list[Input]:
        """Use learned correlations to generate property-perturbing inputs."""
        remaining = MAX_SOLUTIONS - len(already_targeted)
        if remaining <= 0:
            return []

        important = self._tracker.property_importance()
        generic_inputs: list[Input] = []

        for prop_idx, mi_score in important:
            if mi_score < _MI_THRESHOLD:
                break
            if len(generic_inputs) >= remaining:
                break

            if self._plugin is not None:
                mutations = self._plugin.perturb(inp.data, prop_idx, self._rng)
            else:
                mutations = _perturb_property(inp.data, prop_idx, self._rng)
            for m in mutations[:1]:  # max 1 per property
                if m != inp.data:
                    generic_inputs.append(
                        Input(
                            data=m,
                            metadata={
                                "mutator": "concolic",
                                "concolic_source": "generic",
                                "target_property": self._prop_names[prop_idx]
                                    if prop_idx < len(self._prop_names) else f"prop_{prop_idx}",
                                "mi_score": round(mi_score, 4),
                            },
                        )
                    )

        self._generic_execs += len(generic_inputs)
        return generic_inputs

    # ── Divergence computation (domain-agnostic, from v2) ───────

    def _compute_divergences(
        self,
        primary: ExecutionResult,
        refs: list[ExecutionResult],
    ) -> list[DivergenceVector]:
        """Compare ALL JSON keys between primary and each ref."""
        p_data = self._parse_output(primary)
        if not p_data:
            return []

        result: list[DivergenceVector] = []
        for i, ref in enumerate(refs):
            r_data = self._parse_output(ref)
            if not r_data:
                continue

            all_keys = set(p_data.keys()) | set(r_data.keys())
            excluded = self._plugin.excluded_output_fields if self._plugin else _EXCLUDED_FIELDS
            all_keys -= excluded

            differing = frozenset(
                k for k in all_keys if p_data.get(k) != r_data.get(k)
            )

            if differing:
                result.append(
                    DivergenceVector(
                        pair=(0, i + 1),
                        field_diffs=differing,
                        sig_diverges="signature_valid" in differing,
                        subject_diverges="subject" in differing,
                    )
                )

        return result

    @staticmethod
    def _parse_output(result: ExecutionResult) -> dict[str, Any] | None:
        """Parse target JSON output."""
        if not result.stdout:
            return None
        try:
            return json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    # ── Budget control ──────────────────────────────────────────

    @property
    def _concolic_execs(self) -> int:
        return self._expert_execs + self._generic_execs

    def _is_over_budget(self) -> bool:
        if self._total_iters < 100:
            return False
        return self._budget_ratio() > self._budget_pct

    def _budget_ratio(self) -> float:
        if self._total_iters == 0:
            return 0.0
        return self._concolic_execs / self._total_iters

    def _expert_over_share(self) -> bool:
        """Expert exceeded its allocation? Protects generic minimum share."""
        if self._concolic_execs < 10:
            return False
        expert_share = self._expert_execs / max(self._concolic_execs, 1)
        return expert_share > (1.0 - self._generic_min_share)

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _hash_constraints(constraints: list[XmlConstraint]) -> str:
        parts = sorted(
            f"{c.domain}:{c.predicate}:{c.library_pair}" for c in constraints
        )
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _extract_strategies(inp: Input) -> list[str]:
    """Extract strategy names from input metadata."""
    if not hasattr(inp, "metadata"):
        return []
    s = inp.metadata.get("strategies") or inp.metadata.get("strategy")
    if isinstance(s, list):
        return s
    if isinstance(s, str):
        return [s]
    return []
