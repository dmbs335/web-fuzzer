"""GuidanceEngine: bidirectional bridge between static analysis and fuzzer.

Forward path:  analysis → mutation weights, targeted seeds, focus selection
Feedback path: fuzzer → gap hit counts, plateau detection, focus rotation

The engine maintains a priority queue of "gaps" (missing/weak checkpoints)
and rotates focus as each gap saturates.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from webfuzzer.guidance.metrics import GuidanceMetrics
from webfuzzer.guidance.profile import GuidanceProfile, BypassSeed
from webfuzzer.guidance.spec import ProtocolSpec

logger = logging.getLogger(__name__)


@dataclass
class GapInfo:
    """A known gap across one or more libraries."""

    checkpoint_name: str
    severity: str  # critical, high, medium
    taint_sources: list[str]  # attacker-controlled fields that reach this gap
    affected_libraries: list[str]  # libraries missing this checkpoint
    safe_libraries: list[str]  # libraries that have this checkpoint
    bypass_seeds: list[BypassSeed]
    hits: int = 0  # findings attributed to this gap
    saturated: bool = False  # no new findings for N iterations

    @property
    def differential_potential(self) -> float:
        """Higher when some libs have the check and others don't.

        Maximum at 50/50 split — that's where differential fuzzing
        produces the most findings.
        """
        total = len(self.affected_libraries) + len(self.safe_libraries)
        if total == 0:
            return 0.0
        ratio = len(self.affected_libraries) / total
        return 4.0 * ratio * (1.0 - ratio)  # peaks at 0.5


class GuidanceEngine:
    """Bidirectional guidance engine for static-analysis-guided fuzzing.

    Usage:
        spec = ProtocolSpec.load_builtin("jwt")
        profiles = [analyzer.analyze(lib) for lib in libraries]
        engine = GuidanceEngine(spec, profiles)

        # Forward: get mutation weights for the fuzzer
        weights = engine.get_mutation_weights()
        seeds = engine.generate_targeted_seeds()
        focus = engine.current_focus()

        # Feedback: fuzzer reports findings and progress
        engine.on_finding(finding)
        engine.on_iterations(1000)  # check for plateau
    """

    # After this many iterations without new hits on current focus,
    # rotate to the next gap
    PLATEAU_ITERS = 20_000
    # Saturate a gap after this many hits (diminishing returns)
    SATURATION_HITS = 50

    def __init__(
        self,
        spec: ProtocolSpec,
        profiles: list[GuidanceProfile],
        metrics: GuidanceMetrics | None = None,
    ):
        self.spec = spec
        self.profiles = {p.library: p for p in profiles}
        self.gaps: list[GapInfo] = []
        self._focus_idx: int = 0
        self._iters_since_hit: int = 0
        self._total_iters: int = 0
        self.metrics = metrics or GuidanceMetrics()

        self._build_gaps()

    def _build_gaps(self) -> None:
        """Cross-reference spec checkpoints against all profiles to find gaps."""
        for cp_name, checkpoint in self.spec.checkpoints.items():
            affected = []
            safe = []
            seeds: list[BypassSeed] = []

            for lib_name, profile in self.profiles.items():
                cp = profile.checkpoints.get(cp_name)
                if cp is None or not cp.present:
                    affected.append(lib_name)
                    for bs in profile.bypass_seeds:
                        if bs.gap == cp_name:
                            seeds.append(bs)
                elif cp.conditional:
                    safe.append(lib_name)
                else:
                    safe.append(lib_name)

            if affected:
                self.gaps.append(GapInfo(
                    checkpoint_name=cp_name,
                    severity=checkpoint.severity,
                    taint_sources=checkpoint.taint_sources,
                    affected_libraries=affected,
                    safe_libraries=safe,
                    bypass_seeds=seeds,
                ))

        severity_order = {"critical": 0, "high": 1, "medium": 2}
        self.gaps.sort(key=lambda g: (
            severity_order.get(g.severity, 3),
            -g.differential_potential,
        ))

        # Metrics
        self.metrics.gaps_identified = len(self.gaps)
        self.metrics.gaps_critical = sum(
            1 for g in self.gaps if g.severity == "critical"
        )
        self.metrics.gaps_high = sum(
            1 for g in self.gaps if g.severity == "high"
        )
        self.metrics.targeted_seeds_generated = sum(
            len(g.bypass_seeds) for g in self.gaps
        )
        self.metrics.check_gap_health()

        if self.gaps:
            logger.info(
                "GuidanceEngine: %d gaps (%dC/%dH) across %d libs. "
                "Top: %s (%.0f%% diff)",
                len(self.gaps),
                self.metrics.gaps_critical,
                self.metrics.gaps_high,
                len(self.profiles),
                self.gaps[0].checkpoint_name,
                self.gaps[0].differential_potential * 100,
            )

    # ── Forward: guidance → fuzzer ──

    def current_focus(self) -> GapInfo | None:
        active = [g for g in self.gaps if not g.saturated]
        if not active:
            return None
        idx = self._focus_idx % len(active)
        return active[idx]

    def get_mutation_weights(self) -> dict[str, float]:
        """Return field → weight mapping for the mutator."""
        self.metrics.weight_updates += 1
        weights: dict[str, float] = {}
        focus = self.current_focus()

        for gap in self.gaps:
            if not gap.saturated:
                for source in gap.taint_sources:
                    weights[source] = max(weights.get(source, 0), 0.3)

        if focus:
            for source in focus.taint_sources:
                weights[source] = 1.0

        return weights

    def generate_targeted_seeds(self) -> list[dict[str, Any]]:
        seeds = []
        for gap in self.gaps:
            if gap.saturated:
                continue
            for bs in gap.bypass_seeds:
                seeds.append({
                    "fields": bs.seed_fields,
                    "gap": gap.checkpoint_name,
                    "severity": gap.severity,
                    "description": bs.description,
                    "affected": gap.affected_libraries,
                })
        return seeds

    def get_library_risk_scores(self) -> dict[str, float]:
        severity_weight = {"critical": 3.0, "high": 2.0, "medium": 1.0}
        scores: dict[str, float] = defaultdict(float)
        for gap in self.gaps:
            w = severity_weight.get(gap.severity, 0.5)
            for lib in gap.affected_libraries:
                scores[lib] += w
        return dict(scores)

    # ── Feedback: fuzzer → guidance ──

    def on_finding(self, finding_metadata: dict[str, Any]) -> dict[str, Any] | None:
        self.metrics.findings_total += 1
        enrichment = self._match_finding_to_gap(finding_metadata)

        if enrichment:
            self.metrics.findings_attributed += 1
            gap_name = enrichment["gap"]
            for gap in self.gaps:
                if gap.checkpoint_name == gap_name:
                    gap.hits += 1
                    self._iters_since_hit = 0
                    if gap.hits >= self.SATURATION_HITS:
                        gap.saturated = True
                        self.metrics.gaps_saturated += 1
                        logger.info(
                            "GuidanceEngine: gap '%s' saturated (%d hits)",
                            gap_name, gap.hits,
                        )
                    break
        else:
            self.metrics.findings_unattributed += 1

        return enrichment

    def on_iterations(self, count: int) -> None:
        self._total_iters += count
        self._iters_since_hit += count

        if self._total_iters % 50_000 == 0:
            self.metrics.check_runtime_health(self._total_iters)

        if self._iters_since_hit >= self.PLATEAU_ITERS:
            focus = self.current_focus()
            if focus:
                self.metrics.plateau_events += 1
                self.metrics.focus_rotations += 1
                logger.info(
                    "GuidanceEngine: plateau on '%s' (%d hits), rotating",
                    focus.checkpoint_name, focus.hits,
                )
                self._focus_idx += 1
                self._iters_since_hit = 0

    # ── Finding attribution ──

    # Mapping from checkpoint names to finding category/strategy keywords
    # that indicate a finding is related to that checkpoint.
    _CHECKPOINT_KEYWORDS: dict[str, list[str]] = {
        # SAML checkpoints
        "nameid_extraction": [
            "nameid", "name_id", "subject_confusion", "child_element",
            "mixed_content", "truncat",
        ],
        "conditions_check": [
            "condition", "timestamp", "notbefore", "notonorafter",
            "audience", "expired",
        ],
        "replay_prevention": [
            "replay", "inresponseto", "in_response_to", "assertion_id",
        ],
        "xml_sig_verify": [
            "signature", "sig_accepted", "sig_strip", "sig_bypass",
            "signature_bypass", "hmac_confusion", "golden_saml",
        ],
        "digest_verify": [
            "digest", "digestvalue", "hash",
        ],
        "reference_uri_validation": [
            "reference_uri", "xsw", "wrapping", "reference_scope",
            "multi_assertion",
        ],
        "assertion_count_check": [
            "assertion_count", "multiple_assertion", "multi_assertion",
            "xsw",
        ],
        "c14n_algorithm_check": [
            "c14n", "canonical", "transform",
        ],
        # JWT checkpoints
        "crit_check": [
            "crit", "critical",
        ],
        "b64_check": [
            "b64", "base64", "unencoded",
        ],
        "token_type_check": [
            "typ", "token_type", "cty", "content_type",
        ],
        "alg_check": [
            "alg_none", "alg_unknown", "alg_rs_to_hs", "algorithm",
        ],
        "exp_check": [
            "exp", "expir", "timestamp",
        ],
        "kid_check": [
            "kid", "key_id",
        ],
    }

    def _match_finding_to_gap(
        self, metadata: dict[str, Any],
    ) -> dict[str, Any] | None:
        category = metadata.get("category", "").lower()
        strategy = metadata.get("strategy", "").lower()
        mechanism = metadata.get("mechanism", "").lower()
        search_text = f"{category} {strategy} {mechanism}"
        accepting = set(metadata.get("accepting_libraries", []))
        rejecting = set(metadata.get("rejecting_libraries", []))

        best_match: GapInfo | None = None
        best_score = 0.0

        def _norm(name: str) -> str:
            """Normalize lib name for fuzzy matching: python3-saml ↔ python3saml."""
            return name.lower().replace("-", "").replace("_", "")

        accepting_n = {_norm(x) for x in accepting}
        rejecting_n = {_norm(x) for x in rejecting}

        for gap in self.gaps:
            score = 0.0
            cp_name = gap.checkpoint_name

            # 1) Library overlap — strong signal (now available from engine)
            affected_n = {_norm(x) for x in gap.affected_libraries}
            safe_n = {_norm(x) for x in gap.safe_libraries}

            if accepting_n and affected_n:
                score += len(accepting_n & affected_n) * 3.0
            if rejecting_n and safe_n:
                score += len(rejecting_n & safe_n) * 2.0

            # 2) Keyword matching — use explicit keyword list if available
            keywords = self._CHECKPOINT_KEYWORDS.get(cp_name, [])
            if not keywords:
                keywords = cp_name.replace("_", " ").split()
            for kw in keywords:
                if kw in search_text:
                    score += 1.0
                    break  # one keyword match is enough

            if score > best_score:
                best_score = score
                best_match = gap

        # Library match alone (score >= 3.0) is sufficient for attribution.
        # Keyword-only match (score = 1.0) is NOT sufficient — too noisy.
        if best_match and best_score >= 3.0:
            return {
                "gap": best_match.checkpoint_name,
                "gap_severity": best_match.severity,
                "root_cause": (
                    f"Missing '{best_match.checkpoint_name}' "
                    f"in {best_match.affected_libraries}"
                ),
                "affected_libraries": best_match.affected_libraries,
                "safe_libraries": best_match.safe_libraries,
            }
        return None

    # ── Summary ──

    def summary(self) -> dict[str, Any]:
        return {
            "protocol": self.spec.protocol,
            "libraries_analyzed": len(self.profiles),
            "total_gaps": len(self.gaps),
            "active_gaps": sum(1 for g in self.gaps if not g.saturated),
            "saturated_gaps": sum(1 for g in self.gaps if g.saturated),
            "total_hits": sum(g.hits for g in self.gaps),
            "current_focus": (
                self.current_focus().checkpoint_name
                if self.current_focus()
                else None
            ),
            "gaps": [
                {
                    "checkpoint": g.checkpoint_name,
                    "severity": g.severity,
                    "affected": g.affected_libraries,
                    "safe": g.safe_libraries,
                    "differential_potential": round(g.differential_potential, 2),
                    "hits": g.hits,
                    "saturated": g.saturated,
                }
                for g in self.gaps
            ],
            "metrics": self.metrics.to_dict(),
        }
