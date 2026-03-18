"""Guidance system metrics — observable counters and health checks.

Every component emits metrics through GuidanceMetrics. The fuzzer's
status line and report.json include these, so anomalies surface
immediately rather than after a 2-hour session.

Design principle: assert-early. If the guidance system produces
nonsensical state (e.g. 0 gaps when profiles clearly have missing
checkpoints), raise immediately rather than silently producing
bad weights.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GuidanceMetrics:
    """Counters and health state for the guidance pipeline.

    Each stage of the pipeline records metrics here. The fuzzer
    reads these to report status and detect anomalies.
    """

    # ── Analysis stage ──
    libraries_requested: int = 0
    libraries_found: int = 0
    libraries_skipped: list[str] = field(default_factory=list)
    total_checkpoints_scanned: int = 0
    total_checkpoints_found: int = 0
    total_checkpoints_missing: int = 0
    total_error_swallows: int = 0
    total_conditional_bypasses: int = 0
    total_taint_paths: int = 0
    analysis_time_ms: float = 0.0

    # ── Gap construction stage ──
    gaps_identified: int = 0
    gaps_critical: int = 0
    gaps_high: int = 0
    targeted_seeds_generated: int = 0

    # ── Runtime (fuzzer feedback) ──
    findings_total: int = 0
    findings_attributed: int = 0  # matched to a gap
    findings_unattributed: int = 0  # no gap matched
    focus_rotations: int = 0
    gaps_saturated: int = 0
    plateau_events: int = 0
    weight_updates: int = 0

    # ── Errors ──
    errors: list[str] = field(default_factory=list)

    def record_error(self, msg: str) -> None:
        """Record an error. Logged immediately + stored for report."""
        logger.error("GuidanceMetrics: %s", msg)
        self.errors.append(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis": {
                "libraries_requested": self.libraries_requested,
                "libraries_found": self.libraries_found,
                "libraries_skipped": self.libraries_skipped,
                "checkpoints": {
                    "scanned": self.total_checkpoints_scanned,
                    "found": self.total_checkpoints_found,
                    "missing": self.total_checkpoints_missing,
                },
                "error_swallows": self.total_error_swallows,
                "conditional_bypasses": self.total_conditional_bypasses,
                "taint_paths": self.total_taint_paths,
                "time_ms": round(self.analysis_time_ms, 1),
            },
            "gaps": {
                "total": self.gaps_identified,
                "critical": self.gaps_critical,
                "high": self.gaps_high,
                "targeted_seeds": self.targeted_seeds_generated,
            },
            "runtime": {
                "findings_total": self.findings_total,
                "findings_attributed": self.findings_attributed,
                "findings_unattributed": self.findings_unattributed,
                "attribution_rate": (
                    round(self.findings_attributed / self.findings_total, 3)
                    if self.findings_total > 0 else 0.0
                ),
                "focus_rotations": self.focus_rotations,
                "gaps_saturated": self.gaps_saturated,
                "plateau_events": self.plateau_events,
                "weight_updates": self.weight_updates,
            },
            "errors": self.errors,
            "healthy": len(self.errors) == 0,
        }

    def status_line(self) -> str:
        """One-line summary for the fuzzer's stderr status output."""
        parts = [
            f"gaps={self.gaps_identified}({self.gaps_critical}C)",
            f"attr={self.findings_attributed}/{self.findings_total}",
        ]
        if self.gaps_saturated > 0:
            parts.append(f"sat={self.gaps_saturated}")
        if self.focus_rotations > 0:
            parts.append(f"rot={self.focus_rotations}")
        if self.errors:
            parts.append(f"ERR={len(self.errors)}")
        return " ".join(parts)

    # ── Health checks (call after each stage) ──

    def check_analysis_health(self) -> None:
        """Validate analysis stage produced sane results."""
        if self.libraries_found == 0:
            self.record_error(
                f"No libraries found out of {self.libraries_requested} requested. "
                f"Skipped: {self.libraries_skipped}"
            )
        if self.libraries_found > 0 and self.total_checkpoints_found == 0:
            self.record_error(
                "All checkpoints MISSING across all libraries — "
                "detection patterns may be broken"
            )
        if (self.total_checkpoints_scanned > 0
                and self.total_checkpoints_found == self.total_checkpoints_scanned):
            # Every single checkpoint found in every library = suspicious
            # (at least one gap should exist if we're running guidance)
            logger.warning(
                "GuidanceMetrics: all %d checkpoints found — "
                "guidance may not add value for this library set",
                self.total_checkpoints_scanned,
            )

    def check_gap_health(self) -> None:
        """Validate gap construction produced sane results."""
        if self.gaps_identified == 0 and self.total_checkpoints_missing > 0:
            self.record_error(
                f"{self.total_checkpoints_missing} checkpoints missing but "
                f"0 gaps identified — _build_gaps() logic may be broken"
            )
        if self.targeted_seeds_generated == 0 and self.gaps_identified > 0:
            logger.warning(
                "GuidanceMetrics: %d gaps but 0 targeted seeds — "
                "spec may be missing attacker_controlled fields",
                self.gaps_identified,
            )

    def check_runtime_health(self, total_iters: int) -> None:
        """Periodic runtime health check."""
        if total_iters > 50_000 and self.findings_total == 0:
            logger.warning(
                "GuidanceMetrics: 50K+ iterations with 0 findings — "
                "guidance may be misdirecting mutations"
            )
        if (self.findings_total > 20
                and self.findings_attributed == 0):
            logger.warning(
                "GuidanceMetrics: %d findings but 0 attributed to gaps — "
                "finding-to-gap matching may be broken",
                self.findings_total,
            )
