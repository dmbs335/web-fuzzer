"""Fuzzer integration: connects GuidanceEngine to FuzzEngine components.

This module provides the bridge between the guidance system and the
existing fuzzer. It hooks into:

1. Analysis phase  — run before fuzzing, produce profiles
2. Seed injection  — inject targeted seeds into initial corpus
3. Mutator weights — bias field-level mutation toward gaps
4. Oracle enrichment — attribute findings to gaps, add root cause
5. Iteration feedback — plateau detection, focus rotation
6. Report — include guidance metrics in session report

All integration is optional: if guidance is None, everything
passes through unchanged.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

from webfuzzer.guidance.engine import GuidanceEngine
from webfuzzer.guidance.metrics import GuidanceMetrics
from webfuzzer.guidance.profile import GuidanceProfile
from webfuzzer.guidance.spec import ProtocolSpec
from webfuzzer.guidance.analyzers.python_analyzer import (
    PythonAnalyzer,
    JWT_PYTHON_LIBRARIES,
    SAML_PYTHON_LIBRARIES,
)

logger = logging.getLogger(__name__)


def build_guidance_engine(
    protocol: str,
    profile_dir: str | Path | None = None,
) -> GuidanceEngine | None:
    """Build a GuidanceEngine for a protocol.

    If profile_dir is given, load cached profiles from JSON files.
    Otherwise, run live analysis on installed libraries.

    Returns None if no libraries are found.
    """
    metrics = GuidanceMetrics()
    t0 = time.perf_counter()

    spec = ProtocolSpec.load_builtin(protocol)

    # Determine which libraries to analyze
    if protocol == "jwt":
        lib_targets = JWT_PYTHON_LIBRARIES
    elif protocol == "saml":
        lib_targets = SAML_PYTHON_LIBRARIES
    else:
        logger.warning("No built-in library list for protocol '%s'", protocol)
        return None

    metrics.libraries_requested = len(lib_targets)

    profiles: list[GuidanceProfile] = []

    if profile_dir:
        # Load cached profiles
        pdir = Path(profile_dir)
        if pdir.exists():
            for path in sorted(pdir.glob("*.json")):
                try:
                    p = GuidanceProfile.load(path)
                    profiles.append(p)
                    logger.info("Loaded guidance profile: %s", path.name)
                except Exception as e:
                    metrics.record_error(f"Failed to load {path}: {e}")
    else:
        # Live analysis
        analyzer = PythonAnalyzer(spec)
        for lib_target in lib_targets:
            profile = analyzer.analyze(lib_target)
            if profile is None:
                metrics.libraries_skipped.append(lib_target.name)
                continue
            profiles.append(profile)

    metrics.libraries_found = len(profiles)

    # Aggregate analysis metrics
    for p in profiles:
        found, total = p.checkpoint_score
        metrics.total_checkpoints_scanned += total
        metrics.total_checkpoints_found += found
        metrics.total_checkpoints_missing += (total - found)
        metrics.total_error_swallows += len(p.error_swallowing)
        metrics.total_conditional_bypasses += p.conditional_bypasses
        metrics.total_taint_paths += len(p.taint_paths)

    metrics.analysis_time_ms = (time.perf_counter() - t0) * 1000
    metrics.check_analysis_health()

    if not profiles:
        logger.warning("No libraries found for protocol '%s'", protocol)
        return None

    engine = GuidanceEngine(spec, profiles, metrics=metrics)

    logger.info(
        "Guidance ready: %s — %d libs, %d gaps, %d seeds, %.0fms",
        protocol,
        metrics.libraries_found,
        metrics.gaps_identified,
        metrics.targeted_seeds_generated,
        metrics.analysis_time_ms,
    )

    return engine


class GuidanceFuzzHooks:
    """Hooks that connect GuidanceEngine to FuzzEngine events.

    The FuzzEngine calls these at specific points in its loop.
    If guidance is None, all methods are no-ops.
    """

    def __init__(self, engine: GuidanceEngine | None = None):
        self.engine = engine
        self._iter_batch: int = 0
        self._BATCH_SIZE: int = 1000  # report iterations in batches

    @property
    def active(self) -> bool:
        return self.engine is not None

    # ── Called once at startup ──

    def get_targeted_seeds(self) -> list[dict[str, Any]]:
        """Get targeted seed field dicts for initial corpus injection."""
        if not self.engine:
            return []
        seeds = self.engine.generate_targeted_seeds()
        logger.info("Guidance: %d targeted seeds for injection", len(seeds))
        return seeds

    def get_initial_weights(self) -> dict[str, float]:
        """Get initial mutation weights based on gap analysis."""
        if not self.engine:
            return {}
        return self.engine.get_mutation_weights()

    # ── Called during fuzzing ──

    def on_finding(self, finding_metadata: dict[str, Any]) -> dict[str, Any]:
        """Enrich a finding with gap attribution.

        Returns the metadata dict (possibly augmented with root_cause, gap info).
        Always returns the metadata — even if no attribution found.
        """
        if not self.engine:
            return finding_metadata

        enrichment = self.engine.on_finding(finding_metadata)
        if enrichment:
            finding_metadata["guidance"] = enrichment

        return finding_metadata

    def on_iteration(self) -> None:
        """Called once per fuzzer iteration. Batches updates."""
        if not self.engine:
            return
        self._iter_batch += 1
        if self._iter_batch >= self._BATCH_SIZE:
            self.engine.on_iterations(self._iter_batch)
            self._iter_batch = 0

    def should_refresh_weights(self) -> bool:
        """True if the engine rotated focus and weights should be refreshed."""
        if not self.engine:
            return False
        m = self.engine.metrics
        return m.focus_rotations > m.weight_updates - 1

    def get_current_weights(self) -> dict[str, float]:
        """Get current mutation weights (may have changed after rotation)."""
        if not self.engine:
            return {}
        return self.engine.get_mutation_weights()

    # ── Called at end ──

    def get_report_section(self) -> dict[str, Any] | None:
        """Return guidance data for inclusion in session report.json."""
        if not self.engine:
            return None
        return self.engine.summary()

    def get_status_line(self) -> str:
        """One-line status for stderr output."""
        if not self.engine:
            return ""
        return self.engine.metrics.status_line()
