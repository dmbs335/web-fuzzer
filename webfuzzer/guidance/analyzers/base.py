"""Base analyzer interface.

All language-specific analyzers inherit from this and implement analyze().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from webfuzzer.guidance.profile import GuidanceProfile
from webfuzzer.guidance.spec import ProtocolSpec


@dataclass
class LibraryTarget:
    """Identifies a library to analyze."""

    name: str  # e.g. "pyjwt", "python-jose"
    language: str  # "python", "java", "node", "go"
    source_paths: list[str]  # files to analyze (relative to package root)
    package_root: str = ""  # resolved at runtime
    version: str = ""
    # entry points for call graph tracing
    entry_points: list[str] | None = None


class BaseAnalyzer(ABC):
    """Abstract base for language-specific analyzers.

    Subclasses implement:
    - _resolve_library(): locate the library on disk
    - _detect_checkpoints(): find security checkpoints in source
    - _detect_error_swallowing(): find error-swallowing patterns
    - _detect_conditional_bypasses(): find option-guarded checks
    - _extract_taint_paths(): trace attacker-controlled field influence
    - _generate_bypass_seeds(): create targeted seeds for gaps
    """

    def __init__(self, spec: ProtocolSpec):
        self.spec = spec

    def analyze(self, target: LibraryTarget) -> GuidanceProfile | None:
        """Run full analysis on a library. Returns None if library not found."""
        if not self._resolve_library(target):
            return None

        profile = GuidanceProfile(
            protocol=self.spec.protocol,
            library=target.name,
            version=target.version,
            language=target.language,
        )

        # Phase 1: checkpoint detection
        profile.checkpoints = self._detect_checkpoints(target)

        # Phase 1b: error swallowing
        profile.error_swallowing = self._detect_error_swallowing(target)

        # Phase 1c: conditional bypasses
        bypasses = self._detect_conditional_bypasses(target)
        profile.conditional_bypasses = len(bypasses)

        # Mark checkpoints as conditional if they have bypasses
        for bypass_info in bypasses:
            cp_name = bypass_info.get("checkpoint")
            if cp_name and cp_name in profile.checkpoints:
                cp = profile.checkpoints[cp_name]
                cp.conditional = True
                cp.condition = bypass_info.get("condition", "")

        # Phase 2: taint paths (optional — subclass may not implement)
        profile.taint_paths = self._extract_taint_paths(target)

        # Phase 3: bypass seed generation from gaps
        profile.bypass_seeds = self._generate_bypass_seeds(target, profile)

        return profile

    @abstractmethod
    def _resolve_library(self, target: LibraryTarget) -> bool:
        """Locate the library on disk. Populate target.package_root and version.
        Return True if found."""
        ...

    @abstractmethod
    def _detect_checkpoints(self, target: LibraryTarget) -> dict:
        """Detect which security checkpoints exist in the source."""
        ...

    @abstractmethod
    def _detect_error_swallowing(self, target: LibraryTarget) -> list:
        """Find error-swallowing patterns."""
        ...

    @abstractmethod
    def _detect_conditional_bypasses(self, target: LibraryTarget) -> list[dict]:
        """Find option-guarded security checks.
        Return list of {"checkpoint": name, "condition": str, "location": str}.
        """
        ...

    def _extract_taint_paths(self, target: LibraryTarget) -> list:
        """Extract taint paths from attacker-controlled fields.
        Default: empty (Phase 2 feature).
        """
        return []

    def _generate_bypass_seeds(
        self, target: LibraryTarget, profile: GuidanceProfile,
    ) -> list:
        """Generate bypass seeds based on detected gaps.
        Default: use spec's attacker_controlled mutations.
        """
        from webfuzzer.guidance.profile import BypassSeed

        seeds = []
        for cp_name in profile.missing_checkpoints:
            checkpoint = self.spec.checkpoints.get(cp_name)
            if not checkpoint:
                continue
            # Find attacker fields that influence this checkpoint
            for taint_source in checkpoint.taint_sources:
                for af in self.spec.attacker_controlled:
                    if af.field == taint_source:
                        for mutation in af.mutations:
                            seeds.append(BypassSeed(
                                gap=cp_name,
                                description=(
                                    f"{cp_name} missing in {target.name}: "
                                    f"set {af.field}={mutation}"
                                ),
                                seed_fields={af.field: mutation},
                            ))
        return seeds
