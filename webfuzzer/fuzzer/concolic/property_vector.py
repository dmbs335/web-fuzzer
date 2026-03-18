"""Data structures for property-learning concolic layer.

PropertyVector: fixed-size structural property measurements from input bytes.
DivergenceVector: per-library-pair output divergence summary.
Observation: one (input_properties, output_divergences) record for correlation tracking.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


NUM_PROPERTIES = 48


@dataclass(frozen=True, slots=True)
class PropertyVector:
    """Fixed-size vector of structural input properties.

    All values are numeric (float), normalized to roughly [0, 1] where
    practical.  The vector length is fixed at NUM_PROPERTIES so that
    contingency-table indices remain stable across a session.

    Memory: ~30 floats = 240 bytes per vector.
    """

    values: tuple[float, ...]

    def diff(self, other: PropertyVector) -> tuple[float, ...]:
        """Element-wise difference (self - other)."""
        return tuple(a - b for a, b in zip(self.values, other.values))

    def __len__(self) -> int:
        return len(self.values)


@dataclass(slots=True)
class DivergenceVector:
    """Per-library-pair divergence summary from one execution.

    Captures WHAT diverged (which output fields differ) without
    encoding WHY (no hardcoded heuristics).  Field names are
    discovered at runtime from JSON keys.
    """

    pair: tuple[int, int]  # (primary_idx, ref_idx)
    field_diffs: frozenset[str]  # output fields that differ
    sig_diverges: bool  # signature_valid differs
    subject_diverges: bool  # subject differs

    @property
    def severity_score(self) -> float:
        """Rough severity: sig > subject > other."""
        if self.sig_diverges and self.subject_diverges:
            return 1.0
        if self.sig_diverges:
            return 0.8
        if self.subject_diverges:
            return 0.6
        return min(len(self.field_diffs) / 10.0, 0.5)


@dataclass(slots=True)
class Observation:
    """One (input_properties, output_divergences) record.

    Stored in a fixed-size ring buffer inside CorrelationTracker.
    Memory per record: ~240B (PropertyVector) + ~200B (DivergenceVectors)
    + ~100B (strategy names) ≈ 540B.
    """

    properties: PropertyVector
    divergences: list[DivergenceVector]
    strategy_names: list[str]
    found_finding: bool
    timestamp: int  # iteration number
    coverage_features: list[float] | None = None  # from CoverageFeatureExtractor

    @property
    def has_divergence(self) -> bool:
        return any(d.field_diffs for d in self.divergences)

    @property
    def divergent_fields(self) -> frozenset[str]:
        """Union of all differing fields across all pairs."""
        result: set[str] = set()
        for d in self.divergences:
            result.update(d.field_diffs)
        return frozenset(result)
