"""Evidence-routed policy helpers for fuzzer heuristics.

This module is the implementation-side counterpart of
``FiniteHeuristicPolicy.lean``.  Constants can still be empirical, but the
policy shape is explicit:

* preserve only when a preservation witness exists;
* shadow only when replayable diversity exists;
* skip only when a short-campaign resource-risk witness exists;
* cap without increasing priority;
* boost without exceeding a configured cap.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class SelectionBranch(str, Enum):
    """Operational branches for selection-drop remediation."""

    MONITOR = "monitor_only"
    REVIEW_FALLBACK = "review_fallback_signature"
    SHADOW_REVIEW = "shadow_queue_review"
    FINE_PRESERVE = "fine_preserve_bucket"


@dataclass(frozen=True)
class SelectionEvidence:
    """Finite witness bundle used by selection-drop routing."""

    drop_reason: str
    fingerprint_mode: str
    unique_fine_fingerprints: int
    strategy_count: int
    oracle_count: int
    orbit_count: int
    session_count: int = 0
    witness_families: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_values(
        cls,
        *,
        drop_reason: str,
        fingerprint_mode: str,
        unique_fine_fingerprints: int,
        strategy_count: int,
        oracle_count: int,
        orbit_count: int,
        session_count: int = 0,
        witness_families: Iterable[str] | None = None,
    ) -> "SelectionEvidence":
        normalized = frozenset(
            str(family) for family in (witness_families or ()) if str(family)
        )
        return cls(
            drop_reason=drop_reason,
            fingerprint_mode=fingerprint_mode,
            unique_fine_fingerprints=max(0, int(unique_fine_fingerprints)),
            strategy_count=max(0, int(strategy_count)),
            oracle_count=max(0, int(oracle_count)),
            orbit_count=max(0, int(orbit_count)),
            session_count=max(0, int(session_count)),
            witness_families=normalized,
        )

    @property
    def has_block_status_family(self) -> bool:
        return any("block_status" in family for family in self.witness_families)

    @property
    def has_pure_block_status_family(self) -> bool:
        return any(
            "block_status" in family and "timing" not in family
            for family in self.witness_families
        )

    @property
    def has_timing_mixed_block_status_family(self) -> bool:
        return any(
            "block_status" in family and "timing" in family
            for family in self.witness_families
        )

    @property
    def has_pure_body_headers_family(self) -> bool:
        return bool(self.witness_families) and all(
            family == "body_headers" for family in self.witness_families
        )

    @property
    def has_pure_timing_family(self) -> bool:
        return bool(self.witness_families) and all(
            family == "timing" for family in self.witness_families
        )

    @property
    def has_multiple_fine_variants(self) -> bool:
        return self.unique_fine_fingerprints > 1

    @property
    def has_multi_context(self) -> bool:
        return (
            self.strategy_count > 1
            or self.oracle_count > 1
            or self.orbit_count > 1
            or self.session_count > 1
        )

    @property
    def has_preservation_witness(self) -> bool:
        return (
            self.has_pure_block_status_family
            or self.has_multiple_fine_variants
            or self.drop_reason == "duplicate_coarse_bv"
        )

    @property
    def has_shadow_witness(self) -> bool:
        return self.has_multiple_fine_variants and self.has_multi_context

    def to_metadata(self) -> dict[str, object]:
        """Serialize the evidence bundle into stable report metadata."""
        return {
            "drop_reason": self.drop_reason,
            "fingerprint_mode": self.fingerprint_mode,
            "unique_fine_fingerprints": self.unique_fine_fingerprints,
            "strategy_count": self.strategy_count,
            "oracle_count": self.oracle_count,
            "orbit_count": self.orbit_count,
            "session_count": self.session_count,
            "witness_families": sorted(self.witness_families),
            "has_preservation_witness": self.has_preservation_witness,
            "has_shadow_witness": self.has_shadow_witness,
        }


def choose_selection_branch(evidence: SelectionEvidence) -> SelectionBranch:
    """Choose a branch under the verified evidence-routed policy shape."""
    if evidence.fingerprint_mode == "fallback_error_skeleton":
        return SelectionBranch.REVIEW_FALLBACK
    if (
        evidence.fingerprint_mode == "diff_pattern_hash"
        and evidence.has_pure_block_status_family
    ):
        return SelectionBranch.FINE_PRESERVE
    if (
        evidence.fingerprint_mode == "diff_pattern_hash"
        and evidence.has_timing_mixed_block_status_family
    ):
        if evidence.has_multiple_fine_variants:
            return SelectionBranch.FINE_PRESERVE
        if evidence.has_block_status_family:
            return SelectionBranch.MONITOR
    if (
        evidence.fingerprint_mode == "diff_pattern_hash"
        and evidence.has_pure_body_headers_family
    ):
        if evidence.has_multiple_fine_variants:
            return SelectionBranch.FINE_PRESERVE
        return SelectionBranch.MONITOR
    if (
        evidence.fingerprint_mode == "diff_pattern_hash"
        and evidence.has_pure_timing_family
    ):
        if evidence.has_shadow_witness:
            return SelectionBranch.SHADOW_REVIEW
        return SelectionBranch.MONITOR
    if evidence.has_shadow_witness:
        return SelectionBranch.SHADOW_REVIEW
    if evidence.has_multiple_fine_variants:
        return SelectionBranch.FINE_PRESERVE
    if evidence.drop_reason == "duplicate_coarse_bv":
        return SelectionBranch.FINE_PRESERVE
    return SelectionBranch.MONITOR


def selection_branch_contract(
    branch: SelectionBranch,
    evidence: SelectionEvidence,
) -> bool:
    """Return whether a chosen branch satisfies its evidence obligation."""
    if branch == SelectionBranch.FINE_PRESERVE:
        return evidence.has_preservation_witness
    if branch == SelectionBranch.SHADOW_REVIEW:
        return evidence.has_shadow_witness
    return True


SHORT_WAF_CAMPAIGN_MAX_SECONDS = 30.0
SHORT_WAF_SKIP_MIN_BYTES = 580
SHORT_WAF_CAP_TIERS: tuple[tuple[int, float], ...] = (
    (700, 0.10),
    (640, 0.20),
    (560, 0.40),
)


@dataclass(frozen=True)
class ShortWafEvidence:
    """Evidence bundle for short WAF campaign resource policies."""

    mutator_name: str
    max_time_seconds: float
    wire_length: int
    waf_marked: bool
    timeout_prone_shape: bool

    @classmethod
    def from_input(
        cls,
        *,
        input_data: bytes,
        mutator_name: str,
        max_time_seconds: float,
    ) -> "ShortWafEvidence":
        data = input_data or b""
        lower = data.lower()
        has_chunked_te = b"transfer-encoding" in lower and b"chunked" in lower
        timeout_prone_shape = (
            b"multipart/form-data" in lower
            or has_chunked_te
            or b"expect: 100-continue" in lower
        )
        return cls(
            mutator_name=mutator_name,
            max_time_seconds=max_time_seconds,
            wire_length=len(data),
            waf_marked=b"X-WF-" in data,
            timeout_prone_shape=timeout_prone_shape,
        )

    @property
    def short_campaign(self) -> bool:
        return (
            self.mutator_name == "waf_bypass"
            and self.max_time_seconds > 0
            and self.max_time_seconds <= SHORT_WAF_CAMPAIGN_MAX_SECONDS
        )

    @property
    def large_wire(self) -> bool:
        return self.wire_length >= SHORT_WAF_SKIP_MIN_BYTES

    @property
    def skip_witness(self) -> bool:
        return (
            self.short_campaign
            and self.waf_marked
            and self.large_wire
            and self.timeout_prone_shape
        )

    def to_metadata(self) -> dict[str, object]:
        """Serialize the resource-policy evidence for diagnostics."""
        return {
            "mutator_name": self.mutator_name,
            "max_time_seconds": self.max_time_seconds,
            "wire_length": self.wire_length,
            "short_campaign": self.short_campaign,
            "waf_marked": self.waf_marked,
            "large_wire": self.large_wire,
            "timeout_prone_shape": self.timeout_prone_shape,
            "skip_witness": self.skip_witness,
        }


def should_skip_short_waf_execution(
    *,
    input_data: bytes,
    mutator_name: str,
    max_time_seconds: float,
) -> bool:
    """Return whether the short-WAF resource guard may skip this input."""
    evidence = ShortWafEvidence.from_input(
        input_data=input_data,
        mutator_name=mutator_name,
        max_time_seconds=max_time_seconds,
    )
    return evidence.skip_witness


def short_waf_priority_cap(
    *,
    input_data: bytes,
    mutator_name: str,
    max_time_seconds: float,
) -> float | None:
    """Return a priority cap for large WAF inputs in short campaigns."""
    evidence = ShortWafEvidence.from_input(
        input_data=input_data,
        mutator_name=mutator_name,
        max_time_seconds=max_time_seconds,
    )
    if not evidence.short_campaign or not evidence.waf_marked:
        return None
    for min_bytes, cap in SHORT_WAF_CAP_TIERS:
        if evidence.wire_length >= min_bytes:
            return cap
    return None


def cap_priority(current: float, cap: float) -> float:
    """Apply a non-increasing priority cap."""
    return min(current, cap)


def bounded_boost(current: float, suggested: float, cap: float) -> float:
    """Apply a monotone boost that cannot exceed ``cap``."""
    return min(max(current, suggested), cap)
