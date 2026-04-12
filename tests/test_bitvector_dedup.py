"""Unit tests for Phase 2A: Birkhoff bitvector dedup key.

Tests the StructuralDeduplicator.set_atoms() path introduced in Phase 2A.
Without an atoms list, behaviour must be byte-identical to the pre-Phase-2
implementation.  With atoms loaded, two findings that touch the same atom
subset must receive the same fingerprint.
"""
from __future__ import annotations

import hashlib

import pytest

from webfuzzer.fuzzer.dedup.structural_dedup import StructuralDeduplicator
from webfuzzer.fuzzer.protocols import Finding, Input, ExecutionResult, Severity


def _finding(
    oracle_name: str = "diff",
    severity: Severity = Severity.MEDIUM,
    diff_pattern_hash: str = "abc123",
    diff_fields: list[str] | None = None,
    strategy: str = "strat_a",
) -> Finding:
    meta: dict = {"diff_pattern_hash": diff_pattern_hash}
    if diff_fields is not None:
        meta["diff_fields"] = diff_fields
    return Finding(
        title="test",
        severity=severity,
        oracle_name=oracle_name,
        input=Input(data=b"test"),
        result=ExecutionResult(),
        metadata=meta,
    )


# ── Backward-compatibility tests (no atoms loaded) ──────────────────────────

def test_no_atoms_uses_diff_pattern_hash():
    """Without set_atoms, fingerprint is based on diff_pattern_hash."""
    dedup = StructuralDeduplicator()
    f1 = _finding(diff_pattern_hash="hash_x", diff_fields=["a", "b"])
    f2 = _finding(diff_pattern_hash="hash_x", diff_fields=["a", "b"])
    assert dedup.fingerprint(f1) == dedup.fingerprint(f2)


def test_no_atoms_different_hash_is_different():
    dedup = StructuralDeduplicator()
    f1 = _finding(diff_pattern_hash="hash_x")
    f2 = _finding(diff_pattern_hash="hash_y")
    assert dedup.fingerprint(f1) != dedup.fingerprint(f2)


def test_no_atoms_diff_fields_ignored_for_fingerprint():
    """Without atoms, two findings with same hash but different diff_fields
    still match (diff_pattern_hash is what matters)."""
    dedup = StructuralDeduplicator()
    f1 = _finding(diff_pattern_hash="same_hash", diff_fields=["a"])
    f2 = _finding(diff_pattern_hash="same_hash", diff_fields=["b"])
    assert dedup.fingerprint(f1) == dedup.fingerprint(f2)


# ── Bitvector path tests (atoms loaded) ─────────────────────────────────────

def test_same_atom_subset_same_fingerprint():
    """Two findings with identical atom-intersecting diff_fields collapse."""
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["duration_ms", "response_headers", "waf_blocked"])
    f1 = _finding(
        diff_pattern_hash="hash_strat_a",
        diff_fields=["duration_ms", "response_headers"],
        strategy="strat_a",
    )
    f2 = _finding(
        diff_pattern_hash="hash_strat_b",
        diff_fields=["duration_ms", "response_headers"],
        strategy="strat_b",
    )
    # Different oracle-level hashes, same bitvector → same dedup fingerprint
    assert dedup.fingerprint(f1) == dedup.fingerprint(f2)


def test_different_atom_subset_different_fingerprint():
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["duration_ms", "response_headers", "waf_blocked"])
    f1 = _finding(diff_fields=["duration_ms"])
    f2 = _finding(diff_fields=["waf_blocked"])
    assert dedup.fingerprint(f1) != dedup.fingerprint(f2)


def test_superset_of_atoms_different_from_subset():
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["duration_ms", "response_headers", "waf_blocked"])
    f1 = _finding(diff_fields=["duration_ms", "response_headers"])
    f2 = _finding(diff_fields=["duration_ms", "response_headers", "waf_blocked"])
    assert dedup.fingerprint(f1) != dedup.fingerprint(f2)


def test_unknown_diff_fields_ignored_in_bitvector():
    """Fields not in the atom set are silently dropped from the bitvector."""
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["duration_ms"])
    f1 = _finding(diff_fields=["duration_ms", "not_an_atom"])
    f2 = _finding(diff_fields=["duration_ms"])
    # "not_an_atom" is not in atoms → both map to bitvector ("duration_ms",)
    assert dedup.fingerprint(f1) == dedup.fingerprint(f2)


def test_empty_atom_intersection_falls_back_to_diff_pattern_hash():
    """When diff_fields ∩ atoms = ∅, fall back to original hash path."""
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["atom_x", "atom_y"])
    # diff_fields has no overlap with atoms
    f1 = _finding(diff_pattern_hash="unique_hash_1", diff_fields=["unrelated_field"])
    f2 = _finding(diff_pattern_hash="unique_hash_2", diff_fields=["another_field"])
    # Different diff_pattern_hashes → different fingerprints
    assert dedup.fingerprint(f1) != dedup.fingerprint(f2)


def test_no_diff_fields_falls_back_to_diff_pattern_hash():
    """Findings with no diff_fields use the original hash path even when atoms loaded."""
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["atom_x"])
    f1 = _finding(diff_pattern_hash="hash_a", diff_fields=None)
    f2 = _finding(diff_pattern_hash="hash_a", diff_fields=None)
    assert dedup.fingerprint(f1) == dedup.fingerprint(f2)


def test_set_atoms_overwrites_previous():
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["a", "b"])
    dedup.set_atoms(["x", "y"])
    # After overwrite, old atoms "a" and "b" are not in the atom set
    f = _finding(diff_fields=["a", "b"])
    # Falls back to diff_pattern_hash path (no atom intersection with {"x","y"})
    f2 = _finding(diff_pattern_hash=f.metadata["diff_pattern_hash"], diff_fields=[])
    # Both should use same diff_pattern_hash path and produce same fingerprint
    assert dedup.fingerprint(f) == dedup.fingerprint(f2)


# ── Dedup workflow tests ─────────────────────────────────────────────────────

def test_bitvector_dedup_collapses_duplicate():
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["duration_ms", "waf_blocked"])
    f1 = _finding(diff_pattern_hash="hash_a", diff_fields=["duration_ms", "waf_blocked"])
    f2 = _finding(diff_pattern_hash="hash_b", diff_fields=["duration_ms", "waf_blocked"])

    f1.fingerprint = dedup.fingerprint(f1)
    assert not dedup.is_duplicate(f1)
    dedup.register(f1)

    f2.fingerprint = dedup.fingerprint(f2)
    assert dedup.is_duplicate(f2)  # same bitvector → collapsed


def test_bitvector_dedup_allows_distinct_buckets():
    dedup = StructuralDeduplicator()
    dedup.set_atoms(["duration_ms", "waf_blocked"])
    f1 = _finding(diff_fields=["duration_ms"])
    f2 = _finding(diff_fields=["waf_blocked"])

    f1.fingerprint = dedup.fingerprint(f1)
    dedup.register(f1)
    f2.fingerprint = dedup.fingerprint(f2)
    assert not dedup.is_duplicate(f2)
