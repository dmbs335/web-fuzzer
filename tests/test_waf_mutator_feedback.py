"""Tests for WafBypassMutator E4/E7 feedback hooks.

Mirrors tests/test_saml_mutator_lattice_atoms.py and
tests/test_saml_mutator_automaton_witnesses.py: WafBypassMutator boosts
families (not flat strategy weights), but the boost formula and
"never demote" semantics match the SAML reference contract.
"""

from __future__ import annotations

from webfuzzer.fuzzer.mutators.waf_bypass_mutator import (
    _ALL_FAMILIES,
    WafBypassMutator,
)
from webfuzzer.fuzzer.protocols import (
    AutomatonWitnessMutator,
    LatticeAtomMutator,
)


def _first_family() -> str:
    # Pick a stable, well-known family that exists in _ALL_FAMILIES.
    assert "ct_duplicate" in _ALL_FAMILIES
    return "ct_duplicate"


# ── Protocol membership ────────────────────────────────────────────


def test_waf_mutator_implements_lattice_atom_protocol():
    m = WafBypassMutator(seed=0)
    assert isinstance(m, LatticeAtomMutator)


def test_waf_mutator_implements_automaton_witness_protocol():
    m = WafBypassMutator(seed=0)
    assert isinstance(m, AutomatonWitnessMutator)


# ── apply_lattice_atoms ─────────────────────────────────────────────


def test_apply_lattice_atoms_empty_is_noop():
    m = WafBypassMutator(seed=0)
    before = dict(m._family_boosts)
    m.apply_lattice_atoms({})
    assert m._family_boosts == before
    assert m._lattice_atom_weights is None


def test_apply_lattice_atoms_unknown_strategy_is_ignored_but_stored():
    m = WafBypassMutator(seed=0)
    before = dict(m._family_boosts)
    m.apply_lattice_atoms({"not_a_real_family": 0.9})
    assert m._family_boosts == before
    # Auditability: caller's dict is retained verbatim, including unknowns.
    assert m._lattice_atom_weights == {"not_a_real_family": 0.9}


def test_apply_lattice_atoms_boosts_known_family():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    assert m._family_boosts[fam] == 1.0
    m.apply_lattice_atoms({fam: 1.0})
    # boost = 1 + 1.5 · 1 = 2.5, capped at 3.0.
    assert m._family_boosts[fam] == 2.5


def test_apply_lattice_atoms_never_demotes():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    # Pre-boost via direct assignment (simulating an earlier channel).
    m._family_boosts[fam] = 2.9
    m.apply_lattice_atoms({fam: 1.0})  # would compute to 2.5
    assert m._family_boosts[fam] == 2.9  # untouched


def test_apply_lattice_atoms_saturates_at_score_one():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    m.apply_lattice_atoms({fam: 100.0})
    assert m._family_boosts[fam] == 2.5  # clamped to score=1.0


def test_apply_lattice_atoms_negative_or_zero_is_noop():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    m.apply_lattice_atoms({fam: 0.0})
    assert m._family_boosts[fam] == 1.0
    m.apply_lattice_atoms({fam: -0.5})
    assert m._family_boosts[fam] == 1.0


def test_apply_lattice_atoms_caps_at_three():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    # The formula 1 + 1.5·s never exceeds 2.5, but the cap is part
    # of the contract — assert directly.
    m._family_boosts[fam] = 1.0
    m.apply_lattice_atoms({fam: 0.5})
    assert m._family_boosts[fam] == 1.0 + 1.5 * 0.5  # 1.75


# ── apply_automaton_witnesses ───────────────────────────────────────


def test_apply_automaton_witnesses_empty_is_noop():
    m = WafBypassMutator(seed=0)
    before = dict(m._family_boosts)
    m.apply_automaton_witnesses({})
    assert m._family_boosts == before
    assert m._automaton_witness_weights is None


def test_apply_automaton_witnesses_unknown_strategy_ignored_but_stored():
    m = WafBypassMutator(seed=0)
    before = dict(m._family_boosts)
    m.apply_automaton_witnesses({"not_a_real_family": 0.9})
    assert m._family_boosts == before
    assert m._automaton_witness_weights == {"not_a_real_family": 0.9}


def test_apply_automaton_witnesses_boosts_known_family():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    m.apply_automaton_witnesses({fam: 1.0})
    assert m._family_boosts[fam] == 2.5


def test_apply_automaton_witnesses_never_demotes():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    m._family_boosts[fam] = 2.9
    m.apply_automaton_witnesses({fam: 1.0})
    assert m._family_boosts[fam] == 2.9


def test_apply_automaton_witnesses_composes_with_lattice_atoms():
    m = WafBypassMutator(seed=0)
    fam = _first_family()

    m.apply_lattice_atoms({fam: 1.0})
    after_lattice = m._family_boosts[fam]
    assert after_lattice == 2.5

    # Same boost formula → should not demote, may stay flat.
    m.apply_automaton_witnesses({fam: 1.0})
    assert m._family_boosts[fam] >= after_lattice


def test_apply_automaton_witnesses_stronger_than_lattice_takes_over():
    m = WafBypassMutator(seed=0)
    fam = _first_family()
    m.apply_lattice_atoms({fam: 0.2})  # boost → 1.3
    assert m._family_boosts[fam] == 1.3
    m.apply_automaton_witnesses({fam: 1.0})  # boost → 2.5
    assert m._family_boosts[fam] == 2.5


# ── End-to-end mutate() under boost ─────────────────────────────────


def test_mutate_still_runs_after_apply_lattice_atoms():
    """A boosted mutator must still produce valid Input objects."""
    from webfuzzer.fuzzer.protocols import Input

    m = WafBypassMutator(seed=42)
    m.apply_lattice_atoms({"ct_duplicate": 1.0, "enc_chunked_hide": 0.8})
    inp = Input(data=b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    out = m.mutate(inp, [])
    assert isinstance(out, Input)
    assert len(out.data) > 0


def test_default_family_boosts_are_all_one():
    """Without any apply_* call, every family must remain at neutral 1.0."""
    m = WafBypassMutator(seed=0)
    assert all(v == 1.0 for v in m._family_boosts.values())
    assert set(m._family_boosts.keys()) == set(_ALL_FAMILIES)
