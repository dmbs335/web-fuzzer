"""Tests for SamlMutator.apply_lattice_atoms — E4 FCA atom-coverage boost."""

from __future__ import annotations

from webfuzzer.fuzzer.mutators.saml_mutator import SamlMutator
from webfuzzer.fuzzer.protocols import LatticeAtomMutator


def test_saml_mutator_implements_lattice_atom_protocol():
    m = SamlMutator(seed=0)
    assert isinstance(m, LatticeAtomMutator)


def test_apply_lattice_atoms_empty_is_noop():
    m = SamlMutator(seed=0)
    before = list(m._weights)
    m.apply_lattice_atoms({})
    assert m._weights == before
    assert m._lattice_atom_weights is None


def test_apply_lattice_atoms_unknown_strategy_is_ignored():
    m = SamlMutator(seed=0)
    before = list(m._weights)
    m.apply_lattice_atoms({"not_a_real_strategy": 0.9})
    assert m._weights == before
    # But the dict is still stored for auditability.
    assert m._lattice_atom_weights == {"not_a_real_strategy": 0.9}


def test_apply_lattice_atoms_boosts_known_strategy():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    m.apply_lattice_atoms({name: 1.0})
    # score=1.0 → boost = 1 + 1.5·1 = 2.5x base.
    expected = min(int(round(base * 2.5)), base * 3)
    assert m._weights[0] == expected
    # Base weights are untouched.
    assert m._base_weights[0] == base


def test_apply_lattice_atoms_never_demotes():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    # Pre-boost via the learned-weights channel.
    m._weights[0] = base * 4
    # A weaker lattice-atom boost (which would compute to only 2.5× base)
    # should not pull the weight back down.
    m.apply_lattice_atoms({name: 1.0})
    assert m._weights[0] == base * 4  # untouched


def test_apply_lattice_atoms_saturates_at_score_one():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    # Scores > 1.0 are clamped to 1.0 → 2.5× base (same as score=1.0).
    m.apply_lattice_atoms({name: 100.0})
    saturated = m._weights[0]

    m2 = SamlMutator(seed=0)
    m2.apply_lattice_atoms({name: 1.0})
    assert m2._weights[0] == saturated
    # And that number is exactly round(base · 2.5), bounded by 3× base.
    expected = min(int(round(base * 2.5)), base * 3)
    assert saturated == expected


def test_apply_lattice_atoms_negative_or_zero_is_noop():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    m.apply_lattice_atoms({name: 0.0})
    assert m._weights[0] == base
    m.apply_lattice_atoms({name: -0.5})
    assert m._weights[0] == base


def test_apply_lattice_atoms_composes_with_learned_weights():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]

    # Learned-weights channel first (applied from base).
    m.apply_learned_weights({name: 1.0})
    after_learned = m._weights[0]
    assert after_learned >= base  # learned path boosted it

    # Lattice-atom channel adds on top but never demotes.
    m.apply_lattice_atoms({name: 1.0})
    assert m._weights[0] >= after_learned
