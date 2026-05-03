"""Tests for SamlMutator.apply_automaton_witnesses — E7 witness boost."""

from __future__ import annotations

from webfuzzer.fuzzer.mutators.saml_mutator import SamlMutator
from webfuzzer.fuzzer.protocols import AutomatonWitnessMutator


def test_saml_mutator_implements_automaton_witness_protocol():
    m = SamlMutator(seed=0)
    assert isinstance(m, AutomatonWitnessMutator)


def test_apply_automaton_witnesses_empty_is_noop():
    m = SamlMutator(seed=0)
    before = list(m._weights)
    m.apply_automaton_witnesses({})
    assert m._weights == before
    assert m._automaton_witness_weights is None


def test_apply_automaton_witnesses_unknown_strategy_is_ignored():
    m = SamlMutator(seed=0)
    before = list(m._weights)
    m.apply_automaton_witnesses({"not_a_real_strategy": 0.9})
    assert m._weights == before
    # Stored for auditability.
    assert m._automaton_witness_weights == {"not_a_real_strategy": 0.9}


def test_apply_automaton_witnesses_boosts_known_strategy():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    m.apply_automaton_witnesses({name: 1.0})
    expected = min(int(round(base * 2.5)), base * 3)
    assert m._weights[0] == expected
    assert m._base_weights[0] == base


def test_apply_automaton_witnesses_never_demotes():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    m._weights[0] = base * 4
    m.apply_automaton_witnesses({name: 1.0})
    assert m._weights[0] == base * 4


def test_apply_automaton_witnesses_saturates_at_score_one():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    m.apply_automaton_witnesses({name: 100.0})
    saturated = m._weights[0]
    m2 = SamlMutator(seed=0)
    m2.apply_automaton_witnesses({name: 1.0})
    assert m2._weights[0] == saturated
    expected = min(int(round(base * 2.5)), base * 3)
    assert saturated == expected


def test_apply_automaton_witnesses_negative_or_zero_is_noop():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]
    m.apply_automaton_witnesses({name: 0.0})
    assert m._weights[0] == base
    m.apply_automaton_witnesses({name: -0.5})
    assert m._weights[0] == base


def test_apply_automaton_witnesses_composes_with_lattice_atoms():
    m = SamlMutator(seed=0)
    name = m._strategy_names[0]
    base = m._base_weights[0]

    m.apply_lattice_atoms({name: 1.0})
    after_lattice = m._weights[0]
    assert after_lattice >= base

    m.apply_automaton_witnesses({name: 1.0})
    # Same boost formula — should not demote, may stay flat.
    assert m._weights[0] >= after_lattice
