"""Unit tests for Phase 2B: heavy-tail aware apply_learned_weights.

Verifies that:
 - With alpha >= 2 (or alpha=None), normalisation uses max (existing behaviour).
 - With alpha < 2, normalisation uses median — an outlier does not collapse
   all other boosts near zero.
 - WafBypassMutator now implements LearnedWeightMutator protocol.
 - Both mutators compose correctly with prior E4/E7 startup boosts.
"""
from __future__ import annotations

import statistics

import pytest

from webfuzzer.fuzzer.protocols import LearnedWeightMutator
from webfuzzer.fuzzer.mutators.saml_mutator import SamlMutator
from webfuzzer.fuzzer.mutators.waf_bypass_mutator import WafBypassMutator, _ALL_FAMILIES


# ── SamlMutator tests ────────────────────────────────────────────────────────

def _saml() -> SamlMutator:
    return SamlMutator(seed=0)


def test_saml_implements_learned_weight_protocol():
    m = _saml()
    assert isinstance(m, LearnedWeightMutator)


def test_saml_max_norm_when_alpha_none():
    """Default (no alpha): normalise by max, higher rate → higher weight."""
    m = _saml()
    name_a = m._strategy_names[0]
    name_b = m._strategy_names[1]
    rates = {name_a: 0.8, name_b: 0.1}
    m.apply_learned_weights(rates, alpha=None)
    idx_a = 0
    idx_b = 1
    assert m._weights[idx_a] > m._weights[idx_b]


def test_saml_max_norm_when_alpha_ge_2():
    """alpha >= 2 (finite-variance regime): same max normalisation."""
    m = _saml()
    name_a = m._strategy_names[0]
    name_b = m._strategy_names[1]
    rates = {name_a: 0.8, name_b: 0.1}
    m.apply_learned_weights(rates, alpha=2.5)
    assert m._weights[0] > m._weights[1]


def test_saml_median_norm_when_alpha_lt_2():
    """alpha < 2: median normalisation — outlier does NOT crush other boosts."""
    m = _saml()
    # Simulate heavy-tail: one strategy has a 100× outlier divergence rate
    rates = {name: 0.01 for name in m._strategy_names}
    outlier_name = m._strategy_names[0]
    rates[outlier_name] = 1.0  # 100× the rest
    m.apply_learned_weights(rates, alpha=1.5)

    # With median normalisation, ref ≈ 0.01 (the typical value)
    # so all non-outlier strategies get boost ≈ 1.0 + 2.0*(0.01/0.01) = 3.0
    # Compare with max-normalisation where all non-outliers get boost ≈ 1.02
    idx_other = m._strategy_names.index(m._strategy_names[1])
    base = m._base_weights[idx_other]
    # Under median norm: other strategies should be boosted to ≥ 2× base
    assert m._weights[idx_other] >= base * 2


def test_saml_heavy_tail_outlier_still_boosted():
    """The outlier strategy itself must also be boosted (capped at 5×)."""
    m = _saml()
    rates = {name: 0.01 for name in m._strategy_names}
    rates[m._strategy_names[0]] = 1.0
    m.apply_learned_weights(rates, alpha=1.5)
    idx = 0
    assert m._weights[idx] >= m._base_weights[idx] * 2


def test_saml_empty_rates_is_noop():
    m = _saml()
    weights_before = list(m._weights)
    m.apply_learned_weights({}, alpha=1.0)
    assert m._weights == weights_before


def test_saml_all_zero_rates_is_noop():
    m = _saml()
    weights_before = list(m._weights)
    rates = {name: 0.0 for name in m._strategy_names}
    m.apply_learned_weights(rates, alpha=1.0)
    assert m._weights == weights_before


# ── WafBypassMutator tests ───────────────────────────────────────────────────

def _waf() -> WafBypassMutator:
    return WafBypassMutator(seed=0)


def test_waf_implements_learned_weight_protocol():
    m = _waf()
    assert isinstance(m, LearnedWeightMutator)


def test_waf_apply_learned_weights_boosts_known_family():
    m = _waf()
    fam = _ALL_FAMILIES[0]
    before = m._family_boosts[fam]
    m.apply_learned_weights({fam: 0.9}, alpha=None)
    assert m._family_boosts[fam] > before


def test_waf_learned_weights_never_demotes():
    """If E4 already boosted a family to 2.0, learned_weights at 0.1 must not demote."""
    m = _waf()
    fam = _ALL_FAMILIES[0]
    m._family_boosts[fam] = 2.0  # simulate prior E4 boost
    rates = {fam: 0.01}
    # ref = max = 0.01, boost = 1 + 2.0*(0.01/0.01) = 3.0 → capped = 3.0 > 2.0
    # But if rate is very low compared to others, boost might be < 2.0
    # Set up so the computed boost < prior boost
    all_rates = {f: 0.5 for f in _ALL_FAMILIES}
    all_rates[fam] = 0.01  # this family gets small rate, all others bigger
    m.apply_learned_weights(all_rates, alpha=None)
    # boost for fam = 1 + 2.0*(0.01/0.5) = 1.04 < 2.0 — must not demote
    assert m._family_boosts[fam] >= 2.0


def test_waf_median_norm_when_alpha_lt_2():
    """Heavy-tail: outlier does not suppress other families in WAF mutator."""
    m = _waf()
    rates = {fam: 0.01 for fam in _ALL_FAMILIES}
    rates[_ALL_FAMILIES[0]] = 1.0  # outlier
    m.apply_learned_weights(rates, alpha=1.5)
    # Under median norm, typical families should get substantial boost
    idx_other = 1
    fam_other = _ALL_FAMILIES[idx_other]
    assert m._family_boosts[fam_other] > 1.0


def test_waf_learned_weights_cap_at_three():
    m = _waf()
    fam = _ALL_FAMILIES[0]
    m.apply_learned_weights({fam: 1.0}, alpha=None)
    assert m._family_boosts[fam] <= 3.0


def test_waf_unknown_family_ignored():
    m = _waf()
    boosts_before = dict(m._family_boosts)
    m.apply_learned_weights({"non_existent_family": 0.9}, alpha=None)
    assert m._family_boosts == boosts_before


def test_waf_stores_learned_weights_for_auditability():
    m = _waf()
    rates = {"ct_duplicate": 0.5}
    m.apply_learned_weights(rates)
    assert m._learned_weights == rates


# ── Composition: E4/E7 startup + runtime learned weights ────────────────────

def test_waf_learned_weights_stack_on_top_of_e4():
    """Runtime learned weights compose with E4 startup boosts (monotonic max)."""
    m = _waf()
    fam = _ALL_FAMILIES[0]
    # E4 sets boost to 2.0
    m.apply_lattice_atoms({fam: (2.0 - 1.0) / 1.5})  # score to get boost=2.0
    e4_boost = m._family_boosts[fam]
    # Runtime learned weight for same family, producing boost = 1.5
    rates_weak = {fam: 0.5 / 3.0}
    # Force ref = 1.0 by providing only one non-zero entry with value matching
    m.apply_learned_weights({fam: rates_weak[fam]}, alpha=None)
    # Result must be max(e4_boost, computed_boost) — E4 not demoted
    assert m._family_boosts[fam] >= e4_boost
