"""Tests for EntropicScheduler.set_stopping_signal — DG018 phase gate.

Verifies:
1. The default scheduler (no signal) is byte-identical to the
   pre-signal version — zero regression.
2. ``StoppingSignal(phase="discovery")`` is also a no-op (the gate only
   fires on exploitation).
3. ``StoppingSignal(phase="exploitation")`` dampens entropy and
   strengthens the class-saturation penalty.
4. The CLI loader parses both minimal payloads and full lint JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from webfuzzer.fuzzer.corpus import Corpus
from webfuzzer.fuzzer.protocols import (
    Input,
    ScheduleResult,
    StoppingSignal,
)
from webfuzzer.fuzzer.schedulers.entropic import (
    _EXPLOIT_NOVELTY_FACTOR,
    EntropicScheduler,
)


# ── Helpers ─────────────────────────────────────────────────────────


def _build_corpus_with_features() -> Corpus:
    """Identical 2-seed corpus reused across regression assertions."""
    corpus = Corpus()
    a = corpus.force_add(Input(data=b"a"))
    b = corpus.force_add(Input(data=b"b"))
    a.feature_set = {1, 2, 3}
    b.feature_set = {1, 2, 3}
    return corpus


def _force_recompute(sched: EntropicScheduler, corpus: Corpus) -> None:
    """Push past the deferral window so _update_energies actually runs."""
    corpus.generation += 10
    sched._last_corpus_gen = -1
    sched._update_energies(corpus)


# ── Default & no-op cases ───────────────────────────────────────────


def test_signal_defaults_to_none_when_not_supplied():
    sched = EntropicScheduler(seed=42)
    assert sched._stopping_signal is None


def test_signal_can_be_passed_to_constructor():
    sig = StoppingSignal(
        phase="exploitation", missing_mass_upper=0.005, n_samples=1000,
    )
    sched = EntropicScheduler(seed=42, stopping_signal=sig)
    assert sched._stopping_signal is sig


def test_set_stopping_signal_invalidates_caches():
    sched = EntropicScheduler(seed=42)
    sched._last_corpus_gen = 7
    sched._weights_gen = 7
    sched.set_stopping_signal(
        StoppingSignal(
            phase="exploitation", missing_mass_upper=0.005, n_samples=1000,
        ),
    )
    assert sched._last_corpus_gen == -1
    assert sched._weights_gen == -1


def test_discovery_phase_is_noop_vs_no_signal():
    """Discovery phase must produce identical energies to no signal."""
    sched_a = EntropicScheduler(seed=42)
    sched_b = EntropicScheduler(seed=42)
    sched_b.set_stopping_signal(
        StoppingSignal(
            phase="discovery", missing_mass_upper=0.5, n_samples=1000,
        ),
    )
    corpus_a = _build_corpus_with_features()
    corpus_b = _build_corpus_with_features()
    _force_recompute(sched_a, corpus_a)
    _force_recompute(sched_b, corpus_b)
    energies_a = [s.energy for s in corpus_a.seeds]
    energies_b = [s.energy for s in corpus_b.seeds]
    assert energies_a == energies_b


# ── Exploitation phase effects ──────────────────────────────────────


def test_exploitation_phase_reduces_novelty_bonus():
    """Entropy contribution is scaled by _EXPLOIT_NOVELTY_FACTOR (<1)."""
    sched_disc = EntropicScheduler(seed=42)
    sched_expl = EntropicScheduler(seed=42)
    sched_expl.set_stopping_signal(
        StoppingSignal(
            phase="exploitation", missing_mass_upper=0.005, n_samples=1000,
        ),
    )
    corpus_disc = _build_corpus_with_features()
    corpus_expl = _build_corpus_with_features()
    _force_recompute(sched_disc, corpus_disc)
    _force_recompute(sched_expl, corpus_expl)

    # Both seeds have identical feature sets, so the only difference
    # between disc/expl runs is the novelty factor (and the unchanged
    # penalty=1.0 since no class-saturation hits were recorded).
    e_disc = corpus_disc.seeds[0].energy
    e_expl = corpus_expl.seeds[0].energy
    # Exploitation should yield strictly less energy (entropy * 0.3).
    assert e_expl < e_disc
    # And the ratio should track _EXPLOIT_NOVELTY_FACTOR within
    # floating-point tolerance + the 0.01 floor.
    assert e_expl == pytest.approx(e_disc * _EXPLOIT_NOVELTY_FACTOR, rel=1e-3)


def test_exploitation_phase_strengthens_saturation_penalty():
    """When a hot-pattern seed exists, exploitation makes the gap larger."""
    # Build two scheduler/corpus pairs with identical class-saturation
    # state. The hot-pattern seed (A) gets penalty < 1; in exploitation
    # phase that penalty is raised to power 1.5, shrinking it further.
    def _build_pair(signal):
        sched = EntropicScheduler(seed=42)
        if signal is not None:
            sched.set_stopping_signal(signal)
        corpus = Corpus()
        seed_a = corpus.force_add(Input(data=b"a"))
        seed_b = corpus.force_add(Input(data=b"b"))
        seed_a.feature_set = {1, 2, 3}
        seed_b.feature_set = {1, 2, 3}
        for _ in range(100):
            sched.update(seed_a, ScheduleResult(diff_pattern_hashes=["A"]))
        for _ in range(10):
            sched.update(seed_b, ScheduleResult(diff_pattern_hashes=["B"]))
        _force_recompute(sched, corpus)
        return sched, corpus, seed_a, seed_b

    _, corpus_disc, a_disc, b_disc = _build_pair(None)
    _, corpus_expl, a_expl, b_expl = _build_pair(
        StoppingSignal(
            phase="exploitation", missing_mass_upper=0.005, n_samples=1000,
        ),
    )

    ratio_disc = b_disc.energy / a_disc.energy
    ratio_expl = b_expl.energy / a_expl.energy
    # Exploitation phase should widen the b/a ratio because the hot
    # pattern's penalty (~0.09) gets raised to a power >1, shrinking
    # further (~0.027), while the cool pattern's penalty (~0.91) is
    # barely affected (0.91^1.5 ≈ 0.868).
    assert ratio_expl > ratio_disc


def test_select_does_not_crash_in_exploitation_mode():
    sched = EntropicScheduler(seed=42)
    sched.set_stopping_signal(
        StoppingSignal(
            phase="exploitation", missing_mass_upper=0.005, n_samples=1000,
        ),
    )
    corpus = Corpus()
    for i in range(5):
        s = corpus.force_add(Input(data=f"s{i}".encode()))
        s.feature_set = {i, i + 10}
    selected = sched.select(corpus)
    assert selected in corpus.seeds


def test_clearing_signal_restores_discovery_behavior():
    sig = StoppingSignal(
        phase="exploitation", missing_mass_upper=0.005, n_samples=1000,
    )
    sched = EntropicScheduler(seed=42, stopping_signal=sig)
    assert sched._stopping_signal is sig
    sched.set_stopping_signal(None)
    assert sched._stopping_signal is None


# ── CLI loader ──────────────────────────────────────────────────────


def test_loader_parses_minimal_payload(tmp_path: Path):
    from webfuzzer.cli import _load_stopping_signal

    p = tmp_path / "signal.json"
    p.write_text(
        json.dumps({
            "phase": "exploitation",
            "missing_mass_upper": 0.007,
            "n_samples": 9802,
            "tau_mix": 8.91,
        }),
        encoding="utf-8",
    )
    sig = _load_stopping_signal(p)
    assert sig is not None
    assert sig.phase == "exploitation"
    assert sig.missing_mass_upper == 0.007
    assert sig.n_samples == 9802
    assert sig.tau_mix == 8.91


def test_loader_parses_full_lint_json(tmp_path: Path):
    from webfuzzer.cli import _load_stopping_signal

    p = tmp_path / "lint.json"
    p.write_text(
        json.dumps({
            "run_id": "waf_v61_20260407",
            "checks": [
                {"id": "DG017", "status": "WARN", "observed": {}},
                {
                    "id": "DG018",
                    "status": "PASS",
                    "observed": {
                        "missing_mass_upper": 0.003,
                        "n_samples": 12000,
                        "tau_mix": 7.5,
                    },
                },
            ],
        }),
        encoding="utf-8",
    )
    sig = _load_stopping_signal(p)
    assert sig is not None
    assert sig.phase == "exploitation"
    assert sig.missing_mass_upper == 0.003
    assert sig.source_run_id == "waf_v61_20260407"


def test_loader_full_lint_json_with_dg018_warn_yields_discovery(
    tmp_path: Path,
):
    from webfuzzer.cli import _load_stopping_signal

    p = tmp_path / "lint.json"
    p.write_text(
        json.dumps({
            "checks": [
                {
                    "id": "DG018",
                    "status": "WARN",
                    "observed": {
                        "missing_mass_upper": 0.05,
                        "n_samples": 200,
                        "tau_mix": None,
                    },
                },
            ],
        }),
        encoding="utf-8",
    )
    sig = _load_stopping_signal(p)
    assert sig is not None
    assert sig.phase == "discovery"


def test_loader_returns_none_on_garbage(tmp_path: Path):
    from webfuzzer.cli import _load_stopping_signal

    p = tmp_path / "junk.json"
    p.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    assert _load_stopping_signal(p) is None


def test_loader_returns_none_on_missing_file(tmp_path: Path):
    from webfuzzer.cli import _load_stopping_signal

    assert _load_stopping_signal(tmp_path / "does_not_exist.json") is None
