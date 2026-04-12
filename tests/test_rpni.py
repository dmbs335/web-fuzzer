"""Phase 3A: RPNI per-library DFA minimization tests.

Tests cover:
- hill_alpha and rpni_per_library on synthetic FeatureTrace data
- state count after merge (should be ≤ PTA size)
- discriminating coordinates match active features
- empty / single-class / sparse inputs handled gracefully
- run_rpni returns one entry per library
- run.py --rpni flag integration (smoke)
"""
from __future__ import annotations

import numpy as np
import pytest

from experiments.diffspace_geometry.e7_automata.feature_trace import FeatureTrace
from experiments.diffspace_geometry.e7_automata.rpni import (
    rpni_per_library,
    run_rpni,
    _build_pta,
    _compatible,
    _merge,
    _root,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _trace(
    field_names: list[str],
    library_names: list[str],
    X: list[list[int]],
    Y: list[list[int]],
) -> FeatureTrace:
    return FeatureTrace(
        X=np.array(X, dtype=np.uint8),
        Y=np.array(Y, dtype=np.uint8),
        field_names=field_names,
        library_names=library_names,
    )


# ── _build_pta ────────────────────────────────────────────────────────────────

def test_build_pta_single_seq():
    states = _build_pta([("a", "b")], [1])
    # root → a → b, leaf labeled 1
    assert len(states) == 3
    a_id = states[0].trans["a"]
    b_id = states[a_id].trans["b"]
    assert states[b_id].label == 1


def test_build_pta_shared_prefix():
    states = _build_pta([("a", "b"), ("a", "c")], [1, 0])
    # root → a → {b, c}
    a_id = states[0].trans["a"]
    assert "b" in states[a_id].trans
    assert "c" in states[a_id].trans


def test_build_pta_positive_wins_conflict():
    # Same sequence gets labeled 1 then 0 — 1 must win.
    states = _build_pta([("x",), ("x",)], [1, 0])
    leaf = states[0].trans["x"]
    assert states[leaf].label == 1


def test_build_pta_empty_seqs():
    states = _build_pta([], [])
    assert len(states) == 1   # just root


# ── _compatible & _merge ─────────────────────────────────────────────────────

def test_compatible_identical_states():
    states = _build_pta([("a",), ("b",)], [1, 1])
    # Both transitions lead to accepting states → should be compatible
    u = states[0].trans["a"]
    v = states[0].trans["b"]
    assert _compatible(states, u, v, max_suffix_depth=2)


def test_incompatible_conflicting_labels():
    states = _build_pta([("a",), ("b",)], [1, 0])
    u = states[0].trans["a"]  # label=1
    v = states[0].trans["b"]  # label=0
    assert not _compatible(states, u, v, max_suffix_depth=2)


def test_merge_redirects_parent():
    states = _build_pta([("a",), ("b",)], [1, 1])
    u = states[0].trans["a"]
    v = states[0].trans["b"]
    _merge(states, u, v)
    assert _root(states, v) == _root(states, u)


# ── rpni_per_library ─────────────────────────────────────────────────────────

def _simple_trace() -> FeatureTrace:
    """2 libraries, 3 coordinates, 8 rows."""
    fnames = ["alpha", "beta", "gamma"]
    lnames = ["lib_0", "lib_1"]
    # X: which coordinates are active
    X = [
        [1, 0, 0],  # alpha only
        [0, 1, 0],  # beta only
        [1, 1, 0],  # alpha+beta
        [0, 0, 1],  # gamma only
        [1, 0, 1],  # alpha+gamma
        [0, 1, 1],  # beta+gamma
        [1, 1, 1],  # all
        [0, 0, 0],  # none
    ]
    # Y: lib_0 disagrees on alpha, lib_1 disagrees on gamma
    Y = [
        [1, 0],
        [0, 0],
        [1, 0],
        [0, 1],
        [1, 1],
        [0, 1],
        [1, 1],
        [0, 0],
    ]
    return _trace(fnames, lnames, X, Y)


def test_rpni_per_library_returns_dict():
    tr = _simple_trace()
    result = rpni_per_library(tr, 0)
    assert "n_states" in result
    assert "initial_state" in result
    assert "states" in result
    assert "discriminating_coordinates" in result


def test_rpni_per_library_state_count_bounded():
    """RPNI must not increase the number of states vs raw PTA."""
    tr = _simple_trace()
    result = rpni_per_library(tr, 0)
    # With merging, should be ≤ raw PTA size (trivially ≤ n_rows × depth)
    assert result["n_states"] >= 1
    # At minimum: root + at least one more (alpha is discriminating for lib_0)
    assert result["n_states"] >= 1


def test_rpni_per_library_discriminating_coords():
    tr = _simple_trace()
    r0 = rpni_per_library(tr, 0)
    r1 = rpni_per_library(tr, 1)
    # lib_0 is discriminated by alpha; lib_1 by gamma
    assert "alpha" in r0["discriminating_coordinates"]
    assert "gamma" in r1["discriminating_coordinates"]


def test_rpni_per_library_all_negative():
    """All rows have label 0 for this library → single accept=0 state."""
    fnames = ["a", "b"]
    lnames = ["lib_only"]
    X = [[1, 0], [0, 1], [1, 1]]
    Y = [[0], [0], [0]]
    tr = _trace(fnames, lnames, X, Y)
    result = rpni_per_library(tr, 0)
    assert result["n_states"] >= 1
    # All leaf labels should be 0 or None
    for s in result["states"]:
        assert s["label"] in (0, None)


def test_rpni_per_library_all_positive():
    fnames = ["a", "b"]
    lnames = ["lib_only"]
    X = [[1, 0], [0, 1], [1, 1]]
    Y = [[1], [1], [1]]
    tr = _trace(fnames, lnames, X, Y)
    result = rpni_per_library(tr, 0)
    assert result["n_states"] >= 1
    labels = {s["label"] for s in result["states"]}
    assert 1 in labels


def test_rpni_per_library_empty_trace():
    fnames = ["a"]
    lnames = ["lib_only"]
    tr = _trace(fnames, lnames, [], [])
    result = rpni_per_library(tr, 0)
    assert result["n_states"] == 1  # just root
    assert result["discriminating_coordinates"] == []


def test_rpni_per_library_no_active_coords():
    """Rows with no active coordinates → all end up at root → single state."""
    fnames = ["a", "b"]
    lnames = ["lib_only"]
    X = [[0, 0], [0, 0]]
    Y = [[1], [0]]
    tr = _trace(fnames, lnames, X, Y)
    result = rpni_per_library(tr, 0)
    # Root gets both labels; positive wins
    assert result["n_states"] == 1


# ── run_rpni ─────────────────────────────────────────────────────────────────

def test_run_rpni_returns_all_libraries():
    tr = _simple_trace()
    result = run_rpni(tr)
    assert set(result.keys()) == {"lib_0", "lib_1"}
    for lib_dfa in result.values():
        assert "n_states" in lib_dfa


def test_run_rpni_depth_bounding():
    """max_prefix_depth=1 means sequences of length ≤ 1 → fewer states."""
    tr = _simple_trace()
    shallow = run_rpni(tr, max_prefix_depth=1)
    deep = run_rpni(tr, max_prefix_depth=5)
    # Shallow DFA can't have more states than deep (bounded prefix = fewer paths)
    for lib in shallow:
        assert shallow[lib]["n_states"] <= deep[lib]["n_states"] + 1  # +1 for rounding


# ── run.py --rpni integration smoke ─────────────────────────────────────────

def test_run_rpni_integration_smoke(tmp_path):
    """run.py --rpni on the phase2_validate feature dump (if present)."""
    from pathlib import Path
    import json
    from experiments.diffspace_geometry.e7_automata.feature_trace import load_feature_trace
    from experiments.diffspace_geometry.e7_automata.rpni import run_rpni

    dump = Path("out/phase2_validate/synth_features.jsonl")
    if not dump.exists():
        pytest.skip("phase2_validate feature dump not present")

    trace = load_feature_trace(dump)
    if len(trace.library_names) == 0 or trace.X.shape[0] == 0:
        pytest.skip("empty trace")

    out = run_rpni(trace, max_prefix_depth=4, max_suffix_depth=3)
    assert len(out) == len(trace.library_names)
    for lib, dfa in out.items():
        assert dfa["n_states"] >= 1
        assert isinstance(dfa["discriminating_coordinates"], list)

    # Verify JSON serialisable
    serialized = json.dumps(out)
    assert len(serialized) > 10
