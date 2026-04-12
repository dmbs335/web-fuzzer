"""E7 Phase 3A: RPNI per-library DFA minimization.

Oncina & Garcia (1992) RPNI applied to per-library disagreement labels from
a FeatureTrace.  Each feature vector is treated as a sorted sequence of its
active coordinate names.  The algorithm:

1. Builds a Prefix Tree Acceptor (PTA) from the observed (sequence, label)
   pairs, bounded to ``max_prefix_depth`` symbols.
2. Traverses states in BFS order and tries to merge each later state ``v``
   into each earlier state ``u`` when their right-languages agree up to
   ``max_suffix_depth`` steps (the Myhill-Nerode right-congruence test).
3. Emits one minimized DFA per library together with the set of coordinate
   names that appear on at least one transition (discriminating coordinates).

Output is suitable for ``library_dfas.json`` in the E7 outputs directory.
``discriminating_coordinates`` is what downstream Phase 4 mutation targeting
uses to focus on the axes most predictive of per-library divergence.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from .feature_trace import FeatureTrace


# ── DFA state ────────────────────────────────────────────────────────────────

@dataclass
class _State:
    label: Optional[int] = None        # 1=accept, 0=reject, None=unlabeled
    trans: dict[str, int] = field(default_factory=dict)  # sym -> state_id
    parent: Optional[int] = None       # used to track redirect after merge


# Union-find: states[i].parent != None means i merged into parent
def _root(states: list[_State], i: int) -> int:
    while states[i].parent is not None:
        i = states[i].parent
    return i


# ── PTA construction ─────────────────────────────────────────────────────────

def _build_pta(
    seqs: list[tuple[str, ...]],
    labels: list[int],
) -> list[_State]:
    """Build a prefix tree automaton from (sequence, label) training pairs."""
    states: list[_State] = [_State()]          # state 0 = initial
    for seq, lbl in zip(seqs, labels):
        cur = 0
        for sym in seq:
            r = _root(states, cur)
            if sym not in states[r].trans:
                states.append(_State())
                states[r].trans[sym] = len(states) - 1
            cur = states[r].trans[sym]
        leaf = _root(states, cur)
        # Positive label wins over negative; unlabeled → take the label.
        if lbl == 1 or states[leaf].label is None:
            states[leaf].label = lbl
    return states


# ── Suffix collection & compatibility test ───────────────────────────────────

def _suffixes(
    states: list[_State],
    start: int,
    max_depth: int,
) -> list[tuple[str, ...]]:
    """BFS-collect all non-empty symbol-sequences of depth ≤ max_depth."""
    out: list[tuple[str, ...]] = [()]
    q: deque[tuple[int, tuple[str, ...]]] = deque([(_root(states, start), ())])
    seen: set[int] = {_root(states, start)}
    while q:
        s, path = q.popleft()
        for sym, nxt in states[s].trans.items():
            r = _root(states, nxt)
            suffix = path + (sym,)
            out.append(suffix)
            if len(suffix) < max_depth and r not in seen:
                seen.add(r)
                q.append((r, suffix))
    return out


def _run(states: list[_State], start: int, seq: tuple[str, ...]) -> Optional[int]:
    """Simulate the (merged) DFA from *start* over *seq*; None = no transition."""
    cur = _root(states, start)
    for sym in seq:
        nxt = states[cur].trans.get(sym)
        if nxt is None:
            return None
        cur = _root(states, nxt)
    return cur


def _compatible(
    states: list[_State],
    u: int,
    v: int,
    max_suffix_depth: int,
) -> bool:
    """Return True iff merging v into u would not create a label conflict."""
    for suf in _suffixes(states, v, max_suffix_depth):
        u_end = _run(states, u, suf)
        v_end = _run(states, v, suf)
        ul = states[u_end].label if u_end is not None else None
        vl = states[v_end].label if v_end is not None else None
        if ul is not None and vl is not None and ul != vl:
            return False
    return True


# ── Merge operation (with recursive collision resolution) ─────────────────────

def _merge(states: list[_State], u: int, v: int) -> None:
    """Merge state v into state u (modifies states in place)."""
    u, v = _root(states, u), _root(states, v)
    if u == v:
        return
    # Label propagation: positive wins.
    if states[v].label == 1 or states[u].label is None:
        states[u].label = states[v].label
    # Absorb v's outgoing transitions into u.
    for sym, nxt in states[v].trans.items():
        nxt_r = _root(states, nxt)
        if sym not in states[u].trans:
            states[u].trans[sym] = nxt_r
        else:
            existing = _root(states, states[u].trans[sym])
            if existing != nxt_r:
                _merge(states, existing, nxt_r)   # recursive collision resolve
    states[v].parent = u                           # mark v absorbed


# ── Per-library RPNI ─────────────────────────────────────────────────────────

def rpni_per_library(
    trace: FeatureTrace,
    library_idx: int,
    *,
    max_prefix_depth: int = 5,
    max_suffix_depth: int = 3,
) -> dict:
    """Run RPNI for one library and return a JSON-serialisable DFA dict."""
    fnames = trace.field_names
    seqs: list[tuple[str, ...]] = []
    labels: list[int] = []
    for j in range(trace.X.shape[0]):
        active = tuple(fnames[i] for i in range(len(fnames)) if trace.X[j, i])
        seqs.append(active[:max_prefix_depth])
        labels.append(int(trace.Y[j, library_idx]))

    states = _build_pta(seqs, labels)

    # BFS order over live (non-merged) states reachable from root.
    order: list[int] = []
    visited: set[int] = {0}
    q: deque[int] = deque([0])
    while q:
        s = q.popleft()
        r = _root(states, s)
        if r not in {_root(states, x) for x in order}:
            order.append(r)
        for nxt in states[r].trans.values():
            nr = _root(states, nxt)
            if nr not in visited:
                visited.add(nr)
                q.append(nr)

    # RPNI merge pass: for each later state v, try to fold it into an earlier u.
    for i, u in enumerate(order):
        for v in order[i + 1:]:
            uc, vc = _root(states, u), _root(states, v)
            if uc == vc:
                continue
            if _compatible(states, uc, vc, max_suffix_depth):
                _merge(states, uc, vc)

    # Collect live canonical states and renumber.
    live = sorted({_root(states, i) for i in range(len(states))
                   if states[i].parent is None})
    remap = {old: new for new, old in enumerate(live)}

    dfa_states = []
    for old in live:
        s = states[old]
        dfa_states.append({
            "id": remap[old],
            "label": s.label,
            "transitions": {
                sym: remap[_root(states, nxt)]
                for sym, nxt in s.trans.items()
                if _root(states, nxt) in remap
            },
        })

    disc = sorted({sym for s in dfa_states for sym in s["transitions"]})
    return {
        "n_states": len(dfa_states),
        "initial_state": remap[_root(states, 0)],
        "states": dfa_states,
        "discriminating_coordinates": disc,
    }


# ── Public entry point ────────────────────────────────────────────────────────

def run_rpni(
    trace: FeatureTrace,
    *,
    max_prefix_depth: int = 5,
    max_suffix_depth: int = 3,
) -> dict[str, dict]:
    """Run RPNI for every library in trace; return {library_name: dfa_dict}."""
    return {
        name: rpni_per_library(
            trace,
            k,
            max_prefix_depth=max_prefix_depth,
            max_suffix_depth=max_suffix_depth,
        )
        for k, name in enumerate(trace.library_names)
    }
