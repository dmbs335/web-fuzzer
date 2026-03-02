"""Standalone t-way covering array generator using greedy IPOG algorithm.

No external dependencies.  Reusable for any parameterised testing domain.

Algorithm – In-Parameter-Order-General (IPOG), simplified greedy variant:
  1. Start with exhaustive cross-product of first *t* parameters.
  2. For each subsequent parameter *k* (t .. n-1):
     a. Horizontal extension: for every existing row, pick the value of
        parameter *k* that covers the most uncovered t-tuples.
     b. Vertical extension: add new rows for any remaining uncovered
        t-tuples, greedily filling unassigned positions.

Reference:
  Lei & Tai, "In-parameter-order: a test generation strategy for pairwise
  testing", IEEE HASE 1998.
"""

from __future__ import annotations

import itertools
import random
from typing import Sequence

# Type alias: a t-tuple is a tuple of (param_index, value_index) pairs.
_Tuple = tuple[tuple[int, int], ...]


def generate_covering_array(
    parameters: list[list[str]],
    strength: int = 2,
    seed: int | None = None,
) -> list[list[str]]:
    """Generate a *strength*-way covering array.

    Args:
        parameters: ``parameters[i]`` is the list of possible values for
            parameter *i*.
        strength: Interaction strength (2 = pairwise, 3 = 3-way, …).
        seed: Random seed for reproducibility.

    Returns:
        List of test configurations.  Each configuration is a list of
        values, one per parameter (``config[i]`` is from ``parameters[i]``).
    """
    n = len(parameters)
    if n == 0:
        return []
    if strength < 1:
        raise ValueError("strength must be >= 1")
    if strength > n:
        strength = n

    rng = random.Random(seed)
    sizes = [len(p) for p in parameters]

    # Step 1 — exhaustive product of first *strength* parameters.
    first_params = range(strength)
    rows: list[list[int | None]] = []
    for combo in itertools.product(*(range(sizes[i]) for i in first_params)):
        row: list[int | None] = [None] * n
        for pi, vi in zip(first_params, combo):
            row[pi] = vi
        rows.append(row)

    # Track covered t-tuples (set of _Tuple).
    covered: set[_Tuple] = set()
    _update_covered(covered, rows, list(first_params), strength)

    # Step 2 — extend for each remaining parameter.
    for k in range(strength, n):
        active_params = list(range(k + 1))

        # All t-tuples involving param *k* and any (strength-1) of params 0..k-1.
        new_tuples = _all_tuples_involving(k, sizes, active_params, strength)
        uncovered = new_tuples - covered

        # 2a. Horizontal extension: assign param k to existing rows.
        for row in rows:
            if not uncovered:
                row[k] = rng.randrange(sizes[k])
                continue
            best_val, best_count = 0, -1
            for vi in range(sizes[k]):
                row[k] = vi
                cnt = _count_newly_covered(row, uncovered, active_params, strength)
                if cnt > best_count:
                    best_val, best_count = vi, cnt
            row[k] = best_val
            _update_covered_single(covered, uncovered, row, active_params, strength)

        # 2b. Vertical extension: add rows for remaining uncovered tuples.
        while uncovered:
            t = next(iter(uncovered))
            new_row: list[int | None] = [None] * n
            for pi, vi in t:
                new_row[pi] = vi
            # Greedily fill unassigned positions among active params.
            for pi in active_params:
                if new_row[pi] is not None:
                    continue
                best_val, best_count = 0, -1
                for vi in range(sizes[pi]):
                    new_row[pi] = vi
                    cnt = _count_newly_covered(new_row, uncovered, active_params, strength)
                    if cnt > best_count:
                        best_val, best_count = vi, cnt
                new_row[pi] = best_val
            rows.append(new_row)
            _update_covered_single(covered, uncovered, new_row, active_params, strength)

    # Fill any remaining None positions (params beyond current scope)
    for row in rows:
        for pi in range(n):
            if row[pi] is None:
                row[pi] = rng.randrange(sizes[pi])

    # Convert value indices to actual value strings.
    return [[parameters[pi][vi] for pi, vi in enumerate(row)] for row in rows]


# ── Internal helpers ──────────────────────────────────────────────


def _all_tuples_involving(
    k: int, sizes: list[int], active_params: list[int], t: int,
) -> set[_Tuple]:
    """All t-tuples that include parameter *k* (with any t-1 others)."""
    others = [p for p in active_params if p != k]
    tuples: set[_Tuple] = set()
    for combo_params in itertools.combinations(others, t - 1):
        params = sorted(combo_params + (k,))
        for values in itertools.product(*(range(sizes[p]) for p in params)):
            tuples.add(tuple(zip(params, values)))
    return tuples


def _update_covered(
    covered: set[_Tuple],
    rows: list[list[int | None]],
    active_params: list[int],
    t: int,
) -> None:
    """Add all covered t-tuples from *rows* to *covered*."""
    for row in rows:
        for combo in itertools.combinations(active_params, t):
            vals = tuple((p, row[p]) for p in combo)
            if all(v is not None for _, v in vals):
                covered.add(vals)


def _update_covered_single(
    covered: set[_Tuple],
    uncovered: set[_Tuple],
    row: list[int | None],
    active_params: list[int],
    t: int,
) -> None:
    """Update covered/uncovered with tuples from a single row."""
    for combo in itertools.combinations(active_params, t):
        vals = tuple((p, row[p]) for p in combo)
        if all(v is not None for _, v in vals):
            covered.add(vals)
            uncovered.discard(vals)


def _count_newly_covered(
    row: list[int | None],
    uncovered: set[_Tuple],
    active_params: list[int],
    t: int,
) -> int:
    """Count how many tuples in *uncovered* this row would cover."""
    count = 0
    for combo in itertools.combinations(active_params, t):
        vals = tuple((p, row[p]) for p in combo)
        if all(v is not None for _, v in vals) and vals in uncovered:
            count += 1
    return count
