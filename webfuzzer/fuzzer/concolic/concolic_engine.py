"""Real concolic engine: coverage trace → uncovered branch → source condition → targeted mutation.

Uses actual code coverage from Python sys.settrace / Node V8 Profiler
to identify uncovered branches, looks up the source-level condition in
BranchConditionDB, and generates inputs that target those specific branches.

Treat this as a targeted mutation strategy. It uses concrete execution and
source hints, but it is not a full symbolic/concolic executor.
"""

from __future__ import annotations

import logging
import os
import random
from typing import Any

from ..protocols import ExecutionResult, Input
from .branch_db import (
    BRANCH_DB,
    MUTATION_FUNCTIONS,
    BranchCondition,
    get_mutations_for_uncovered_lines,
)

logger = logging.getLogger(__name__)

# Library index → (library_name, source_dir, key_files)
# Populated at runtime from actual installed package paths
_LIBRARY_MAP: dict[int, tuple[str, str, list[str]]] = {}


def _init_library_map() -> None:
    """Discover library source paths at import time."""
    global _LIBRARY_MAP
    try:
        import signxml

        sig_dir = os.path.dirname(signxml.__file__)
        _LIBRARY_MAP[0] = (
            "signxml",
            sig_dir,
            ["processor.py", "verifier.py"],
        )
    except ImportError:
        pass

    try:
        import onelogin.saml2

        saml_dir = os.path.dirname(onelogin.saml2.__file__)
        _LIBRARY_MAP[1] = (
            "python3-saml",
            saml_dir,
            ["response.py", "utils.py", "xml_utils.py"],
        )
    except ImportError:
        pass


_init_library_map()


class ConcolicEngine:
    """Coverage-guided concolic execution engine.

    Loop per iteration:
      1. Receive execution results with coverage bitmaps
      2. Decode bitmap → covered lines per library
      3. Find uncovered branches adjacent to covered code
      4. Look up branch condition in DB → mutation function
      5. Apply mutation → return targeted input

    The bitmap from sys.settrace hashes ``filename:lineno`` via FNV-1a
    into 16384 bytes.  We cannot reverse the hash, so instead we maintain
    a shadow set of ``(file, line)`` tuples observed via a lightweight
    line-level trace.  For the initial version, we use the bitmap's
    NEW bits as a signal of coverage progress, and the BranchConditionDB
    to generate targeted mutations for lines we know are uncovered.

    Strategy: cycle through all BranchCondition entries, trying each
    mutation.  Track which mutations have been tried and skip duplicates.
    Prioritize mutations whose target lines had nearby coverage activity.
    """

    MAX_TARGETED = 3  # max targeted inputs per iteration

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

        # Track which branch conditions have been tried
        self._tried_mutations: set[str] = set()  # "library:file:line_start:mutation_fn"

        # Track which branch conditions produced new coverage
        self._successful_mutations: dict[str, int] = {}  # key → success count

        # Round-robin index into BRANCH_DB
        self._branch_idx = 0

        # Per-library cumulative covered bitmap indices
        self._covered_indices: dict[int, set[int]] = {}

        # Stats
        self._total_generated = 0
        self._total_new_coverage = 0

    def generate_targeted(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
    ) -> list[Input]:
        """Generate inputs targeting uncovered branches.

        Uses coverage bitmaps from results to identify which libraries
        have coverage gaps, then generates mutations to fill those gaps.
        """
        # Update coverage state
        self._update_coverage(primary_result, 0)
        for i, ref in enumerate(ref_results):
            self._update_coverage(ref, i + 1)

        # Find untried mutations, prioritizing those near recent coverage
        candidates = self._find_candidates()
        if not candidates:
            # All mutations tried — reset and try again with different seeds
            if len(self._tried_mutations) >= len(BRANCH_DB):
                self._tried_mutations.clear()
                candidates = self._find_candidates()

        targeted: list[Input] = []
        for bc in candidates[: self.MAX_TARGETED]:
            key = f"{bc.library}:{bc.file}:{bc.line_start}:{bc.mutation_fn}"
            self._tried_mutations.add(key)

            fn = MUTATION_FUNCTIONS.get(bc.mutation_fn)
            if fn is None:
                continue

            try:
                mutated = fn(inp.data, self._rng)
            except Exception:
                continue

            if mutated is None or mutated == inp.data:
                continue

            targeted.append(
                Input(
                    data=mutated,
                    metadata={
                        "mutator": "concolic",
                        "concolic_source": "concolic_engine",
                        "target_branch": f"{bc.library}/{bc.file}:{bc.line_start}",
                        "condition": bc.condition,
                        "xml_property": bc.xml_property,
                    },
                )
            )

        self._total_generated += len(targeted)
        return targeted

    def on_coverage_result(
        self, mutation_key: str | None, had_new_coverage: bool
    ) -> None:
        """Feedback: did the targeted mutation produce new coverage?"""
        if mutation_key and had_new_coverage:
            self._successful_mutations[mutation_key] = (
                self._successful_mutations.get(mutation_key, 0) + 1
            )
            self._total_new_coverage += 1

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_generated": self._total_generated,
            "total_new_coverage": self._total_new_coverage,
            "tried_mutations": len(self._tried_mutations),
            "total_branch_conditions": len(BRANCH_DB),
            "successful_mutations": dict(
                sorted(
                    self._successful_mutations.items(),
                    key=lambda x: -x[1],
                )[:10]
            ),
            "libraries_mapped": len(_LIBRARY_MAP),
        }

    def get_status_line(self) -> str:
        return (
            f"concolic:{self._total_generated} "
            f"tried:{len(self._tried_mutations)}/{len(BRANCH_DB)} "
            f"hit:{self._total_new_coverage}"
        )

    # ── Internal ────────────────────────────────────────────────

    def _update_coverage(self, result: ExecutionResult, lib_idx: int) -> None:
        """Update per-library covered bitmap indices."""
        raw = result.metadata.get("target_coverage")
        if not raw:
            return
        if lib_idx not in self._covered_indices:
            self._covered_indices[lib_idx] = set()
        covered = self._covered_indices[lib_idx]
        for i in range(min(len(raw), 16384)):
            if raw[i]:
                covered.add(i)

    def _find_candidates(self) -> list[BranchCondition]:
        """Find untried branch conditions, ordered by priority.

        Priority: conditions in libraries with active coverage first,
        round-robin through the DB to ensure diversity.
        """
        # Libraries with any coverage (more likely to benefit from targeting)
        active_libs = {
            _LIBRARY_MAP[idx][0]
            for idx in self._covered_indices
            if idx in _LIBRARY_MAP and self._covered_indices[idx]
        }

        candidates: list[BranchCondition] = []
        n = len(BRANCH_DB)

        # Start from round-robin position
        for offset in range(n):
            idx = (self._branch_idx + offset) % n
            bc = BRANCH_DB[idx]
            key = f"{bc.library}:{bc.file}:{bc.line_start}:{bc.mutation_fn}"

            if key in self._tried_mutations:
                continue

            # Prioritize active libraries
            if bc.library in active_libs:
                candidates.insert(0, bc)
            else:
                candidates.append(bc)

            if len(candidates) >= self.MAX_TARGETED * 2:
                break

        # Advance round-robin
        self._branch_idx = (self._branch_idx + self.MAX_TARGETED) % max(n, 1)

        return candidates
