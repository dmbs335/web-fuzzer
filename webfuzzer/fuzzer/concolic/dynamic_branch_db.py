"""Dynamic branch DB: auto-generated from AST analysis + domain plugin.

Replaces the hardcoded branch_db.py (41 entries) with runtime-generated
branch conditions from any Python library's source code.

Usage:
    from .dynamic_branch_db import DynamicBranchDB
    db = DynamicBranchDB(domain_plugin=saml_plugin)
    db.analyze("signxml")
    db.analyze("python3-saml")
    # db now has ~400 branches with mutations tied to the plugin's perturbations
"""

from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import Any, Callable

from .ast_analyzer import AstBranchExtractor, ExtractedBranch, map_branches_to_mutations
from .domain_plugin import DomainPlugin

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class DynamicBranch:
    """One branch condition with linked mutation via domain plugin."""

    branch: ExtractedBranch
    mutation_names: list[str]  # property-level mutation names
    prop_indices: list[int]  # corresponding property indices in the plugin
    tried: bool = False
    success_count: int = 0


class DynamicBranchDB:
    """Auto-generated branch DB from AST analysis.

    Ties extracted branch conditions to domain plugin perturbations
    via the PROPERTY_TO_MUTATION mapping.
    """

    def __init__(self, domain_plugin: DomainPlugin | None = None) -> None:
        self._plugin = domain_plugin
        self._extractor = AstBranchExtractor()
        self._branches: list[DynamicBranch] = []
        self._round_robin = 0

        # Build mutation name → property index lookup from plugin
        self._mutation_to_idx: dict[str, int] = {}
        if domain_plugin:
            # Plugin-specific mutation name mapping (primary)
            self._mutation_to_idx.update(domain_plugin.mutation_name_to_prop_index)
            # Also add direct property name → index (fallback)
            for i, name in enumerate(domain_plugin.property_names):
                if name not in self._mutation_to_idx:
                    self._mutation_to_idx[name] = i

    def analyze(
        self,
        library_name: str,
        source_dir: str | None = None,
        key_files: list[str] | None = None,
    ) -> int:
        """Analyze a library and add branches to the DB.

        Returns number of new branches added.
        """
        raw_branches = self._extractor.analyze_library(
            library_name, source_dir, key_files
        )
        mapped = map_branches_to_mutations(raw_branches)

        added = 0
        for branch, mutation_names in mapped:
            # Resolve mutation names → plugin property indices
            prop_indices = []
            for mname in mutation_names:
                idx = self._mutation_to_idx.get(mname, -1)
                if idx >= 0:
                    prop_indices.append(idx)

            if not prop_indices:
                continue  # no matching perturbation in this plugin

            self._branches.append(
                DynamicBranch(
                    branch=branch,
                    mutation_names=mutation_names,
                    prop_indices=prop_indices,
                )
            )
            added += 1

        logger.info(
            "DynamicBranchDB: analyzed %s — %d branches extracted, %d mapped",
            library_name,
            len(raw_branches),
            added,
        )
        return added

    def analyze_module(self, module_name: str) -> int:
        """Analyze a Python module by import name."""
        raw_branches = self._extractor.analyze_module(module_name)
        mapped = map_branches_to_mutations(raw_branches)

        added = 0
        for branch, mutation_names in mapped:
            prop_indices = []
            for mname in mutation_names:
                idx = self._mutation_to_idx.get(mname, -1)
                if idx >= 0:
                    prop_indices.append(idx)

            if not prop_indices:
                continue

            self._branches.append(
                DynamicBranch(
                    branch=branch,
                    mutation_names=mutation_names,
                    prop_indices=prop_indices,
                )
            )
            added += 1

        return added

    def generate_targeted(
        self,
        data: bytes,
        rng: random.Random,
        max_mutations: int = 3,
    ) -> list[tuple[bytes, DynamicBranch]]:
        """Generate targeted mutations from untried branches.

        Returns (mutated_data, branch) pairs.
        """
        if not self._branches or self._plugin is None:
            return []

        candidates = self._find_candidates(max_mutations * 2)
        results: list[tuple[bytes, DynamicBranch]] = []

        for db in candidates:
            if len(results) >= max_mutations:
                break

            # Pick a random property index from this branch's options
            prop_idx = rng.choice(db.prop_indices)

            # Use the plugin's perturbation
            mutations = self._plugin.perturb(data, prop_idx, rng)
            if mutations:
                mutated = mutations[0]
                if mutated != data:
                    results.append((mutated, db))
                    db.tried = True

        return results

    def on_result(self, branch: DynamicBranch, had_new_coverage: bool) -> None:
        """Feedback: did the mutation produce new coverage?"""
        if had_new_coverage:
            branch.success_count += 1

    def _find_candidates(self, n: int) -> list[DynamicBranch]:
        """Find untried branches, round-robin with priority to successful ones."""
        total = len(self._branches)
        if total == 0:
            return []

        candidates: list[DynamicBranch] = []
        for offset in range(total):
            idx = (self._round_robin + offset) % total
            db = self._branches[idx]
            if not db.tried:
                candidates.append(db)
            if len(candidates) >= n:
                break

        # If all tried, reset and try again (with randomization)
        if not candidates:
            for db in self._branches:
                db.tried = False
            for offset in range(min(n, total)):
                idx = (self._round_robin + offset) % total
                candidates.append(self._branches[idx])

        self._round_robin = (self._round_robin + n) % max(total, 1)

        # Sort: successful branches first
        candidates.sort(key=lambda x: -x.success_count)
        return candidates

    @property
    def total_branches(self) -> int:
        return len(self._branches)

    @property
    def tried_count(self) -> int:
        return sum(1 for b in self._branches if b.tried)

    def get_stats(self) -> dict[str, Any]:
        by_lib: dict[str, int] = {}
        for db in self._branches:
            lib = db.branch.library
            by_lib[lib] = by_lib.get(lib, 0) + 1

        return {
            "total_branches": self.total_branches,
            "tried": self.tried_count,
            "by_library": by_lib,
            "successful": sum(1 for b in self._branches if b.success_count > 0),
        }
