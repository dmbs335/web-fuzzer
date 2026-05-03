"""Assembly helpers for experimental runtime features."""

from __future__ import annotations

import sys
from pathlib import Path


def build_guidance_hooks(*, protocol: str | None, profile_dir: Path | None):
    """Build optional regex/AST/profile guidance hooks."""
    if not protocol:
        return None

    from ..guidance.integration import GuidanceFuzzHooks, build_guidance_engine

    guidance_engine = build_guidance_engine(
        protocol=protocol,
        profile_dir=profile_dir,
    )
    if guidance_engine:
        print(
            f"  Guidance: {protocol} (experimental) - "
            f"{guidance_engine.metrics.gaps_identified} gaps, "
            f"{guidance_engine.metrics.targeted_seeds_generated} seeds",
            file=sys.stderr,
        )
        return GuidanceFuzzHooks(guidance_engine)

    print(
        f"  Guidance: {protocol} - no libraries found, disabled",
        file=sys.stderr,
    )
    return None


def build_targeted_mutation_coordinator(
    *,
    enabled: bool,
    mode: str,
    budget: float,
    seed: int | None,
    oracle: str | None,
    grammar: str | None,
):
    """Build optional targeted-mutation coordinator.

    The CLI flag is still named ``--concolic`` for compatibility, but this
    assembly helper keeps the implementation described as targeted mutation.
    """
    if not enabled:
        return None

    from ..fuzzer.concolic.plugins.registry import get_plugin

    domain_plugin = get_plugin(oracle=oracle, grammar=grammar)
    plugin_name = type(domain_plugin).__name__ if domain_plugin else "default(SAML)"

    if mode == "expert":
        from ..fuzzer.concolic.constraint_extractor import ConstraintExtractor
        from ..fuzzer.concolic.coordinator import ConcolicCoordinator
        from ..fuzzer.concolic.solver import ConstraintSolver

        coordinator = ConcolicCoordinator(
            extractor=ConstraintExtractor(),
            solver=ConstraintSolver(seed=seed),
            budget_pct=budget,
        )
    elif mode == "learned":
        from ..fuzzer.concolic.property_guided import PropertyGuidedCoordinator

        coordinator = PropertyGuidedCoordinator(
            budget_pct=budget,
            seed=seed,
        )
    elif mode == "whitebox":
        from ..fuzzer.concolic.hybrid_coordinator import HybridCoordinator

        coordinator = HybridCoordinator(
            budget_pct=budget,
            seed=seed,
            use_expert=False,
            use_coverage=True,
            domain_plugin=domain_plugin,
        )
    else:
        from ..fuzzer.concolic.hybrid_coordinator import HybridCoordinator

        coordinator = HybridCoordinator(
            budget_pct=budget,
            seed=seed,
            domain_plugin=domain_plugin,
        )

    print(
        f"  Targeted mutation: enabled (mode={mode}, "
        f"plugin={plugin_name}, budget={budget:.0%})",
        file=sys.stderr,
    )
    return coordinator
