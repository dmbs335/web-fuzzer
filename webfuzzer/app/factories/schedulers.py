"""Scheduler factory helpers."""

from __future__ import annotations

import random
import sys


def build_seed_scheduler(name: str, seed: int | None):
    """Instantiate a seed scheduler by name."""
    from ...fuzzer.schedulers.ecofuzz import EcoFuzzScheduler
    from ...fuzzer.schedulers.entropic import EntropicScheduler
    from ...fuzzer.schedulers.random_scheduler import RandomSeedScheduler
    from ...fuzzer.schedulers.rare_branch import RareBranchScheduler

    scheduler_map = {
        "random": lambda: RandomSeedScheduler(seed=seed),
        "entropic": lambda: EntropicScheduler(seed=seed),
        "ecofuzz": lambda: EcoFuzzScheduler(seed=seed),
        "rare-branch": lambda: RareBranchScheduler(seed=seed),
    }

    if name == "map-elites":
        from ...fuzzer.schedulers.composite import CompositeScheduler
        from ...fuzzer.schedulers.map_elites import MapElitesScheduler

        return CompositeScheduler(
            primary=EntropicScheduler(seed=seed),
            secondary=MapElitesScheduler(seed=seed),
            p_secondary=0.3,
            seed=seed,
        )

    factory = scheduler_map.get(name)
    if factory is None:
        print(f"Warning: Unknown scheduler {name!r}, using entropic.", file=sys.stderr)
        return EntropicScheduler(seed=seed)
    return factory()


def build_mutator_scheduler(name: str, seed: int | None, **kwargs):
    """Instantiate a mutator scheduler by name."""
    if name == "random":
        weights_str = kwargs.get("weights")
        if weights_str:
            from ...fuzzer.engine import _DefaultMutatorScheduler

            weights = [float(w) for w in weights_str.split(",")]
            return _DefaultMutatorScheduler(random.Random(seed), weights=weights)
        return None

    from ...fuzzer.schedulers.linucb_scheduler import LinUCBScheduler
    from ...fuzzer.schedulers.mutation_scheduler import DARWINScheduler, MOPTScheduler

    mutator_scheduler_map = {
        "mopt": lambda: MOPTScheduler(seed=seed),
        "darwin": lambda: DARWINScheduler(seed=seed),
        "linucb": lambda: LinUCBScheduler(
            alpha=kwargs.get("alpha", 1.0), seed=seed,
        ),
    }

    factory = mutator_scheduler_map.get(name)
    if factory is None:
        print(
            f"Warning: Unknown mutator scheduler {name!r}, using random.",
            file=sys.stderr,
        )
        return None
    return factory()
