"""Fuzzing engine — target-agnostic, pluggable architecture."""

from .protocols import (
    CoverageCollector,
    Deduplicator,
    ExecutionResult,
    Finding,
    Input,
    InputSource,
    Mutator,
    MutatorScheduler,
    Oracle,
    ScheduleResult,
    SeedScheduler,
    Severity,
    Target,
)
from .corpus import CoverageMap, Corpus, Seed
from .engine import FuzzEngine

__all__ = [
    "CoverageCollector",
    "CoverageMap",
    "Corpus",
    "Deduplicator",
    "ExecutionResult",
    "Finding",
    "FuzzEngine",
    "Input",
    "InputSource",
    "Mutator",
    "MutatorScheduler",
    "Oracle",
    "ScheduleResult",
    "Seed",
    "SeedScheduler",
    "Severity",
    "Target",
]
