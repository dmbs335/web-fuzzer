"""All fuzzer component interfaces (Protocols).

Every swappable component is defined as a typing.Protocol.
Users implement only what they need; the rest uses built-in defaults.

To fuzz a new target, implement:
  1. Target     — how to send input and get results
  2. (optional) CoverageCollector — how to measure coverage
  3. (optional) Oracle — how to detect bugs
Everything else (Mutator, Scheduler, etc.) ships with built-in implementations.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .corpus import Corpus, CoverageMap, Seed


# ── Severity enum ──────────────────────────────────────────────────

class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ── Core data structures ──────────────────────────────────────────

@dataclass
class Input:
    """A single fuzzer-generated input."""

    data: bytes
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of executing an Input against a Target."""

    exit_code: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    duration_ms: float = 0.0
    coverage_data: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A discovered bug or anomaly."""

    title: str
    severity: Severity
    input: Input
    result: ExecutionResult
    oracle_name: str
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScheduleResult:
    """Feedback from an execution — used by schedulers to update state."""

    found_new_coverage: bool = False
    found_crash: bool = False
    execution_time_ms: float = 0.0
    new_edges: set[int] = field(default_factory=set)
    # Finding metadata for MAP-Elites: list of {category, ref_index, severity}.
    finding_metadata: list[dict[str, Any]] = field(default_factory=list)


# ── Pluggable component Protocols ─────────────────────────────────

@runtime_checkable
class Target(Protocol):
    """Fuzzing target — sends input, receives result.

    Implement this to fuzz anything:
    local process, HTTP server, TCP socket, file parser, browser, etc.
    """

    def execute(self, inp: Input) -> ExecutionResult: ...
    def setup(self) -> None: ...
    def teardown(self) -> None: ...
    def is_alive(self) -> bool: ...
    def reset(self) -> None: ...


@runtime_checkable
class CoverageCollector(Protocol):
    """Extracts coverage information from execution results."""

    def collect(self, result: ExecutionResult) -> CoverageMap: ...
    def merge(self, a: CoverageMap, b: CoverageMap) -> CoverageMap: ...
    def is_novel(self, existing: CoverageMap, new: CoverageMap) -> bool: ...
    def diff(self, old: CoverageMap, new: CoverageMap) -> set[int]: ...


@runtime_checkable
class Oracle(Protocol):
    """Bug detector — inspects execution results for anomalies."""

    name: str

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None: ...


@runtime_checkable
class Mutator(Protocol):
    """Mutates an existing input to produce a new one."""

    name: str

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input: ...


@runtime_checkable
class InputSource(Protocol):
    """Generates fresh inputs (for initial seeding or generation mode)."""

    def generate(self) -> Input: ...


@runtime_checkable
class SeedScheduler(Protocol):
    """Selects the next seed from the corpus for mutation.

    Implementations: random, Entropic, EcoFuzz (MAB), FairFuzz, etc.
    """

    def select(self, corpus: Corpus) -> Seed: ...
    def update(self, seed: Seed, result: ScheduleResult) -> None: ...


@runtime_checkable
class MutatorScheduler(Protocol):
    """Selects which mutator to use for the current iteration.

    Implementations: random, MOPT (PSO), DARWIN (ES), etc.
    """

    def select(self, mutators: list[Mutator], seed: Seed) -> Mutator: ...
    def update(self, mutator: Mutator, result: ScheduleResult) -> None: ...


@runtime_checkable
class Deduplicator(Protocol):
    """Prevents duplicate bug reports."""

    def fingerprint(self, finding: Finding) -> str: ...
    def is_duplicate(self, finding: Finding) -> bool: ...
    def register(self, finding: Finding) -> None: ...
