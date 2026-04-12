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
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

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


_JSON_NOT_CACHED = object()


@dataclass
class ExecutionResult:
    """Result of executing an Input against a Target."""

    exit_code: int = 0
    stdout: bytes = b""
    stderr: bytes = b""
    duration_ms: float = 0.0
    coverage_data: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Cached JSON parse of stdout — avoids redundant json.loads across
    # coverage collector, oracle, and diff strategies (~60K→~5K calls).
    _parsed_json: Any = field(default=_JSON_NOT_CACHED, repr=False, compare=False)

    def parsed_json(self) -> dict | None:
        """Return parsed JSON from stdout, caching the result."""
        if self._parsed_json is not _JSON_NOT_CACHED:
            return self._parsed_json
        import json
        try:
            text = self.stdout.strip()
            if text:
                data = json.loads(text)
                if isinstance(data, dict):
                    self._parsed_json = data
                    return data
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
            pass
        self._parsed_json = None
        return None


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


@dataclass(frozen=True)
class StoppingSignal:
    """Offline PAC stopping signal from diffspace-geometry lint (DG018).

    Produced by running
    ``python -m experiments.diffspace_geometry.lint --json`` on a prior
    session and extracting the ``DG018`` observed fields (or constructed
    by hand for tests). The signal tells the scheduler whether the
    previous campaign's Good-Turing missing-mass upper bound already
    cleared the PAC stopping threshold ε.

    ``phase="discovery"``  — the fuzzer should keep exploring normally;
    scheduler behaves as if no signal were supplied.

    ``phase="exploitation"`` — the species pool is already near-saturated
    (per McAllester–Schapire). The entropic scheduler dampens its
    novelty component and strengthens the class-saturation penalty so
    that energy flows to *under-visited* patterns rather than to the
    rare-feature frontier (which has already been charted).

    Fields are kept minimal and domain-agnostic; ``source_run_id`` is
    only used for logging.
    """

    phase: Literal["discovery", "exploitation"]
    missing_mass_upper: float
    n_samples: int
    tau_mix: float | None = None
    source_run_id: str | None = None
    # Pareto tail-index α from the DG006 Hill estimator.  When α < 2 the
    # divergence-rate distribution has infinite variance; mutators should use
    # median normalisation instead of max in apply_learned_weights.
    pareto_alpha: float | None = None


@dataclass
class ScheduleResult:
    """Feedback from an execution — used by schedulers to update state."""

    found_new_coverage: bool = False
    found_crash: bool = False
    execution_time_ms: float = 0.0
    new_edges: set[int] = field(default_factory=set)
    # Finding metadata for MAP-Elites: list of {category, ref_index, severity}.
    finding_metadata: list[dict[str, Any]] = field(default_factory=list)
    # Differential pattern hashes observed this invocation (pre-dedup).
    # Consumed by class-saturation aware schedulers (Phase 4 feedback hook).
    diff_pattern_hashes: list[str] = field(default_factory=list)


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
class ScheduleFeedbackInputSource(Protocol):
    """Accepts per-execution feedback for adaptive input generation."""

    def update(self, inp: Input, result: ScheduleResult) -> None: ...


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
class StrategyWeightProvider(Protocol):
    """Provides learned strategy weights for compatible mutators."""

    def get_strategy_weights(self) -> dict[str, float]: ...


@runtime_checkable
class LearnedWeightMutator(Protocol):
    """Accepts strategy weights learned by another subsystem."""

    def apply_learned_weights(
        self,
        strategy_effectiveness: dict[str, float],
        alpha: float | None = None,
    ) -> None: ...


@runtime_checkable
class LatticeAtomMutator(Protocol):
    """Accepts offline Birkhoff-atom coverage weights (E4 FCA output).

    The input is a ``{strategy_name: weight in [0,1]}`` dict derived from
    ``experiments/diffspace_geometry/e4_fca/strategy_atoms.py``. Higher
    weights correspond to strategies whose historical findings cover a
    larger subset of the meet-irreducible diff-field atoms of the
    observed concept lattice. Implementations should treat this as a
    startup-time weight initialization, not a runtime feedback channel.
    """

    def apply_lattice_atoms(
        self,
        atom_weights: dict[str, float],
    ) -> None: ...


@runtime_checkable
class AutomatonWitnessMutator(Protocol):
    """Accepts E7 differential-SFA witness scores as a startup boost.

    Input is ``{strategy_name: score in [0, 1]}`` produced offline from
    the E7 pairwise symmetric-difference surfaces plus the feature dump
    (see
    ``experiments/diffspace_geometry/e7_automata/strategy_witnesses.py``).
    Higher scores mean the strategy historically contributed more to
    diff-field coordinates that witness observed library-pair
    disagreements. Implementations should treat this as a startup-time
    initialization that composes with other boost channels without ever
    demoting a weight already raised elsewhere.
    """

    def apply_automaton_witnesses(
        self,
        witness_weights: dict[str, float],
    ) -> None: ...


@runtime_checkable
class StrategyFeedbackMutator(Protocol):
    """Accepts coarse execution outcome signals to tune internal strategy mix."""

    def feedback(self, strategy_name: str, signal: str) -> None: ...


@runtime_checkable
class ExceptionHintMutator(Protocol):
    """Accepts exception-derived hints for targeted follow-up mutations."""

    def set_exception_hint(self, hint: Any | None) -> None: ...


@runtime_checkable
class ResettableMutatorWeights(Protocol):
    """Can reset dynamic mutator weights after long stalls."""

    def reset_weights(self, boost_zero_finds: bool = False) -> None: ...


@runtime_checkable
class GuidanceWeightedMutator(Protocol):
    """Accepts field-level guidance weights from guidance hooks."""

    def apply_guidance_weights(self, field_weights: dict[str, float]) -> None: ...


@runtime_checkable
class CleanupAwareSeedScheduler(Protocol):
    """Can drop scheduler state for seeds removed during corpus compaction."""

    def cleanup_removed(self, removed_ids: set[int]) -> None: ...


@runtime_checkable
class Deduplicator(Protocol):
    """Prevents duplicate bug reports."""

    def fingerprint(self, finding: Finding) -> str: ...
    def is_duplicate(self, finding: Finding) -> bool: ...
    def register(self, finding: Finding) -> None: ...
