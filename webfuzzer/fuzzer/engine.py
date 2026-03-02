"""FuzzEngine — main fuzzing loop.

Assembles all pluggable components and runs the generate-execute-evaluate loop.
Every component is injected via Protocol interfaces — swap any part freely.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

from .corpus import Corpus, CoverageMap, Seed
from .coverage.diff_coverage import DiffCoverageCollector
from .coverage.adaptive_coverage import AdaptiveDiffCoverage
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
    Target,
)
from .redis_publisher import RedisPublisher
from .stats import FuzzStats

logger = logging.getLogger(__name__)


class FuzzEngine:
    """Main fuzzing engine — wires all components together.

    All components are Protocol-based and fully swappable.

    Usage:
        engine = FuzzEngine(
            target=MyTarget(),
            input_source=GrammarInputSource(registry, "json"),
            mutators=[HavocMutator(), GrammarMutator(...)],
            oracles=[CrashOracle()],
            coverage=EdgeCoverage(),
            seed_scheduler=EntropicScheduler(),
        )
        engine.run()
    """

    def __init__(
        self,
        target: Target,
        input_source: InputSource,
        mutators: list[Mutator],
        oracles: list[Oracle],
        coverage: CoverageCollector | None = None,
        seed_scheduler: SeedScheduler | None = None,
        mutator_scheduler: MutatorScheduler | None = None,
        deduplicator: Deduplicator | None = None,
        corpus: Corpus | None = None,
        max_iterations: int = 0,
        max_time_seconds: float = 0,
        initial_seed_count: int = 100,
        seed: int | None = None,
        output_dir: Path | None = None,
        status_interval: float = 5.0,
        reference_targets: list[Target] | None = None,
        seeds_dir: Path | None = None,
        import_findings: list[Path] | None = None,
        resume: bool = False,
        checkpoint_interval: float = 60.0,
    ):
        self.target = target
        self.reference_targets: list[Target] = reference_targets or []
        self.input_source = input_source
        self.mutators = mutators
        self.oracles = oracles
        self.coverage = coverage
        self.corpus = corpus or Corpus()
        self.stats = FuzzStats(output_dir=output_dir)
        self.rng = random.Random(seed)

        self.max_iterations = max_iterations
        self.max_time_seconds = max_time_seconds
        self.initial_seed_count = initial_seed_count
        self.output_dir = output_dir
        self.status_interval = status_interval
        self.seeds_dir = seeds_dir
        self.import_findings = import_findings or []
        self.resume = resume
        self.checkpoint_interval = checkpoint_interval

        # Use defaults if not provided
        self.seed_scheduler: SeedScheduler = seed_scheduler or _DefaultSeedScheduler(self.rng)
        self.mutator_scheduler: MutatorScheduler = mutator_scheduler or _DefaultMutatorScheduler(self.rng)
        self.deduplicator: Deduplicator = deduplicator or _DefaultDeduplicator()

        self._last_status_time = 0.0
        self._last_save_time = 0.0
        self._last_checkpoint_time = 0.0
        self._running = False
        self._resumed = False
        self._publisher = RedisPublisher()
        self._cmd_queue: queue.Queue[dict] = queue.Queue()

        # Reusable thread pool for reference target execution (avoids
        # per-iteration ThreadPoolExecutor creation/teardown overhead).
        self._ref_pool: ThreadPoolExecutor | None = None

    def run(self) -> FuzzStats:
        """Execute the main fuzzing loop. Returns stats when done."""
        self._running = True
        self.stats = FuzzStats()
        self._publisher.publish_status("started")

        try:
            self._setup()
            if self.resume and self._load_checkpoint():
                self._resumed = True
                logger.info(
                    "Resumed from checkpoint: %d seeds, %d edges, %d execs",
                    len(self.corpus), self.stats.total_edges,
                    self.stats.total_executions,
                )
            else:
                self._seed_corpus()
            self._main_loop()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            self._publisher.publish_status("stopped")
        finally:
            self._save_checkpoint()
            self._cleanup()

        return self.stats

    def stop(self) -> None:
        """Signal the engine to stop after current iteration."""
        self._running = False

    # ── Internal phases ───────────────────────────────────────────

    def _setup(self) -> None:
        self.target.setup()
        for i, ref in enumerate(self.reference_targets):
            ref.setup()
            logger.info("Reference target [%d] set up", i)
        self._start_command_reader()
        logger.info("Target set up successfully")

    def _seed_corpus(self) -> None:
        """Generate initial seeds and populate the corpus."""
        file_seed_count = 0

        # Phase 0: Import finding inputs from previous sessions
        if self.import_findings:
            imported = 0
            for session_dir in self.import_findings:
                findings_dir = session_dir / "findings"
                if not findings_dir.is_dir():
                    logger.warning("No findings dir in %s", session_dir)
                    continue
                for fd in sorted(findings_dir.iterdir()):
                    input_f = fd / "input"
                    if not input_f.is_file():
                        continue
                    try:
                        data = input_f.read_bytes()
                        if data:
                            inp = Input(data=data)
                            result = self._execute(inp)
                            ref_results = self._execute_references(inp)
                            cov = self._collect_coverage(inp, result, ref_results=ref_results)
                            self.corpus.force_add(inp, cov)
                            self._check_oracles(inp, result, mutator_name="file_seed", ref_results=ref_results)
                            self.stats.record_execution("file_seed")
                            imported += 1
                            file_seed_count += 1
                    except Exception as e:
                        logger.warning("Failed to import finding %s: %s", input_f, e)
            logger.info("Imported %d finding inputs from %d session(s)", imported, len(self.import_findings))

        # Phase 1: Load file-based seeds if seeds_dir is provided
        if self.seeds_dir and self.seeds_dir.is_dir():
            seed_files = sorted(self.seeds_dir.iterdir())
            logger.info("Loading %d seed files from %s", len(seed_files), self.seeds_dir)
            for sf in seed_files:
                if sf.is_file() and not sf.name.startswith("."):
                    try:
                        data = sf.read_bytes()
                        if data:
                            inp = Input(data=data)
                            result = self._execute(inp)
                            ref_results = self._execute_references(inp)
                            cov = self._collect_coverage(inp, result, ref_results=ref_results)
                            self.corpus.force_add(inp, cov)
                            self._check_oracles(inp, result, mutator_name="file_seed", ref_results=ref_results)
                            self.stats.record_execution("file_seed")
                            file_seed_count += 1
                    except Exception as e:
                        logger.warning("Failed to load seed %s: %s", sf, e)

        # Phase 2: Fill remaining with grammar-generated seeds
        gen_count = max(0, self.initial_seed_count - file_seed_count)
        logger.info("Generating %d initial seeds (%d from files)...", gen_count, file_seed_count)

        for _ in range(gen_count):
            inp = self.input_source.generate()
            result = self._execute(inp)

            # Execute refs once, share results with coverage + oracles
            ref_results = self._execute_references(inp)
            cov = self._collect_coverage(inp, result, ref_results=ref_results)

            # Check novelty BEFORE force_add (which merges into global coverage)
            is_novel = bool(
                cov and self.coverage
                and self.coverage.is_novel(self.corpus.global_coverage, cov)
            )
            self.corpus.force_add(inp, cov)
            found_crash = self._check_oracles(inp, result, mutator_name="seed", ref_results=ref_results)
            self.stats.record_execution("seed")

            # MCTS feedback: backpropagate to grammar UCB1 table
            if hasattr(self.input_source, 'update'):
                self.input_source.update(inp, ScheduleResult(
                    found_new_coverage=is_novel,
                    found_crash=found_crash,
                ))

        self.stats.update_corpus(
            len(self.corpus),
            sum(len(s.input.data) for s in self.corpus.seeds),
        )
        self.stats.record_new_coverage(self.corpus.global_coverage.edge_count)
        logger.info(
            "Seeding done: %d seeds, %d edges",
            len(self.corpus), self.corpus.global_coverage.edge_count,
        )
        self._publisher.publish_stats(
            elapsed_seconds=self.stats.elapsed(),
            total_execs=self.stats.total_executions,
            execs_per_sec=self.stats.executions_per_second,
            corpus_size=self.stats.corpus_size,
            total_edges=self.stats.total_edges,
            unique_findings=self.stats.unique_findings,
        )
        self._publisher.publish_coverage(
            edge_count=self.corpus.global_coverage.edge_count,
            elapsed_sec=self.stats.elapsed(),
            exec_count=self.stats.total_executions,
            corpus_size=len(self.corpus),
        )

    def _main_loop(self) -> None:
        """The core fuzz loop."""
        while self._running and not self._should_stop():
            self.stats.record_iteration()

            # 1. Select seed
            seed = self.seed_scheduler.select(self.corpus)
            seed.exec_count += 1
            seed.last_mutated_at = time.time()

            # 2. Select mutator
            mutator = self.mutator_scheduler.select(self.mutators, seed)
            mutator_name = mutator.name

            # 3. Mutate
            mutated_input = mutator.mutate(seed.input, self.corpus.seeds)

            # 4. Execute
            result = self._execute(mutated_input)
            self.stats.record_execution(mutator_name)

            # Track per-strategy metrics (e.g., SAML mutator's 50 strategies)
            strategies = mutated_input.metadata.get("strategies", [])
            if strategies:
                self.stats.record_strategies(strategies)

            # 4.5. Execute refs once (cached for coverage + oracles)
            ref_results = self._execute_references(mutated_input)

            # 5. Collect coverage and check novelty
            is_novel = False
            new_edges: set[int] = set()
            if self.coverage:
                new_cov = self._collect_coverage(mutated_input, result, ref_results=ref_results)
                is_novel = self.coverage.is_novel(
                    self.corpus.global_coverage, new_cov
                )
                if is_novel:
                    new_seed = self.corpus.add(
                        mutated_input, new_cov,
                        parent_id=seed.id,
                        depth=seed.depth + 1,
                    )
                    if new_seed:
                        new_edges = new_seed.feature_set
                        self.stats.record_new_coverage(
                            self.corpus.global_coverage.edge_count, mutator_name
                        )
                        if strategies:
                            self.stats.record_strategy_coverage(strategies)
                        self.stats.update_corpus(
                            len(self.corpus),
                            sum(len(s.input.data) for s in self.corpus.seeds),
                        )
                        self._publisher.publish_coverage(
                            edge_count=self.corpus.global_coverage.edge_count,
                            elapsed_sec=self.stats.elapsed(),
                            exec_count=self.stats.total_executions,
                            corpus_size=len(self.corpus),
                        )
                        self._publisher.publish_corpus(
                            seed_id=new_seed.id,
                            input_data=mutated_input.data,
                            parent_id=seed.id,
                            depth=new_seed.depth,
                            energy=new_seed.energy,
                            metadata=mutated_input.metadata,
                        )
            # 6. Check oracles
            found_crash = self._check_oracles(mutated_input, result, mutator_name, ref_results=ref_results)
            if found_crash and strategies:
                self.stats.record_strategy_finding(strategies)

            # 7. Update schedulers
            schedule_result = ScheduleResult(
                found_new_coverage=is_novel,
                found_crash=found_crash,
                execution_time_ms=result.duration_ms,
                new_edges=new_edges,
                finding_metadata=self._last_finding_metadata,
            )
            self.seed_scheduler.update(seed, schedule_result)
            self.mutator_scheduler.update(mutator, schedule_result)

            # 7.5 MCTS feedback: backpropagate to grammar UCB1 table
            if hasattr(self.input_source, 'update') and (is_novel or found_crash):
                self.input_source.update(mutated_input, schedule_result)

            # 7.6 CEGAR adaptive coverage check
            if isinstance(self.coverage, AdaptiveDiffCoverage):
                self.coverage.notify_execution()
                if is_novel:
                    self.coverage.notify_new_coverage(self.stats.total_iterations)
                if self.coverage.check_and_adapt(self.corpus):
                    self.stats.update_corpus(
                        len(self.corpus),
                        sum(len(s.input.data) for s in self.corpus.seeds),
                    )
                    self.stats.record_new_coverage(
                        self.corpus.global_coverage.edge_count,
                    )

            # 8. Process external commands (priority adjustments etc.)
            self._process_commands()

            # 9. Periodic corpus compaction (every 10K iterations)
            if self.stats.total_iterations % 10000 == 0 and len(self.corpus) > 200:
                removed = self.corpus.compact(min_seeds=50)
                if removed > 0:
                    logger.info(
                        "Corpus compacted: %d seeds removed, %d remaining",
                        removed, len(self.corpus),
                    )
                    self.stats.update_corpus(
                        len(self.corpus),
                        sum(len(s.input.data) for s in self.corpus.seeds),
                    )

            # 10. Status output + periodic checkpoint
            self._maybe_print_status()
            self._maybe_save_checkpoint()

    def _collect_coverage(
        self, inp: Input, result: ExecutionResult,
        ref_results: list[ExecutionResult] | None = None,
    ) -> CoverageMap | None:
        """Collect coverage, dispatching to diff/adaptive coverage if applicable."""
        if self.coverage is None:
            return None
        if isinstance(self.coverage, AdaptiveDiffCoverage):
            # Adaptive wrapper needs seed_id for FeatureStore.
            # During seeding (corpus.add not yet called) seed_id is corpus._next_id.
            seed_id = self.corpus._next_id
            return self.coverage.collect_diff(
                inp, result, ref_results=ref_results, seed_id=seed_id,
            )
        if isinstance(self.coverage, DiffCoverageCollector):
            return self.coverage.collect_diff(inp, result, ref_results=ref_results)
        return self.coverage.collect(result)

    def _execute(self, inp: Input) -> ExecutionResult:
        """Execute input against target, handling crashes."""
        start = time.time()
        try:
            result = self.target.execute(inp)
        except Exception as e:
            result = ExecutionResult(
                exit_code=-1,
                stderr=str(e).encode("utf-8", errors="replace"),
            )

        if result.duration_ms == 0:
            result.duration_ms = (time.time() - start) * 1000

        # Check target health
        if not self.target.is_alive():
            logger.warning("Target died, resetting...")
            try:
                self.target.teardown()
            except Exception:
                pass
            self.target.setup()

        return result

    def _execute_references(self, inp: Input) -> list[ExecutionResult] | None:
        """Execute input against all reference targets (parallel).

        Fast path: Rust parallel_pipe_execute (GIL-free native threads).
        Slow path: Python ThreadPoolExecutor (fallback).
        """
        if not self.reference_targets:
            return None

        # --- Fast path: Rust parallel pipe I/O ---
        if self._can_use_rust_pipes():
            try:
                return self._execute_references_rust(inp)
            except Exception as e:
                logger.debug("Rust pipe execute failed, falling back: %s", e)

        # --- Slow path: Python ThreadPoolExecutor ---
        def _run(target: Target) -> ExecutionResult:
            try:
                return target.execute(inp)
            except Exception as e:
                return ExecutionResult(
                    exit_code=-999,
                    stderr=str(e).encode("utf-8", errors="replace"),
                )

        if len(self.reference_targets) == 1:
            return [_run(self.reference_targets[0])]

        if self._ref_pool is None:
            self._ref_pool = ThreadPoolExecutor(
                max_workers=len(self.reference_targets),
            )
        return list(self._ref_pool.map(_run, self.reference_targets))

    def _can_use_rust_pipes(self) -> bool:
        """Check if Rust parallel pipe execution is available and applicable.

        Currently disabled: Rust raw pipe I/O conflicts with Python's
        buffered warmup reads on the same pipe handles, causing reference
        targets to return empty stdout.  Python ThreadPoolExecutor is used
        instead (still fast enough at ~50 exec/s with 7 reference targets).
        TODO: Re-enable after implementing handle-level isolation (dup pipe
        fds after warmup, or pass raw fds directly to Rust).
        """
        return False

    def _execute_references_rust(self, inp: Input) -> list[ExecutionResult]:
        """Execute all reference targets via Rust parallel_pipe_execute."""
        from webfuzzer.native import parallel_pipe_execute
        from .targets.persistent_target import PersistentTarget

        # Collect handles, restarting dead processes
        handles: list[tuple[int, int]] = []
        for target in self.reference_targets:
            assert isinstance(target, PersistentTarget)
            if not target.is_alive():
                target.setup()
            ph = target.pipe_handles
            if ph is None:
                raise RuntimeError("Could not obtain pipe handles")
            handles.append(ph)

        timeout_ms = int(max(t.timeout_seconds for t in self.reference_targets) * 1000)

        # Call Rust — GIL released during I/O
        raw_results = parallel_pipe_execute(handles, inp.data, timeout_ms)

        # Convert to ExecutionResult objects
        results: list[ExecutionResult] = []
        for i, (output, exit_code, duration_ms, error) in enumerate(raw_results):
            if error is not None:
                target = self.reference_targets[i]
                assert isinstance(target, PersistentTarget)
                logger.warning("Ref[%d] error (%s): %s (%.0fms)",
                               i, target.command[:60], error, duration_ms)
                target.teardown()
                results.append(ExecutionResult(
                    exit_code=-1,
                    stderr=error.encode("utf-8", errors="replace"),
                    duration_ms=duration_ms,
                    metadata={"error": "persistent_target_error"},
                ))
            else:
                results.append(ExecutionResult(
                    exit_code=exit_code,
                    stdout=output,
                    duration_ms=duration_ms,
                ))

        return results

    def _check_oracles(self, inp: Input, result: ExecutionResult,
                       mutator_name: str = "",
                       ref_results: list[ExecutionResult] | None = None) -> bool:
        """Run all oracles. Returns True if any finding was recorded.

        Side-effect: populates ``self._last_finding_metadata`` with
        metadata dicts for each unique finding (used by MAP-Elites).
        """
        found = False
        self._last_finding_metadata: list[dict] = []
        for oracle in self.oracles:
            # DiffOracle.check_with_refs returns list[Finding]
            if ref_results is not None and hasattr(oracle, 'check_with_refs'):
                findings_or_one = oracle.check_with_refs(inp, result, ref_results)
            else:
                findings_or_one = oracle.check(inp, result)

            # Normalize to list
            if findings_or_one is None:
                findings: list[Finding] = []
            elif isinstance(findings_or_one, list):
                findings = findings_or_one
            else:
                findings = [findings_or_one]

            for finding in findings:
                if mutator_name:
                    finding.metadata["mutator"] = mutator_name
                finding.fingerprint = self.deduplicator.fingerprint(finding)
                if not self.deduplicator.is_duplicate(finding):
                    self.deduplicator.register(finding)
                    self.stats.record_finding(finding, mutator_name)
                    self._publisher.publish_finding(
                        title=finding.title,
                        severity=finding.severity.value,
                        oracle_name=finding.oracle_name,
                        fingerprint=finding.fingerprint,
                        input_data=finding.input.data,
                        exit_code=finding.result.exit_code,
                        duration_ms=finding.result.duration_ms,
                        metadata=finding.metadata,
                    )
                    logger.info(
                        "Finding: [%s] %s (oracle=%s)",
                        finding.severity.value, finding.title, finding.oracle_name,
                    )
                    # Collect metadata for MAP-Elites scheduler.
                    self._last_finding_metadata.append({
                        "category": finding.metadata.get("category", ""),
                        "ref_index": finding.metadata.get("ref_index", 0),
                        "severity": finding.severity.value,
                        "strategy": finding.metadata.get("strategy", ""),
                    })
                    found = True
        return found

    def _should_stop(self) -> bool:
        if self.max_iterations and self.stats.total_iterations >= self.max_iterations:
            return True
        if self.max_time_seconds and self.stats.elapsed() >= self.max_time_seconds:
            return True
        if not self.corpus.seeds:
            return True
        return False

    def _maybe_print_status(self) -> None:
        now = time.time()
        if now - self._last_status_time >= self.status_interval:
            self._last_status_time = now
            status = self.stats.status_line()
            if self._publisher.enabled or os.environ.get("FUZZER_SESSION_ID"):
                # Orchestrator mode: newline-terminated for readline() parsing
                print(status, flush=True, file=sys.stderr)
            else:
                # Terminal mode: carriage return for in-place update
                print(f"\r{status}", end="", flush=True, file=sys.stderr)
            self._publisher.publish_stats(
                elapsed_seconds=self.stats.elapsed(),
                total_execs=self.stats.total_executions,
                execs_per_sec=self.stats.executions_per_second,
                corpus_size=self.stats.corpus_size,
                total_edges=self.stats.total_edges,
                unique_findings=self.stats.unique_findings,
            )

            # Periodically save intermediate report.json (every 30s)
            if self.output_dir and now - self._last_save_time >= 30.0:
                self._last_save_time = now
                self.output_dir.mkdir(parents=True, exist_ok=True)
                (self.output_dir / "report.json").write_text(
                    self.stats.report("json"), encoding="utf-8",
                )

    def _start_command_reader(self) -> None:
        """Start a daemon thread that reads JSON commands from stdin."""
        if not sys.stdin or not hasattr(sys.stdin, 'closed') or sys.stdin.closed:
            return

        def _reader() -> None:
            try:
                for line in sys.stdin:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        cmd = json.loads(line)
                        self._cmd_queue.put(cmd)
                    except json.JSONDecodeError:
                        pass
            except (EOFError, OSError, ValueError):
                pass  # stdin closed or unavailable

        t = threading.Thread(target=_reader, daemon=True, name="cmd-reader")
        t.start()

    def _process_commands(self) -> None:
        """Process queued commands from stdin (non-blocking)."""
        while True:
            try:
                cmd = self._cmd_queue.get_nowait()
            except queue.Empty:
                break

            cmd_type = cmd.get("cmd")
            if cmd_type == "set_priority":
                seed_id = cmd.get("seed_id")
                boost = cmd.get("boost", 1.0)
                if seed_id is not None:
                    ok = self.corpus.set_priority(seed_id, boost)
                    if ok:
                        self._publisher.publish_priority_update(seed_id, boost)
                        logger.debug("Priority set: seed=%d boost=%.2f", seed_id, boost)
            elif cmd_type == "reset_priorities":
                self.corpus.reset_priorities()
                logger.debug("All priorities reset to 1.0")

    def _cleanup(self) -> None:
        print("", file=sys.stderr)  # newline after status line
        if self._ref_pool is not None:
            self._ref_pool.shutdown(wait=False)
            self._ref_pool = None
        try:
            self.target.teardown()
        except Exception:
            pass
        for ref in self.reference_targets:
            try:
                ref.teardown()
            except Exception:
                pass

        if self.output_dir:
            self.stats.save(self.output_dir)
            self.corpus.save(self.output_dir / "corpus")
            logger.info("Results saved to %s", self.output_dir)

        if self._running:
            self._publisher.publish_status("completed")
        self._publisher.close()

    # ── Checkpointing ──────────────────────────────────────────────

    def _checkpoint_dir(self) -> Path | None:
        """Return checkpoint directory path, or None if output_dir not set."""
        if self.output_dir is None:
            return None
        return self.output_dir / "checkpoint"

    def _save_checkpoint(self) -> None:
        """Save full engine state to checkpoint directory."""
        ckpt = self._checkpoint_dir()
        if ckpt is None:
            return

        try:
            # Corpus (seeds + global coverage bitmap)
            self.corpus.save_checkpoint(ckpt / "corpus")

            # Stats
            state: dict = {
                "stats": self.stats.to_checkpoint_dict(),
                "rng_state": self.rng.getstate(),
            }

            # Deduplicator seen set
            if isinstance(self.deduplicator, _DefaultDeduplicator):
                state["dedup_seen"] = sorted(self.deduplicator._seen)

            ckpt.mkdir(parents=True, exist_ok=True)
            (ckpt / "state.json").write_text(
                json.dumps(state, default=str), encoding="utf-8",
            )
            logger.debug(
                "Checkpoint saved: %d seeds, %d edges",
                len(self.corpus), self.stats.total_edges,
            )
        except Exception as e:
            logger.warning("Failed to save checkpoint: %s", e)

    def _load_checkpoint(self) -> bool:
        """Load engine state from checkpoint. Returns True if loaded."""
        ckpt = self._checkpoint_dir()
        if ckpt is None:
            return False

        state_file = ckpt / "state.json"
        if not state_file.exists():
            return False

        try:
            # Corpus
            if not self.corpus.load_checkpoint(ckpt / "corpus"):
                return False

            # State
            state = json.loads(state_file.read_text(encoding="utf-8"))

            # Stats
            self.stats.load_checkpoint_dict(state.get("stats", {}))

            # RNG
            rng_state = state.get("rng_state")
            if rng_state is not None:
                # JSON serializes tuples as lists; Random.setstate needs tuples
                self.rng.setstate(_json_to_rng_state(rng_state))

            # Deduplicator
            dedup_seen = state.get("dedup_seen")
            if dedup_seen and isinstance(self.deduplicator, _DefaultDeduplicator):
                self.deduplicator._seen = set(dedup_seen)

            return True
        except Exception as e:
            logger.warning("Failed to load checkpoint: %s", e)
            return False

    def _maybe_save_checkpoint(self) -> None:
        """Save checkpoint periodically (every checkpoint_interval seconds)."""
        if self.output_dir is None:
            return
        now = time.time()
        if now - self._last_checkpoint_time >= self.checkpoint_interval:
            self._last_checkpoint_time = now
            self._save_checkpoint()


def _json_to_rng_state(raw: list) -> tuple:
    """Convert JSON-deserialized RNG state back to the tuple format
    expected by random.Random.setstate().

    JSON serializes tuples as lists, but Random.setstate() requires:
        (version: int, internalstate: tuple[int, ...], gauss_next: float)
    """
    version = raw[0]
    internal = tuple(raw[1])
    gauss_next = raw[2]
    return (version, internal, gauss_next)


# ── Default implementations (minimal, used when user provides none) ──

class _DefaultSeedScheduler:
    """Random seed selection — simplest possible scheduler."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def select(self, corpus: Corpus) -> Seed:
        weights = [s.priority_boost for s in corpus.seeds]
        return self.rng.choices(corpus.seeds, weights=weights, k=1)[0]

    def update(self, seed: Seed, result: ScheduleResult) -> None:
        pass


class _DefaultMutatorScheduler:
    """Random mutator selection."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng

    def select(self, mutators: list[Mutator], seed: Seed) -> Mutator:
        return self.rng.choice(mutators)

    def update(self, mutator: Mutator, result: ScheduleResult) -> None:
        pass


class _DefaultDeduplicator:
    """Metadata-aware hash-based deduplication.

    Fingerprint components (all contribute to the hash):
      1. oracle_name — separates crash / differential / ssrf
      2. severity — CRITICAL host confusion ≠ MEDIUM output mismatch
      3. exit_code + stderr[:256] — crash signature
      4. strategy + ref_index — which strategy, which reference target
      5. category — ssrf_host_confusion vs scheme_confusion etc.
      6. diff_fields — SET of JSON fields that differ between parsers

    This ensures that different classes of parsing divergence
    produce distinct fingerprints, while truly duplicate findings
    (same class, same ref target, same structural diff) get merged.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def fingerprint(self, finding: Finding) -> str:
        meta = finding.metadata or {}

        # Build key string directly — no hashing needed, string IS the fingerprint
        parts = [
            finding.oracle_name,
            finding.severity.value,
            str(finding.result.exit_code),
            meta.get("strategy", ""),
            str(meta.get("ref_index", "")),
            meta.get("category", ""),
        ]

        df = meta.get("diff_fields")
        if df:
            parts.append(",".join(sorted(df)))

        # Namespace/structural element sets — different element
        # divergence patterns produce distinct fingerprints.
        # (Avoids output hash which creates too-granular dedup.)
        op = meta.get("only_primary")
        orr = meta.get("only_ref")
        if op:
            parts.append(f"op={','.join(sorted(op))}")
        if orr:
            parts.append(f"or={','.join(sorted(orr))}")

        # Bypass signal — differentiates has_script vs has_event_handler etc.
        sig = meta.get("signal")
        if sig:
            parts.append(f"sig={sig}")

        pi = meta.get("primary_internal")
        if pi is not None:
            parts.append(f"pi={pi}")
        ri = meta.get("ref_internal")
        if ri is not None:
            parts.append(f"ri={ri}")

        pe = meta.get("primary_exit")
        re_ = meta.get("ref_exit")
        if pe is not None and re_ is not None:
            parts.append(f"p={pe},r={re_}")

        return "|".join(parts)

    def is_duplicate(self, finding: Finding) -> bool:
        return finding.fingerprint in self._seen

    def register(self, finding: Finding) -> None:
        self._seen.add(finding.fingerprint)
