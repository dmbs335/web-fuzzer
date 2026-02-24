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
    ):
        self.target = target
        self.reference_targets: list[Target] = reference_targets or []
        self.input_source = input_source
        self.mutators = mutators
        self.oracles = oracles
        self.coverage = coverage
        self.corpus = corpus or Corpus()
        self.stats = FuzzStats()
        self.rng = random.Random(seed)

        self.max_iterations = max_iterations
        self.max_time_seconds = max_time_seconds
        self.initial_seed_count = initial_seed_count
        self.output_dir = output_dir
        self.status_interval = status_interval
        self.seeds_dir = seeds_dir

        # Use defaults if not provided
        self.seed_scheduler: SeedScheduler = seed_scheduler or _DefaultSeedScheduler(self.rng)
        self.mutator_scheduler: MutatorScheduler = mutator_scheduler or _DefaultMutatorScheduler(self.rng)
        self.deduplicator: Deduplicator = deduplicator or _DefaultDeduplicator()

        self._last_status_time = 0.0
        self._last_save_time = 0.0
        self._running = False
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
            self._seed_corpus()
            self._main_loop()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            self._publisher.publish_status("stopped")
        finally:
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

            self.corpus.force_add(inp, cov)
            self._check_oracles(inp, result, mutator_name="seed", ref_results=ref_results)
            self.stats.record_execution("seed")

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

            # 7. Update schedulers
            schedule_result = ScheduleResult(
                found_new_coverage=is_novel,
                found_crash=found_crash,
                execution_time_ms=result.duration_ms,
                new_edges=new_edges,
            )
            self.seed_scheduler.update(seed, schedule_result)
            self.mutator_scheduler.update(mutator, schedule_result)

            # 8. Process external commands (priority adjustments etc.)
            self._process_commands()

            # 9. Status output
            self._maybe_print_status()

    def _collect_coverage(
        self, inp: Input, result: ExecutionResult,
        ref_results: list[ExecutionResult] | None = None,
    ) -> CoverageMap | None:
        """Collect coverage, dispatching to diff coverage if applicable."""
        if self.coverage is None:
            return None
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
        """Execute input against all reference targets (parallel)."""
        if not self.reference_targets:
            return None

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

    def _check_oracles(self, inp: Input, result: ExecutionResult,
                       mutator_name: str = "",
                       ref_results: list[ExecutionResult] | None = None) -> bool:
        """Run all oracles. Returns True if any finding was recorded."""
        found = False
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
        if not sys.stdin or sys.stdin.closed:
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
        import hashlib
        h = hashlib.sha256()
        h.update(finding.oracle_name.encode())
        h.update(finding.severity.value.encode())
        h.update(str(finding.result.exit_code).encode())
        h.update(finding.result.stderr[:256])

        meta = finding.metadata or {}

        # Strategy name (exit_code, output, ssrf, timing, error_pattern)
        if "strategy" in meta:
            h.update(meta["strategy"].encode())

        # Which reference target triggered the finding
        if "ref_index" in meta:
            h.update(str(meta["ref_index"]).encode())

        # SSRF-specific category (host_confusion, scheme_confusion, etc.)
        if "category" in meta:
            h.update(meta["category"].encode())

        # Set of JSON fields that differ (computed by SSRF/output strategy)
        if "diff_fields" in meta:
            h.update(",".join(sorted(meta["diff_fields"])).encode())

        # For host confusion: internal vs external classification
        # (not exact host — same class of bypass should dedup)
        if "primary_internal" in meta:
            h.update(f"pi={meta['primary_internal']}".encode())
        if "ref_internal" in meta:
            h.update(f"ri={meta['ref_internal']}".encode())

        # For accept/reject: direction matters
        if "primary_exit" in meta and "ref_exit" in meta:
            h.update(f"p={meta['primary_exit']},r={meta['ref_exit']}".encode())

        return h.hexdigest()[:16]

    def is_duplicate(self, finding: Finding) -> bool:
        return finding.fingerprint in self._seen

    def register(self, finding: Finding) -> None:
        self._seen.add(finding.fingerprint)
