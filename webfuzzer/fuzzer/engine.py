"""FuzzEngine — main fuzzing loop.

Assembles all pluggable components and runs the generate-execute-evaluate loop.
Every component is injected via Protocol interfaces — swap any part freely.
"""

from __future__ import annotations

import hashlib
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
from .schedulers.danger_booster import DangerBooster
from .stats import FuzzStats

logger = logging.getLogger(__name__)


def _build_jndi_exception_hint(result: ExecutionResult) -> dict[str, object] | None:
    """Extract JNDI-oriented exception feedback from an execution result.

    Also passes method introspection data (string_methods, has_no_arg_ctor)
    from JndiTarget so the mutator can auto-discover forceString candidates.
    """
    parsed = result.parsed_json()
    if not isinstance(parsed, dict):
        return None

    hint: dict[str, object] = {}

    # ── Identity fields (for availability cache) ──────────────────
    factory_class = str(parsed.get("factory_class", "") or "")
    reference_class = str(parsed.get("reference_class", "") or "")
    if factory_class:
        hint["factory_class"] = factory_class
    if reference_class:
        hint["reference_class"] = reference_class

    # ── Factory/bean status (for reachability feedback) ───────────
    factory_loaded = parsed.get("factory_loaded")
    if factory_loaded is not None:
        hint["factory_loaded"] = bool(factory_loaded)
    bean_created = parsed.get("bean_created")
    if bean_created is not None:
        hint["bean_created"] = bool(bean_created)
    resolved_class_name = parsed.get("resolved_class_name")
    if resolved_class_name:
        hint["resolved_class_name"] = str(resolved_class_name)
    method_invoked = parsed.get("method_invoked")
    if method_invoked:
        hint["method_invoked"] = str(method_invoked)
    sinks_hit = parsed.get("sinks_hit")
    if isinstance(sinks_hit, list) and sinks_hit:
        hint["sinks_hit"] = sinks_hit
    jdbc_driver = parsed.get("jdbc_driver")
    if jdbc_driver:
        hint["jdbc_driver"] = str(jdbc_driver)

    # ── Method introspection feedback ──────────────────────────────
    string_methods = parsed.get("string_methods")
    if isinstance(string_methods, list) and string_methods:
        hint["string_methods"] = string_methods
    has_no_arg_ctor = parsed.get("has_no_arg_ctor")
    if has_no_arg_ctor is not None:
        hint["has_no_arg_ctor"] = bool(has_no_arg_ctor)

    # ── Phase 6: Classpath sweep results ─────────────────────────
    sweep_results = parsed.get("sweep_results")
    if isinstance(sweep_results, list):
        hint["sweep_results"] = sweep_results

    # ── Exception feedback ─────────────────────────────────────────
    exception_class = str(parsed.get("exception_class", "") or "")
    exception_msg = str(parsed.get("exception", "") or "")
    error_type_raw = str(parsed.get("error_type", "") or "")
    low_class = exception_class.lower()
    low_msg = exception_msg.lower()

    # Use JndiTarget's own error_type if available, else classify
    if error_type_raw and error_type_raw not in ("other", ""):
        error_type = error_type_raw
    elif exception_class or exception_msg:
        if "classnotfoundexception" in low_class or "noclassdeffounderror" in low_class:
            error_type = "class_not_found"
        elif "nosuchmethod" in low_class:
            error_type = "no_such_method"
        elif "securityexception" in low_class:
            error_type = "security_exception"
        elif "timeout" in low_class or "timed out" in low_msg:
            error_type = "timeout"
        elif "nosuitabledriver" in low_class or (
            "driver" in low_msg and "not found" in low_msg
        ):
            error_type = "driver_not_found"
        else:
            error_type = "other"
    else:
        error_type = ""

    if error_type:
        hint["error_type"] = error_type
    if exception_msg:
        hint["error_message"] = exception_msg
        hint["exception_class"] = exception_class
        hint["duration_ms"] = result.duration_ms

    return hint if hint else None


def _build_jdbc_sink_hint(result: ExecutionResult) -> dict[str, object] | None:
    """Extract JDBC sink attribution feedback from JdbcTarget output.

    Passes class_name_properties, class_load_trigger, and sink_attribution
    so the JDBC mutator's affinity DB can learn which (driver, property, class)
    combinations trigger class loading or reach sinks.
    """
    parsed = result.parsed_json()
    if not isinstance(parsed, dict):
        return None

    hint: dict[str, object] = {}

    # JdbcTarget uses camelCase (Gson default), normalize to snake_case
    cnp = parsed.get("classNameProperties") or parsed.get("class_name_properties")
    if isinstance(cnp, dict) and cnp:
        hint["class_name_properties"] = cnp

    clt = parsed.get("classLoadTrigger") or parsed.get("class_load_trigger")
    if clt:
        hint["class_load_trigger"] = str(clt)

    sa = parsed.get("sinkAttribution") or parsed.get("sink_attribution")
    if isinstance(sa, dict) and sa:
        hint["sink_attribution"] = sa

    # Driver identity for affinity DB routing
    driver = parsed.get("driver") or parsed.get("jdbcDriver")
    if driver:
        hint["driver"] = str(driver)

    # Standard exception info for C10 exception_guided
    exc = parsed.get("exceptionClass") or parsed.get("exception_class")
    if exc:
        hint["type"] = str(exc)
        hint["message"] = str(parsed.get("exception", ""))

    return hint if hint else None


def _build_sandbox_hint(result: ExecutionResult) -> dict[str, object] | None:
    """Extract sandbox escape feedback from target output."""
    parsed = result.parsed_json()
    if not isinstance(parsed, dict):
        return None
    hint: dict[str, object] = {}
    if parsed.get("escaped"):
        hint["escaped"] = True
        hint["payload"] = str(parsed.get("payload", ""))[:200]
    error_type = parsed.get("type")
    if error_type:
        hint["error_type"] = str(error_type)
    error_msg = parsed.get("error")
    if error_msg:
        hint["error_message"] = str(error_msg)[:200]
    return hint if hint else None


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
        danger_booster: DangerBooster | None = None,
        verify_browser: bool = False,
        max_corpus_size: int = 5000,
        target_coverage: bool = False,
        guidance_hooks: "GuidanceFuzzHooks | None" = None,
        concolic: "ConcolicCoordinator | None" = None,
    ):
        self.target = target
        self.reference_targets: list[Target] = reference_targets or []
        self.input_source = input_source
        self.mutators = mutators
        self.oracles = oracles
        self._concolic = concolic

        # Optionally wrap coverage with HybridCoverageCollector for
        # per-target code coverage augmentation.
        if target_coverage and coverage is not None:
            from .coverage.hybrid_coverage import HybridCoverageCollector
            self.coverage = HybridCoverageCollector(coverage, target_coverage_enabled=True)
        else:
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
        self._danger_booster = danger_booster
        self._max_corpus_size = max_corpus_size
        self._last_edge_count = 0
        self._edge_growth_window = 0  # tracks recent edge growth for dynamic sizing

        # Guidance hooks — static analysis → mutation bias + finding attribution
        self._guidance = guidance_hooks

        self._last_status_time = 0.0
        self._last_save_time = 0.0
        self._last_checkpoint_time = 0.0
        self._running = False
        self._resumed = False

        # Stall detection — track last iteration that produced a new finding.
        # After _STALL_WINDOW_ITERS with no findings, trigger weight shuffle.
        self._STALL_WINDOW_ITERS = 50_000
        self._last_finding_iter = 0
        self._stall_resets = 0
        # Deser pipeline diagnostics — per-stage counters for observability.
        # These are exposed in stats.deser_diag and printed in status/report.
        self._deser_total = 0
        self._deser_compiled = 0
        self._deser_deserialized = 0
        self._deser_sink_hits: dict[str, int] = {}     # sink_type → count
        self._deser_exceptions: dict[str, int] = {}    # exception_class → count
        self._deser_oracle_positive = 0                 # oracle said "finding"
        self._deser_oracle_deduped = 0                  # suppressed by dedup

        # Persistent target recycling — kill and restart child processes
        # periodically to prevent memory accumulation in Node/Ruby/Java.
        # Memory profiling showed RSS growing ~25MB/1K iters without this.
        self._RECYCLE_EVERY = 10_000
        self._total_target_execs = 0
        self._last_finding_metadata: list[dict] = []
        self._publisher = RedisPublisher()
        self._cmd_queue: queue.Queue[dict] = queue.Queue()

        # Browser verification queue (pub-sub)
        self._verify_queue = None
        self._verify_seen: set[str] = set()
        if verify_browser and output_dir:
            from .verification_queue import create_verification_queue
            self._verify_queue = create_verification_queue(output_dir)

        # Flat list of all targets for primary rotation in differential mode.
        # Round-robin rotation removes the fixed-primary bias: each target
        # takes turns as "primary" so differentials visible from any
        # parser's perspective get discovered.
        self.all_targets: list[Target] = [target] + list(self.reference_targets)
        self._rotation_idx: int = 0

        # Extract library names from target commands for guidance attribution.
        self._target_lib_names: list[str] = [
            self._extract_lib_name(t) for t in self.all_targets
        ]

        # Reusable thread pool for reference target execution (avoids
        # per-iteration ThreadPoolExecutor creation/teardown overhead).
        self._ref_pool: ThreadPoolExecutor | None = None

    def run(self) -> FuzzStats:
        """Execute the main fuzzing loop. Returns stats when done."""
        self._running = True
        self.stats = FuzzStats(output_dir=self.output_dir)
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
        except Exception:
            logger.exception("FuzzEngine crashed with unhandled exception")
            self._publisher.publish_status("failed")
            raise
        finally:
            self._save_checkpoint()
            self._cleanup()

        return self.stats

    def stop(self) -> None:
        """Signal the engine to stop after current iteration."""
        self._running = False

    # ── Internal phases ───────────────────────────────────────────

    def _setup(self) -> None:
        for i, t in enumerate(self.all_targets):
            t.setup()
            logger.info("Target [%d] set up", i)
        self._start_command_reader()
        logger.info("All %d targets set up successfully", len(self.all_targets))

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
                            primary, refs = self._rotate_primary()
                            result = self._execute_on(primary, inp)
                            ref_results = self._execute_on_refs(refs, inp)
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
            seed_files = sorted(f for f in self.seeds_dir.rglob("*") if f.is_file())
            logger.info("Loading %d seed files from %s", len(seed_files), self.seeds_dir)
            for sf in seed_files:
                if sf.is_file() and not sf.name.startswith("."):
                    try:
                        data = sf.read_bytes()
                        if data:
                            inp = Input(data=data)
                            primary, refs = self._rotate_primary()
                            result = self._execute_on(primary, inp)
                            # Track deser pipeline metrics during seed loading
                            if result.stdout:
                                try:
                                    _rj = json.loads(result.stdout)
                                    if isinstance(_rj, dict):
                                        self._track_deser_result(_rj)
                                except Exception:
                                    pass
                            ref_results = self._execute_on_refs(refs, inp)
                            cov = self._collect_coverage(inp, result, ref_results=ref_results)
                            self.corpus.force_add(inp, cov)
                            self._check_oracles(inp, result, mutator_name="file_seed", ref_results=ref_results)
                            self.stats.record_execution("file_seed")
                            file_seed_count += 1
                    except Exception as e:
                        logger.warning("Failed to load seed %s: %s", sf, e)

        # Seed validation summary — expose pipeline health immediately
        if self._deser_total > 0:
            self._sync_deser_diag()
            dd = self.stats.deser_diag
            logger.info(
                "Seed validation: %d seeds → compiled=%d (%.0f%%) → "
                "deserialized=%d (%.0f%%) | sinks=%s | findings=%d",
                dd["total"], dd["compiled"],
                dd["compiled"] / dd["total"] * 100 if dd["total"] else 0,
                dd["deserialized"],
                dd["deserialized"] / dd["total"] * 100 if dd["total"] else 0,
                dd.get("sink_hits", {}),
                self.stats.unique_findings,
            )
            # Print top exceptions so --add-opens issues are immediately visible
            exc = dd.get("exceptions_top5", [])
            if exc:
                for cls, cnt in exc[:3]:
                    logger.info("  Top exception: %s (%d seeds)", cls, cnt)

        # Phase 1.5: Inject guidance-targeted seeds + amplified variants.
        # Each targeted seed is injected raw, then mutated N times using
        # the domain mutator to produce ~20% of corpus as guidance seeds.
        guidance_seed_count = 0
        _GUIDANCE_TARGET_PCT = 0.20  # aim for 20% of initial corpus
        if self._guidance and self._guidance.active:
            targeted_seeds = self._guidance.get_targeted_seeds()

            # Determine how many variants to generate per seed
            guidance_budget = max(
                int(self.initial_seed_count * _GUIDANCE_TARGET_PCT),
                len(targeted_seeds),
            )
            variants_per_seed = max(guidance_budget // max(len(targeted_seeds), 1), 1)

            # Find the domain mutator for amplification
            domain_mutator = None
            for m in self.mutators:
                if hasattr(m, 'apply_guidance_weights'):
                    domain_mutator = m
                    break

            for seed_dict in targeted_seeds:
                try:
                    if hasattr(self.input_source, 'generate_from_fields'):
                        inp = self.input_source.generate_from_fields(seed_dict)
                    else:
                        data = json.dumps(seed_dict.get("fields", seed_dict)).encode("utf-8")
                        inp = Input(data=data, metadata={"guidance_seed": True})
                    # Inject the original seed
                    primary, refs = self._rotate_primary()
                    result = self._execute_on(primary, inp)
                    ref_results = self._execute_on_refs(refs, inp)
                    cov = self._collect_coverage(inp, result, ref_results=ref_results)
                    self.corpus.force_add(inp, cov)
                    self._check_oracles(inp, result, mutator_name="guidance_seed", ref_results=ref_results)
                    self.stats.record_execution("guidance_seed")
                    guidance_seed_count += 1

                    # Amplify: mutate this seed N times
                    if domain_mutator:
                        for _ in range(variants_per_seed - 1):
                            try:
                                mutated = domain_mutator.mutate(inp, None)
                                if mutated is None or mutated.data == inp.data:
                                    continue
                                mutated.metadata["guidance_seed"] = True
                                p2, r2 = self._rotate_primary()
                                res2 = self._execute_on(p2, mutated)
                                rr2 = self._execute_on_refs(r2, mutated)
                                cov2 = self._collect_coverage(mutated, res2, ref_results=rr2)
                                self.corpus.force_add(mutated, cov2)
                                self._check_oracles(mutated, res2, mutator_name="guidance_seed", ref_results=rr2)
                                self.stats.record_execution("guidance_seed")
                                guidance_seed_count += 1
                            except Exception:
                                pass  # variant generation is best-effort
                except Exception as e:
                    logger.warning("Failed to inject guidance seed: %s", e)
            if guidance_seed_count:
                logger.info("Injected %d guidance seeds (%d base + %d variants)",
                            guidance_seed_count, len(targeted_seeds),
                            guidance_seed_count - len(targeted_seeds))

            # Apply initial mutation weights from gap analysis
            weights = self._guidance.get_initial_weights()
            if weights:
                self._apply_guidance_weights(weights)

        # Phase 2: Fill remaining with grammar-generated seeds
        gen_count = max(0, self.initial_seed_count - file_seed_count - guidance_seed_count)
        logger.info("Generating %d initial seeds (%d from files, %d from guidance)...",
                     gen_count, file_seed_count, guidance_seed_count)

        for _ in range(gen_count):
            inp = self.input_source.generate()
            primary, refs = self._rotate_primary()
            result = self._execute_on(primary, inp)

            # Execute refs once, share results with coverage + oracles
            ref_results = self._execute_on_refs(refs, inp)
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

        # Drop per-seed 65KB coverage bitmaps after seeding — feature_set
        # and FeatureStore records are sufficient for all runtime operations.
        for s in self.corpus.seeds:
            s.coverage = None

        self.stats.update_corpus(
            len(self.corpus),
            self.corpus.total_bytes,
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
        _iter_errors = 0
        while self._running and not self._should_stop():
          try:
            self.stats.record_iteration()

            # 1. Select seed
            seed = self.seed_scheduler.select(self.corpus)
            seed.exec_count += 1
            seed.last_mutated_at = time.time()

            # 2. Select mutator
            mutator = self.mutator_scheduler.select(self.mutators, seed)
            # Override if scheduler picked an incompatible mutator (e.g.,
            # GrammarMutator for a tree-less file seed).  We override
            # post-selection rather than pre-filtering to avoid resetting
            # MOPT/DARWIN/LinUCB internal state (they re-init when k changes).
            if getattr(mutator, 'requires_tree', False) and 'tree' not in seed.input.metadata:
                compatible = [m for m in self.mutators if not getattr(m, 'requires_tree', False)]
                if compatible:
                    mutator = self.rng.choice(compatible)
            mutator_name = mutator.name

            # 3. Mutate
            mutated_input = mutator.mutate(seed.input, self.corpus.seeds)

            # 4. Execute with rotated primary
            primary, refs = self._rotate_primary()
            result = self._execute_on(primary, mutated_input)
            self.stats.record_execution(mutator_name)

            # Track per-strategy metrics (e.g., SAML mutator's 50 strategies)
            strategies = mutated_input.metadata.get("strategies", [])
            if strategies:
                self.stats.record_strategies(strategies)

            # 4.1. Queue for async browser verification (fire-and-forget)
            self._maybe_queue_for_browser(mutated_input, result)

            # 4.5. Execute refs once (cached for coverage + oracles)
            ref_results = self._execute_on_refs(refs, mutated_input)

            # 5. Collect coverage and check novelty
            is_novel = False
            new_edges: set[int] = set()
            child_danger = 0
            new_cov = None
            if self.coverage:
                new_cov = self._collect_coverage(mutated_input, result, ref_results=ref_results)
                child_danger = getattr(new_cov, 'danger_lvl', 0) if new_cov else 0
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
                        # Drop the 65KB bitmap clone — feature_set is
                        # sufficient for compaction/scheduling and
                        # FeatureStore holds raw data for CEGAR re-hash.
                        new_seed.coverage = None
                        new_edges = new_seed.feature_set
                        self.stats.record_new_coverage(
                            self.corpus.global_coverage.edge_count, mutator_name
                        )
                        if strategies:
                            self.stats.record_strategy_coverage(strategies)
                        self.stats.update_corpus(
                            len(self.corpus),
                            self.corpus.total_bytes,
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

            # 6.5 Finding-driven corpus injection
            # Novel finding + no new coverage → force-add so structural
            # patterns can be reused by future mutations.
            if found_crash and not is_novel and new_cov is not None:
                finding_seed = self.corpus.add_finding_seed(
                    mutated_input, new_cov,
                    parent_id=seed.id,
                    depth=seed.depth + 1,
                )
                if finding_seed:
                    finding_seed.coverage = None
                    self.stats.update_corpus(
                        len(self.corpus),
                        self.corpus.total_bytes,
                    )

            # 6.5c Concolic constraint extraction + targeted mutation
            if self._concolic is not None and ref_results:
                targeted = self._concolic.on_differential_result(
                    mutated_input, result, ref_results, found_crash,
                )
                for t_inp in targeted:
                    t_inp.metadata["mutator"] = "concolic"
                    primary_c, refs_c = self._rotate_primary()
                    t_result = self._execute_on(primary_c, t_inp)
                    t_ref_results = self._execute_on_refs(refs_c, t_inp)
                    t_cov = self._collect_coverage(
                        t_inp, t_result, ref_results=t_ref_results,
                    )
                    if self.coverage and t_cov:
                        t_novel = self.coverage.is_novel(
                            self.corpus.global_coverage, t_cov,
                        )
                        if t_novel:
                            t_seed = self.corpus.add(
                                t_inp, t_cov,
                                parent_id=seed.id,
                                depth=seed.depth + 1,
                            )
                            if t_seed:
                                t_seed.coverage = None
                                self.stats.record_new_coverage(
                                    self.corpus.global_coverage.edge_count,
                                    "concolic",
                                )
                    self._check_oracles(
                        t_inp, t_result, "concolic",
                        ref_results=t_ref_results,
                    )
                    self.stats.record_execution("concolic")
                    # Release targeted execution coverage bitmaps
                    t_result.metadata.pop("target_coverage", None)
                    for tr in (t_ref_results or []):
                        tr.metadata.pop("target_coverage", None)

                # Feed learned strategy weights back to mutator
                if hasattr(self._concolic, "get_strategy_weights"):
                    learned_weights = self._concolic.get_strategy_weights()
                    if learned_weights and hasattr(mutator, "apply_learned_weights"):
                        mutator.apply_learned_weights(learned_weights)

            # 6.6 Release coverage bitmaps to prevent memory growth
            # (16KB × num_targets per iteration; coverage + concolic already consumed)
            result.metadata.pop("target_coverage", None)
            if ref_results:
                for rr in ref_results:
                    rr.metadata.pop("target_coverage", None)

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

            # 7.4 Mutator strategy feedback (dynamic weight adjustment)
            # Signals: "finding" (highest), "stage_up" (danger escalation),
            #          "coverage" (new edges). Checked BEFORE DangerBooster
            #          updates _seed_max_danger so we can detect escalation.
            if strategies and hasattr(mutator, 'feedback'):
                _prev_max = (self._danger_booster._seed_max_danger.get(seed.id, 0)
                             if self._danger_booster else 0)
                if found_crash:
                    signal = "finding"
                elif child_danger > _prev_max:
                    signal = "stage_up"
                elif is_novel:
                    signal = "coverage"
                elif result.metadata.get("error_type") == "TimeoutError":
                    signal = "timeout"
                else:
                    signal = None
                if signal:
                    for sname in strategies:
                        mutator.feedback(sname, signal)

            # 7.4a Exception feedback for constraint-guided mutation (deser)
            if hasattr(mutator, 'set_exception_hint') and result.stdout:
                try:
                    import json as _json
                    _rj = _json.loads(result.stdout)
                    if isinstance(_rj, dict):
                        self._track_deser_result(_rj)
                        if (
                            not _rj.get("compiled", True)
                            or not _rj.get("deserialized", True)
                        ):
                            from .mutators.deser_feedback import parse_exception
                            _hint = parse_exception(_rj)
                            mutator.set_exception_hint(_hint)
                        else:
                            mutator.set_exception_hint(None)
                except Exception:
                    pass

            # 7.4b Stall detection — track last finding iteration
            if getattr(mutator, "name", "") == "jndi" and hasattr(mutator, 'set_exception_hint'):
                mutator.set_exception_hint(_build_jndi_exception_hint(result))

            if getattr(mutator, "name", "") == "jdbc" and hasattr(mutator, 'set_exception_hint'):
                mutator.set_exception_hint(_build_jdbc_sink_hint(result))

            if getattr(mutator, "name", "") == "sandbox" and hasattr(mutator, 'set_exception_hint'):
                mutator.set_exception_hint(_build_sandbox_hint(result))

            if found_crash:
                self._last_finding_iter = self.stats.total_iterations
            iters_since_finding = self.stats.total_iterations - self._last_finding_iter
            if (iters_since_finding > 0
                    and iters_since_finding % self._STALL_WINDOW_ITERS == 0):
                self._stall_resets += 1
                logger.warning(
                    "STALL: %d iters since last finding (reset #%d) — "
                    "shuffling mutator weights",
                    iters_since_finding, self._stall_resets,
                )
                # Reset dynamic weights on all mutators that support it
                for m in self.mutators:
                    if hasattr(m, 'reset_weights'):
                        m.reset_weights(boost_zero_finds=True)

            # 7.4c Guidance iteration + weight refresh
            if self._guidance and self._guidance.active:
                self._guidance.on_iteration()
                if self._guidance.should_refresh_weights():
                    weights = self._guidance.get_current_weights()
                    if weights:
                        self._apply_guidance_weights(weights)

            # 7.5 Danger-weighted priority boost
            if self._danger_booster and child_danger >= 2:
                self._danger_booster.on_execution(seed, child_danger, self.corpus)

            # 7.6 MCTS feedback: backpropagate to grammar UCB1 table
            if hasattr(self.input_source, 'update') and (is_novel or found_crash):
                self.input_source.update(mutated_input, schedule_result)

            # 7.6 CEGAR adaptive coverage check
            _inner_cov = getattr(self.coverage, 'inner', self.coverage)
            if isinstance(_inner_cov, AdaptiveDiffCoverage):
                self.coverage.notify_execution()
                if is_novel:
                    self.coverage.notify_new_coverage(self.stats.total_iterations)
                if self.coverage.check_and_adapt(self.corpus):
                    self.stats.update_corpus(
                        len(self.corpus),
                        self.corpus.total_bytes,
                    )
                    self.stats.record_new_coverage(
                        self.corpus.global_coverage.edge_count,
                    )

            # 8. Process external commands (priority adjustments etc.)
            self._process_commands()

            # 9. Periodic danger boost decay (every 2K iterations)
            if self._danger_booster and self.stats.total_iterations % 2000 == 0:
                self._danger_booster.apply_decay(self.corpus)

            # 10. Periodic corpus compaction (every 5K iterations or size cap)
            #     Dynamic sizing: if coverage is still growing, allow larger corpus
            max_cap = self._max_corpus_size
            if self.stats.total_iterations % 5000 == 0 and hasattr(self.corpus, 'global_coverage'):
                cur_edges = self.corpus.global_coverage.edge_count
                if cur_edges > self._last_edge_count:
                    self._edge_growth_window = min(self._edge_growth_window + 1, 5)
                    self._last_edge_count = cur_edges
                else:
                    self._edge_growth_window = max(self._edge_growth_window - 1, 0)
                # Allow up to 2x max when actively discovering new coverage
                if self._edge_growth_window >= 3:
                    max_cap = self._max_corpus_size * 2
            if (self.stats.total_iterations % 5000 == 0 or len(self.corpus) > max_cap) and len(self.corpus) > 200:
                removed_ids = self.corpus.compact(min_seeds=100, max_seeds=max_cap)
                if removed_ids:
                    # Clean up FeatureStore entries for removed seeds
                    _cov_inner = getattr(self.coverage, 'inner', self.coverage)
                    if isinstance(_cov_inner, AdaptiveDiffCoverage):
                        for sid in removed_ids:
                            _cov_inner._feature_store.remove(sid)
                    if self._danger_booster:
                        self._danger_booster.cleanup_removed(removed_ids)
                    if hasattr(self.seed_scheduler, 'cleanup_removed'):
                        self.seed_scheduler.cleanup_removed(removed_ids)
                    logger.info(
                        "Corpus compacted: %d seeds removed, %d remaining",
                        len(removed_ids), len(self.corpus),
                    )
                    self.stats.update_corpus(
                        len(self.corpus),
                        self.corpus.total_bytes,
                    )

            # 10.5. Periodic persistent target recycling
            # Node/Ruby/Java child processes accumulate memory over tens of
            # thousands of executions.  Recycle them to reset RSS.
            self._total_target_execs += 1 + (len(refs) if ref_results else 0)
            if self._total_target_execs >= self._RECYCLE_EVERY:
                self._recycle_persistent_targets()
                self._total_target_execs = 0

            # 11. Status output + periodic checkpoint
            self._maybe_print_status()
            self._maybe_save_checkpoint()
          except KeyboardInterrupt:
            raise
          except Exception:
            _iter_errors += 1
            if _iter_errors <= 5 or _iter_errors % 100 == 0:
                logger.exception(
                    "Iteration error #%d at exec %d (continuing)",
                    _iter_errors, self.stats.total_executions,
                )
            if _iter_errors >= 500:
                logger.error("Too many iteration errors (%d), stopping", _iter_errors)
                break

    def _collect_coverage(
        self, inp: Input, result: ExecutionResult,
        ref_results: list[ExecutionResult] | None = None,
    ) -> CoverageMap | None:
        """Collect coverage, dispatching to diff/adaptive coverage if applicable."""
        if self.coverage is None:
            return None

        # Unwrap HybridCoverageCollector to check inner type.
        from .coverage.hybrid_coverage import HybridCoverageCollector
        inner = self.coverage.inner if isinstance(self.coverage, HybridCoverageCollector) else self.coverage

        if isinstance(inner, AdaptiveDiffCoverage):
            seed_id = self.corpus._next_id
            return self.coverage.collect_diff(
                inp, result, ref_results=ref_results, seed_id=seed_id,
            )
        if isinstance(inner, DiffCoverageCollector):
            return self.coverage.collect_diff(inp, result, ref_results=ref_results)
        return self.coverage.collect(result)

    # ── Browser verification queue ────────────────────────────────

    def _maybe_queue_for_browser(self, inp: Input, result: ExecutionResult) -> None:
        """Queue interesting inputs for async browser verification."""
        if self._verify_queue is None or not result.stdout:
            return
        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if not self._is_browser_interesting(data):
            return

        input_hash = hashlib.md5(inp.data).hexdigest()
        if input_hash in self._verify_seen:
            return
        self._verify_seen.add(input_hash)
        # Cap to prevent unbounded set growth
        if len(self._verify_seen) > 10_000:
            self._verify_seen.clear()

        from .verification_queue import VerificationItem

        reason = self._get_trigger_reason(data)
        item = VerificationItem(
            id=input_hash[:16],
            input_data=inp.data,
            jsdom_sanitized=data.get("sanitized", ""),
            trigger_reason=reason,
            metadata={
                k: data.get(k)
                for k in (
                    "mxss_security",
                    "danger_escalation",
                    "max_depth",
                    "new_elements_after_reparse",
                )
            },
            session_output_dir=str(self.output_dir) if self.output_dir else "",
            iteration=self.stats.total_iterations,
        )
        try:
            self._verify_queue.push(item)
        except Exception as e:
            logger.debug("Failed to queue for browser verify: %s", e)

    @staticmethod
    def _is_browser_interesting(data: dict) -> bool:
        if data.get("mxss_security"):
            return True
        if data.get("danger_escalation"):
            return True
        if any(
            data.get(k)
            for k in (
                "near_miss_img",
                "near_miss_a_href",
                "near_miss_style",
                "near_miss_form",
                "near_miss_svg",
                "near_miss_math",
            )
        ):
            return True
        if data.get("new_elements_after_reparse"):
            return True
        if (data.get("max_depth") or 0) >= 400:
            return True
        return False

    @staticmethod
    def _get_trigger_reason(data: dict) -> str:
        if data.get("danger_escalation"):
            return "danger_escalation"
        if data.get("mxss_security"):
            return "mxss_security"
        if (data.get("max_depth") or 0) >= 400:
            return "depth_400+"
        if data.get("new_elements_after_reparse"):
            return "new_elements"
        return "near_miss"

    # ── Primary rotation ─────────────────────────────────────────

    def _rotate_primary(self) -> tuple[Target, list[Target]]:
        """Select next primary target via round-robin.

        Returns (primary, refs) where refs is all other targets.
        Each call advances the rotation counter, so every target gets
        equal time as primary.  In non-differential mode (single target)
        this always returns (target, []).
        """
        idx = self._rotation_idx % len(self.all_targets)
        self._rotation_idx += 1
        primary = self.all_targets[idx]
        refs = [t for i, t in enumerate(self.all_targets) if i != idx]
        return primary, refs

    # ── Execution helpers ──────────────────────────────────────

    def _execute_on(self, target: Target, inp: Input) -> ExecutionResult:
        """Execute input against a specific target, handling crashes."""
        start = time.time()
        try:
            result = target.execute(inp)
        except Exception as e:
            result = ExecutionResult(
                exit_code=-1,
                stderr=str(e).encode("utf-8", errors="replace"),
            )

        if result.duration_ms == 0:
            result.duration_ms = (time.time() - start) * 1000

        # Check target health
        if not target.is_alive():
            error_detail = result.metadata.get("error_type", "unknown")
            logger.warning(
                "Target died (%s), resetting... input_len=%d duration=%.0fms stderr=%s",
                error_detail, len(inp.data), result.duration_ms,
                result.stderr[:120].decode("utf-8", errors="replace") if result.stderr else "",
            )
            try:
                target.teardown()
            except Exception:
                pass
            target.setup()

        return result

    def _execute_on_refs(self, refs: list[Target], inp: Input) -> list[ExecutionResult] | None:
        """Execute input against specified reference targets (parallel)."""
        if not refs:
            return None

        def _run(target: Target) -> ExecutionResult:
            try:
                return target.execute(inp)
            except Exception as e:
                return ExecutionResult(
                    exit_code=-999,
                    stderr=str(e).encode("utf-8", errors="replace"),
                )

        if len(refs) == 1:
            return [_run(refs[0])]

        if self._ref_pool is None:
            self._ref_pool = ThreadPoolExecutor(
                max_workers=max(len(self.all_targets) - 1, 1),
            )
        return list(self._ref_pool.map(_run, refs))

    def _execute(self, inp: Input) -> ExecutionResult:
        """Execute input against the fixed primary target (backward compat)."""
        return self._execute_on(self.target, inp)

    def _execute_references(self, inp: Input) -> list[ExecutionResult] | None:
        """Execute input against all reference targets (backward compat).

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

        return self._execute_on_refs(self.reference_targets, inp)

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
                # Track which target was primary for this finding (analysis use,
                # not included in fingerprint to avoid over-deduplication).
                primary_idx = (self._rotation_idx - 1) % len(self.all_targets)
                finding.metadata["primary_idx"] = primary_idx
                # Translate relative ref_index to absolute target index so
                # MAP-Elites archive cells have stable meaning across primary
                # rotations (ref_index=0 means the same parser every time).
                rel_ri = finding.metadata.get("ref_index")
                if rel_ri is not None and len(self.all_targets) > 1:
                    # refs = all_targets minus primary, in order
                    abs_indices = [i for i in range(len(self.all_targets)) if i != primary_idx]
                    if rel_ri < len(abs_indices):
                        finding.metadata["ref_index"] = abs_indices[rel_ri]
                # Inject library names for guidance attribution.
                if self._target_lib_names and len(self.all_targets) > 1:
                    md = finding.metadata
                    p_idx = md.get("primary_idx", primary_idx)
                    r_idx = md.get("ref_index")
                    p_name = self._target_lib_names[p_idx] if p_idx < len(self._target_lib_names) else ""
                    r_name = self._target_lib_names[r_idx] if r_idx is not None and r_idx < len(self._target_lib_names) else ""

                    # Determine accepting/rejecting from available fields
                    accepting_side = md.get("accepting_side")
                    if accepting_side and r_idx is not None:
                        if accepting_side == "primary":
                            md["accepting_libraries"] = [p_name]
                            md["rejecting_libraries"] = [r_name]
                        else:
                            md["accepting_libraries"] = [r_name]
                            md["rejecting_libraries"] = [p_name]
                    elif r_idx is not None:
                        # SAML diff strategy: primary_valid/ref_valid fields
                        p_valid = md.get("primary_valid")
                        r_valid = md.get("ref_valid")
                        if p_valid is True and r_valid is False:
                            md["accepting_libraries"] = [p_name]
                            md["rejecting_libraries"] = [r_name]
                        elif r_valid is True and p_valid is False:
                            md["accepting_libraries"] = [r_name]
                            md["rejecting_libraries"] = [p_name]

                finding.fingerprint = self.deduplicator.fingerprint(finding)
                if finding.oracle_name == "deser":
                    self._deser_oracle_positive += 1
                if not self.deduplicator.is_duplicate(finding):
                    self.deduplicator.register(finding)
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
                    # Enrich finding with guidance gap attribution
                    if self._guidance and self._guidance.active:
                        finding.metadata = self._guidance.on_finding(finding.metadata)
                    logger.info(
                        "Finding: [%s] %s (oracle=%s)",
                        finding.severity.value, finding.title, finding.oracle_name,
                    )
                    # record_finding strips heavy data after incremental save
                    self.stats.record_finding(finding, mutator_name)
                    # Collect metadata for MAP-Elites scheduler.
                    self._last_finding_metadata.append({
                        "category": finding.metadata.get("category", ""),
                        "ref_index": finding.metadata.get("ref_index", 0),
                        "severity": finding.severity.value,
                        "strategy": finding.metadata.get("strategy", ""),
                    })
                    found = True
        return found

    def _recycle_persistent_targets(self) -> None:
        """Kill and restart all persistent target child processes.

        Prevents memory accumulation in long-running Node/Ruby/Java
        processes.  Each target's reset() calls teardown() + setup(),
        which kills the old process tree and spawns a fresh one.
        """
        from .targets.persistent_target import PersistentTarget

        recycled = 0
        for t in self.all_targets:
            if isinstance(t, PersistentTarget):
                try:
                    t.reset()
                    recycled += 1
                except Exception as e:
                    logger.warning("Failed to recycle target %s: %s",
                                   t.command[:60], e)
        if recycled:
            import gc
            import sys as _sys
            gc.collect()
            msg = (
                f"[recycle] {recycled} targets recycled at "
                f"exec={self.stats.total_executions}"
            )
            logger.info(msg)
            print(msg, file=_sys.stderr, flush=True)

    def _apply_guidance_weights(self, weights: dict[str, float]) -> None:
        """Apply guidance mutation weights to compatible mutators.

        Guidance weights are field-level biases (e.g. {"header.crit": 1.0,
        "header.alg": 0.3}).  Mutators that support `apply_guidance_weights()`
        can translate these into strategy-level weight adjustments.
        """
        applied = False
        for m in self.mutators:
            if hasattr(m, 'apply_guidance_weights'):
                m.apply_guidance_weights(weights)
                applied = True
        if applied:
            logger.info(
                "Guidance weights applied: %d fields → %s",
                len(weights),
                ", ".join(f"{k}={v:.1f}" for k, v in
                          sorted(weights.items(), key=lambda x: -x[1])[:5]),
            )

    @staticmethod
    def _extract_lib_name(target: "Target") -> str:
        """Extract a library name from a target's command string.

        Examples:
            'python targets/saml_signxml.py {input}' → 'signxml'
            'node targets/jwt_node_jose4.js {input}'  → 'jose4'
            'targets/saml_crewjam/saml_crewjam.exe --persistent' → 'crewjam'
        """
        import re as _re
        # Prefer original_cmd (set by CLI) over persistent wrapper command
        cmd = getattr(target, 'original_cmd', None) \
            or getattr(target, 'command_template', None) \
            or getattr(target, 'command', '')
        # Find the target script in the command
        m = _re.search(r'targets/(\w+)', cmd)
        if m:
            script = m.group(1)
            # Strip common prefixes and suffixes
            for pfx in ('saml_', 'jwt_', 'oauth_', 'cookie_', 'sanitizer_',
                        'markdown_', 'graphql_', 'deser_', 'dpop_',
                        'jwt_node_', 'jwt_python_'):
                if script.startswith(pfx):
                    script = script[len(pfx):]
                    break
            # Strip _module, _diff, _mxss suffixes
            for sfx in ('_module', '_diff', '_mxss', '_exec'):
                if script.endswith(sfx):
                    script = script[:-len(sfx)]
            return script
        # Fallback: last path component without extension
        parts = cmd.replace('\\', '/').split()
        for part in parts:
            if 'target' in part.lower():
                return part.rsplit('/', 1)[-1].split('.')[0]
        return cmd[:30]

    def _should_stop(self) -> bool:
        if self.max_iterations and self.stats.total_iterations >= self.max_iterations:
            return True
        if self.max_time_seconds and self.stats.elapsed() >= self.max_time_seconds:
            return True
        if not self.corpus.seeds:
            return True
        return False

    def _track_deser_result(self, rj: dict) -> None:
        """Update deser pipeline counters from a parsed JSON result."""
        if "compiled" not in rj:
            return
        self._deser_total += 1
        if rj.get("compiled"):
            self._deser_compiled += 1
        else:
            exc_cls = rj.get("exception_class", "unknown")
            self._deser_exceptions[exc_cls] = (
                self._deser_exceptions.get(exc_cls, 0) + 1)
        if rj.get("deserialized"):
            self._deser_deserialized += 1
            for _sk in (rj.get("sinks_hit") or []):
                if isinstance(_sk, str):
                    self._deser_sink_hits[_sk] = (
                        self._deser_sink_hits.get(_sk, 0) + 1)
            _sr = rj.get("sink_reached")
            if isinstance(_sr, str) and _sr:
                self._deser_sink_hits[_sr] = (
                    self._deser_sink_hits.get(_sr, 0) + 1)

    def _sync_deser_diag(self) -> None:
        """Push deser pipeline counters into stats for reporting."""
        if self._deser_total == 0:
            return
        exc_sorted = sorted(self._deser_exceptions.items(), key=lambda x: -x[1])
        self.stats.deser_diag = {
            "total": self._deser_total,
            "compiled": self._deser_compiled,
            "deserialized": self._deser_deserialized,
            "sink_hits": dict(self._deser_sink_hits),
            "exceptions_top5": exc_sorted[:5],
            "oracle_positive": self._deser_oracle_positive,
            "oracle_deduped": self._deser_oracle_positive - self.stats.unique_findings,
        }

    def _maybe_print_status(self) -> None:
        now = time.time()
        if now - self._last_status_time >= self.status_interval:
            self._last_status_time = now
            self._sync_deser_diag()
            guidance_status = ""
            if self._guidance and self._guidance.active:
                guidance_status = self._guidance.get_status_line()
            status = self.stats.status_line()
            if guidance_status:
                status = f"{status} | G:{guidance_status}"
            if self._concolic is not None:
                status = f"{status} | {self._concolic.get_status_line()}"
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
                report_text = self.stats.report("json")
                # Inject guidance section if active
                if self._guidance and self._guidance.active:
                    guidance_report = self._guidance.get_report_section()
                    if guidance_report:
                        try:
                            report_data = json.loads(report_text)
                            report_data["guidance"] = guidance_report
                            report_text = json.dumps(report_data, indent=2)
                        except Exception:
                            pass
                if self._concolic is not None:
                    try:
                        report_data = json.loads(report_text)
                        report_data["concolic"] = self._concolic.get_stats()
                        report_text = json.dumps(report_data, indent=2)
                    except Exception:
                        pass
                (self.output_dir / "report.json").write_text(
                    report_text, encoding="utf-8",
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
        for t in self.all_targets:
            try:
                t.teardown()
            except Exception:
                pass

        if self.output_dir:
            try:
                self.stats.save(self.output_dir)
                # Re-inject guidance section into final report.json
                if self._guidance and self._guidance.active:
                    rpath = self.output_dir / "report.json"
                    if rpath.exists():
                        try:
                            report_data = json.loads(rpath.read_text(encoding="utf-8"))
                            guidance_report = self._guidance.get_report_section()
                            if guidance_report:
                                report_data["guidance"] = guidance_report
                                rpath.write_text(
                                    json.dumps(report_data, indent=2),
                                    encoding="utf-8",
                                )
                        except Exception:
                            pass
            except Exception as e:
                logger.error("Failed to save stats: %s", e)
            try:
                self.corpus.save(self.output_dir / "corpus")
            except Exception as e:
                logger.error("Failed to save corpus: %s", e)
            else:
                logger.info("Results saved to %s", self.output_dir)

        if self._verify_queue:
            self._verify_queue.close()

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
    """Weighted random mutator selection."""

    def __init__(self, rng: random.Random, weights: list[float] | None = None) -> None:
        self.rng = rng
        self._weights = weights

    def select(self, mutators: list[Mutator], seed: Seed) -> Mutator:
        w = self._weights
        if w and len(w) == len(mutators):
            return self.rng.choices(mutators, weights=w, k=1)[0]
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

    # Keys whose values define the semantic identity of a differential
    # finding — used instead of ref_index so that the same divergence
    # detected across multiple reference targets deduplicates to one.
    #
    # IMPORTANT: Only include CATEGORICAL identifiers that distinguish
    # truly different classes of bugs.  Per-input values (domains, paths,
    # versions, counts, flag booleans, raw cookie names) change with
    # every mutation and cause finding explosion (3000+ in 30s).
    #
    # The fingerprint uses:
    #   1. oracle_name, severity, exit_code, strategy, category
    #   2. accepting_side: primary-accepts vs ref-accepts
    #   3. name_class: normalized cookie name bucket (not raw name)
    #      → $Version, __Host-*, __Secure-*, _other_
    #   4. ref_index fallback for non-differential oracles
    _DIFF_VALUE_KEYS = (
        "accepting_side",
        "mechanism",
        "reject_reason",
    )

    # Known security-relevant cookie name patterns → bucket tag.
    # Raw names from havoc (random bytes) all map to "_other_".
    _NAME_CLASS_PATTERNS = (
        ("$version", "$version"),
        ("__host-", "__host_prefix"),
        ("__secure-", "__secure_prefix"),
    )

    @classmethod
    def _name_class(cls, raw: str) -> str:
        """Normalize a cookie name to a security-relevant bucket."""
        low = raw.lower().strip()
        for prefix, tag in cls._NAME_CLASS_PATTERNS:
            if low.startswith(prefix) or low == prefix.rstrip("-"):
                return tag
        return "_other_"

    def fingerprint(self, finding: Finding) -> str:
        meta = finding.metadata or {}

        # ── Coverage-based dedup ──
        # If the oracle provides a diff_pattern_hash (computed from the
        # actual divergence pattern across all refs), use it as the
        # primary fingerprint.  This is data-driven: same root cause
        # (same set of refs diverging on same fields) → same fingerprint,
        # regardless of how many metadata labels exist.
        dph = meta.get("diff_pattern_hash")
        if dph:
            parts = [
                finding.oracle_name,
                meta.get("strategy", ""),
                meta.get("category", ""),
                dph,
            ]
            # Cookie name bucket — still needed so different cookie
            # name classes don't collapse
            raw_name = (
                meta.get("cookie_name")
                or meta.get("parsed_name")
                or meta.get("primary_name")
                or meta.get("ref_name")
                or ""
            )
            if raw_name:
                parts.append(f"nc={self._name_class(str(raw_name))}")
            # Bypass signal for mXSS (has_script vs has_event_handler)
            sig = meta.get("signal")
            if sig:
                parts.append(f"sig={sig}")
            return "|".join(parts)

        # ── Fallback: non-differential oracles (mXSS, SSRF, etc.) ──
        parts = [
            finding.oracle_name,
            finding.severity.value,
            str(finding.result.exit_code),
            meta.get("strategy", ""),
            meta.get("category", ""),
        ]

        diff_sig = []
        for key in self._DIFF_VALUE_KEYS:
            v = meta.get(key)
            if v is not None:
                diff_sig.append(f"{key}={v}")

        raw_name = (
            meta.get("cookie_name")
            or meta.get("parsed_name")
            or meta.get("primary_name")
            or meta.get("ref_name")
            or ""
        )
        if raw_name:
            nc = self._name_class(str(raw_name))
            diff_sig.append(f"nc={nc}")

        affected = meta.get("affected_refs")
        if affected and isinstance(affected, list):
            diff_sig.append(f"refs={'_'.join(str(r) for r in sorted(affected))}")
        elif meta.get("ref_index") is not None:
            diff_sig.append(f"refs={meta['ref_index']}")

        if diff_sig:
            parts.append(";".join(diff_sig))

        df = meta.get("diff_fields")
        if df:
            parts.append(",".join(sorted(df)))

        op = meta.get("only_primary")
        orr = meta.get("only_ref")
        if op:
            parts.append(f"op={','.join(sorted(op))}")
        if orr:
            parts.append(f"or={','.join(sorted(orr))}")

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
