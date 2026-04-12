"""FuzzEngine — main fuzzing loop.

Assembles all pluggable components and runs the generate-execute-evaluate loop.
Every component is injected via Protocol interfaces — swap any part freely.
"""

from __future__ import annotations

import logging
import os
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from pathlib import Path
from .corpus import Corpus, CoverageMap, Seed
from .browser_queueing import BrowserVerificationService
from .checkpointing import CheckpointService
from .command_channel import CommandChannel
from .coverage.diff_coverage import DiffCoverageCollector
from .coverage.adaptive_coverage import AdaptiveDiffCoverage
from .finding_pipeline import FindingProcessor, extract_lib_name
from .maintenance import RuntimeMaintenanceService
from .runtime_reporting import RuntimeReportingService
from .seeding import SeedingService
from .protocols import (
    CoverageCollector,
    Deduplicator,
    ExceptionHintMutator,
    ExecutionResult,
    Finding,
    Input,
    InputSource,
    Mutator,
    MutatorScheduler,
    Oracle,
    ScheduleResult,
    SeedScheduler,
    StrategyFeedbackMutator,
    StrategyWeightProvider,
    Target,
    LearnedWeightMutator,
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
        fixed_primary: bool = False,
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
        self._verify_browser_enabled = verify_browser

        # Use defaults if not provided
        self.seed_scheduler: SeedScheduler = seed_scheduler or _DefaultSeedScheduler(self.rng)
        self.mutator_scheduler: MutatorScheduler = mutator_scheduler or _DefaultMutatorScheduler(self.rng)
        self.deduplicator: Deduplicator = deduplicator or _DefaultDeduplicator()
        self._danger_booster = danger_booster
        self._max_corpus_size = max_corpus_size

        # Guidance hooks — static analysis → mutation bias + finding attribution
        self._guidance = guidance_hooks

        self._last_status_time = 0.0
        self._last_save_time = 0.0
        self._last_checkpoint_time = 0.0
        self._running = False
        self._resumed = False

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
        self._last_finding_metadata: list[dict] = []
        self._publisher = RedisPublisher()
        self._command_channel = CommandChannel(
            corpus=self.corpus,
            publisher=self._publisher,
        )

        # Flat list of all targets for primary rotation in differential mode.
        # Round-robin rotation removes the fixed-primary bias: each target
        # takes turns as "primary" so differentials visible from any
        # parser's perspective get discovered.
        # Exception: WAF bypass and similar asymmetric campaigns use
        # fixed_primary=True to keep all_targets[0] as primary always.
        self.all_targets: list[Target] = [target] + list(self.reference_targets)
        self._rotation_idx: int = 0
        self._fixed_primary: bool = fixed_primary

        # Extract library names from target commands for guidance attribution.
        self._target_lib_names: list[str] = [
            extract_lib_name(t) for t in self.all_targets
        ]
        self._bind_runtime_services()

        # Reusable thread pool for reference target execution (avoids
        # per-iteration ThreadPoolExecutor creation/teardown overhead).
        self._ref_pool: ThreadPoolExecutor | None = None

    def run(self) -> FuzzStats:
        """Execute the main fuzzing loop. Returns stats when done."""
        self._running = True
        self.stats = FuzzStats(output_dir=self.output_dir)
        self._bind_runtime_services()
        self._publisher.publish_status("started")

        try:
            self._setup()
            if self.resume and self._checkpoint_service.load():
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
            self._checkpoint_service.save()
            self._cleanup()

        return self.stats

    def stop(self) -> None:
        """Signal the engine to stop after current iteration."""
        self._running = False

    # ── Internal phases ───────────────────────────────────────────

    def _bind_runtime_services(self) -> None:
        """Recreate services that hold a direct reference to the active stats."""
        self._browser_verification = BrowserVerificationService(
            enabled=self._verify_browser_enabled,
            output_dir=self.output_dir,
            stats=self.stats,
        )
        # Phase 2C: build violation_sink if output_dir is set and at least
        # one oracle exposes drain_violations (ImplicationSoftOracle).
        _vsink = None
        if self.output_dir is not None and any(
            hasattr(o, "drain_violations") for o in self.oracles
        ):
            from .finding_pipeline import make_jsonl_violation_sink
            _vsink = make_jsonl_violation_sink(
                self.output_dir / "violations.jsonl"
            )
        self._finding_processor = FindingProcessor(
            oracles=self.oracles,
            deduplicator=self.deduplicator,
            publisher=self._publisher,
            stats=self.stats,
            guidance_hooks=self._guidance,
            all_targets=self.all_targets,
            target_lib_names=self._target_lib_names,
            violation_sink=_vsink,
        )
        self._runtime_reporting = RuntimeReportingService(
            stats=self.stats,
            publisher=self._publisher,
            output_dir=self.output_dir,
            guidance_hooks=self._guidance,
            concolic=self._concolic,
            corpus=self.corpus,
            verify_queue=self._browser_verification.queue,
            all_targets=self.all_targets,
            running_getter=lambda: self._running,
            sync_deser_diag=self._sync_deser_diag,
        )
        _adaptive_cov = self.coverage if isinstance(self.coverage, AdaptiveDiffCoverage) else None
        self._checkpoint_service = CheckpointService(
            output_dir=self.output_dir,
            corpus=self.corpus,
            stats=self.stats,
            rng=self.rng,
            dedup_exporter=self._export_dedup_seen,
            dedup_importer=self._import_dedup_seen,
            adaptive_coverage=_adaptive_cov,
        )
        self._maintenance = RuntimeMaintenanceService(
            corpus=self.corpus,
            coverage=self.coverage,
            stats=self.stats,
            mutators=self.mutators,
            input_source=self.input_source,
            seed_scheduler=self.seed_scheduler,
            danger_booster=self._danger_booster,
            guidance_hooks=self._guidance,
            all_targets=self.all_targets,
            max_corpus_size=self._max_corpus_size,
        )

    def _setup(self) -> None:
        for i, t in enumerate(self.all_targets):
            t.setup()
            logger.info("Target [%d] set up", i)
        self._command_channel.start_reader()
        logger.info("All %d targets set up successfully", len(self.all_targets))

    def _seed_corpus(self) -> None:
        """Generate initial seeds and populate the corpus."""
        SeedingService(
            corpus=self.corpus,
            coverage=self.coverage,
            input_source=self.input_source,
            mutators=self.mutators,
            stats=self.stats,
            publisher=self._publisher,
            guidance_hooks=self._guidance,
            initial_seed_count=self.initial_seed_count,
            seeds_dir=self.seeds_dir,
            import_findings=self.import_findings,
            rotate_primary=self._rotate_primary,
            execute_on=self._execute_on,
            execute_on_refs=self._execute_on_refs,
            collect_coverage=self._collect_coverage,
            check_oracles=self._check_oracles,
            apply_guidance_weights=self._maintenance.apply_guidance_weights,
            track_deser_result=self._track_deser_result,
            sync_deser_diag=self._sync_deser_diag,
        ).run()

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
            result, ref_results = self._execute_primary_and_refs(
                primary, refs, mutated_input
            )
            self.stats.record_execution(mutator_name)

            # Track per-strategy metrics (e.g., SAML mutator's 50 strategies)
            strategies = mutated_input.metadata.get("strategies", [])
            if strategies:
                self.stats.record_strategies(strategies)

            # 4.1. Queue for async browser verification (fire-and-forget)
            self._browser_verification.maybe_queue(mutated_input, result)

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

                # Feed learned strategy weights back to mutator.
                # Phase 2B: pass pareto_alpha from the stopping signal so
                # heavy-tail (α<2) campaigns use median normalisation.
                if isinstance(self._concolic, StrategyWeightProvider):
                    learned_weights = self._concolic.get_strategy_weights()
                    if learned_weights and isinstance(mutator, LearnedWeightMutator):
                        _ss = getattr(self.seed_scheduler, "_stopping_signal", None)
                        _alpha = getattr(_ss, "pareto_alpha", None)
                        mutator.apply_learned_weights(learned_weights, alpha=_alpha)

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
                diff_pattern_hashes=list(
                    result.metadata.get("diff_pattern_hashes") or ()
                ),
            )
            self.seed_scheduler.update(seed, schedule_result)
            self.mutator_scheduler.update(mutator, schedule_result)

            # 7.4 Mutator strategy feedback (dynamic weight adjustment)
            # Signals: "finding" (highest), "stage_up" (danger escalation),
            #          "coverage" (new edges). Checked BEFORE DangerBooster
            #          updates _seed_max_danger so we can detect escalation.
            if strategies and isinstance(mutator, StrategyFeedbackMutator):
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
            if isinstance(mutator, ExceptionHintMutator) and result.stdout:
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

            # 7.4b Domain-specific exception feedback
            if (
                getattr(mutator, "name", "") == "jndi"
                and isinstance(mutator, ExceptionHintMutator)
            ):
                mutator.set_exception_hint(_build_jndi_exception_hint(result))

            if (
                getattr(mutator, "name", "") == "jdbc"
                and isinstance(mutator, ExceptionHintMutator)
            ):
                mutator.set_exception_hint(_build_jdbc_sink_hint(result))

            if (
                getattr(mutator, "name", "") == "sandbox"
                and isinstance(mutator, ExceptionHintMutator)
            ):
                mutator.set_exception_hint(_build_sandbox_hint(result))

            self._maintenance.handle_feedback(
                seed=seed,
                mutated_input=mutated_input,
                schedule_result=schedule_result,
                is_novel=is_novel,
                found_crash=found_crash,
                child_danger=child_danger,
            )

            # 8. Process external commands (priority adjustments etc.)
            self._command_channel.process_pending()

            self._maintenance.handle_periodic_maintenance(
                ref_result_count=len(ref_results) if ref_results else 0,
            )

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



    # ── Primary rotation ─────────────────────────────────────────

    def _rotate_primary(self) -> tuple[Target, list[Target]]:
        """Select next primary target via round-robin.

        Returns (primary, refs) where refs is all other targets.
        Each call advances the rotation counter, so every target gets
        equal time as primary.  In non-differential mode (single target)
        this always returns (target, []).

        When ``_fixed_primary`` is set (WAF bypass and other asymmetric
        campaigns), ``all_targets[0]`` is always primary — rotation is
        disabled because the roles are not interchangeable.
        """
        if self._fixed_primary:
            # Keep rotation_idx pinned at 1 so finding_pipeline computes
            # primary_idx = (1-1) % N = 0  (always the fixed primary).
            self._rotation_idx = 1
            return self.all_targets[0], self.all_targets[1:]
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
        pool_timeout = getattr(refs[0], 'timeout_seconds', 10.0) * 2 + 10
        return list(self._ref_pool.map(_run, refs, timeout=pool_timeout))

    def _execute_primary_and_refs(
        self,
        primary,
        refs: list,
        inp: Input,
    ) -> tuple[ExecutionResult, list[ExecutionResult] | None]:
        """Execute primary + references in one call.

        Fast path: if primary is a MultiDiffPersistentTarget, delegate to
        execute_all() which fans out to all WAFs via a single subprocess and
        Rust parallel sockets — one pipe round-trip instead of N+1.

        Slow path: normal execute_on + _execute_on_refs (unchanged behaviour).
        """
        from .targets.persistent_target import MultiDiffPersistentTarget

        if isinstance(primary, MultiDiffPersistentTarget):
            try:
                return primary.execute_all(inp)
            except Exception as e:
                logger.warning(
                    "MultiDiffPersistentTarget.execute_all error: %s — "
                    "falling back to normal execution",
                    e,
                )
                # Fall through to normal path on unexpected failure

        # Parallel path: submit primary alongside refs so all WAF subprocesses
        # run concurrently — halves wall time vs sequential primary-then-refs.
        if refs:
            if self._ref_pool is None:
                self._ref_pool = ThreadPoolExecutor(
                    max_workers=max(len(self.all_targets), 1),
                )
            f_primary = self._ref_pool.submit(self._execute_on, primary, inp)
            f_refs = [self._ref_pool.submit(self._execute_on, r, inp) for r in refs]
            # Generous timeout: 2× target timeout + 10s for setup/warmup.
            # Prevents permanent hang if a subprocess pipe deadlocks on
            # Windows (no error / no traceback — the process just freezes).
            pool_timeout = getattr(primary, 'timeout_seconds', 10.0) * 2 + 10
            try:
                result = f_primary.result(timeout=pool_timeout)
                ref_results: list[ExecutionResult] | None = [
                    f.result(timeout=pool_timeout) for f in f_refs
                ]
            except FutureTimeoutError:
                logger.error(
                    "ThreadPool future timed out after %.0fs — possible "
                    "subprocess pipe deadlock. Cancelling and recycling.",
                    pool_timeout,
                )
                # Cancel pending futures (won't stop running ones)
                for f in [f_primary] + f_refs:
                    f.cancel()
                # Force-recycle all targets to break any pipe deadlock
                for t in self.all_targets:
                    try:
                        t.teardown()
                    except Exception:
                        pass
                    t.setup()
                # Return a synthetic error result so the loop can continue
                result = ExecutionResult(
                    exit_code=-1,
                    stderr=b"ThreadPool future timeout",
                    metadata={"error": "pool_timeout",
                              "error_type": "TimeoutError"},
                )
                ref_results = None
            return result, ref_results

        result = self._execute_on(primary, inp)
        return result, None

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
        """Run all oracles and persist any unique findings."""
        result_summary = self._finding_processor.check(
            inp,
            result,
            mutator_name=mutator_name,
            ref_results=ref_results,
            rotation_idx=self._rotation_idx,
        )
        self._last_finding_metadata = result_summary.metadata
        self._deser_oracle_positive = self._finding_processor.deser_oracle_positive
        return result_summary.found

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
        self._last_status_time, self._last_save_time = (
            self._runtime_reporting.maybe_print_status(
                last_status_time=self._last_status_time,
                last_save_time=self._last_save_time,
                status_interval=self.status_interval,
            )
        )

    def _cleanup(self) -> None:
        self._runtime_reporting.cleanup(ref_pool=self._ref_pool)
        self._ref_pool = None

    # ── Checkpointing ──────────────────────────────────────────────

    def _export_dedup_seen(self) -> list[str] | None:
        """Expose deduplicator state for checkpoint persistence."""
        if isinstance(self.deduplicator, _DefaultDeduplicator):
            return sorted(self.deduplicator._seen)
        return None

    def _import_dedup_seen(self, dedup_seen: list[str]) -> None:
        """Restore deduplicator state from a checkpoint."""
        if dedup_seen and isinstance(self.deduplicator, _DefaultDeduplicator):
            self.deduplicator._seen = set(dedup_seen)

    def _maybe_save_checkpoint(self) -> None:
        """Save checkpoint periodically (every checkpoint_interval seconds)."""
        self._last_checkpoint_time = self._checkpoint_service.maybe_save(
            last_checkpoint_time=self._last_checkpoint_time,
            checkpoint_interval=self.checkpoint_interval,
        )

    def _save_checkpoint(self) -> None:
        """Backward-compatible alias for explicit checkpoint saves in tests."""
        self._checkpoint_service.save()

    def _load_checkpoint(self) -> bool:
        """Backward-compatible alias for explicit checkpoint loads in tests."""
        return self._checkpoint_service.load()


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
            # Strategy/category are omitted: the diff_pattern_hash
            # captures the behavioral signature.  Including strategy
            # caused 3-5x inflation where the same input triggered
            # separate findings for each of 8 WAF bypass strategies.
            parts = [
                finding.oracle_name,
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
