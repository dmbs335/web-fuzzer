"""Initial corpus seeding workflow for the fuzzing engine."""

from __future__ import annotations

import json
import logging

from .protocols import Input, ScheduleResult

logger = logging.getLogger(__name__)


class SeedingService:
    """Populate the initial corpus from findings, files, guidance, and grammar."""

    GUIDANCE_TARGET_PCT = 0.20

    def __init__(
        self,
        *,
        corpus,
        coverage,
        input_source,
        mutators: list,
        stats,
        publisher,
        guidance_hooks,
        initial_seed_count: int,
        seeds_dir,
        import_findings: list,
        rotate_primary,
        execute_on,
        execute_on_refs,
        collect_coverage,
        check_oracles,
        apply_guidance_weights,
        track_deser_result,
        sync_deser_diag,
    ) -> None:
        self.corpus = corpus
        self.coverage = coverage
        self.input_source = input_source
        self.mutators = mutators
        self.stats = stats
        self.publisher = publisher
        self.guidance_hooks = guidance_hooks
        self.initial_seed_count = initial_seed_count
        self.seeds_dir = seeds_dir
        self.import_findings = import_findings
        self.rotate_primary = rotate_primary
        self.execute_on = execute_on
        self.execute_on_refs = execute_on_refs
        self.collect_coverage = collect_coverage
        self.check_oracles = check_oracles
        self.apply_guidance_weights = apply_guidance_weights
        self.track_deser_result = track_deser_result
        self.sync_deser_diag = sync_deser_diag

    def run(self) -> None:
        """Generate initial seeds and populate the corpus."""
        file_seed_count = self._import_previous_findings()
        file_seed_count += self._load_file_seeds()
        self._log_deser_seed_summary()
        guidance_seed_count = self._inject_guidance_seeds()
        self._generate_grammar_seeds(file_seed_count, guidance_seed_count)
        self._finalize()

    def _ingest_seed(
        self,
        inp: Input,
        *,
        mutator_name: str,
        track_deser_stdout: bool = False,
    ) -> None:
        primary, refs = self.rotate_primary()
        result = self.execute_on(primary, inp)
        if track_deser_stdout and result.stdout:
            try:
                parsed = json.loads(result.stdout)
                if isinstance(parsed, dict):
                    self.track_deser_result(parsed)
            except Exception:
                pass
        ref_results = self.execute_on_refs(refs, inp)
        cov = self.collect_coverage(inp, result, ref_results=ref_results)
        self.corpus.force_add(inp, cov)
        self.check_oracles(
            inp,
            result,
            mutator_name=mutator_name,
            ref_results=ref_results,
        )
        self.stats.record_execution(mutator_name)

    def _import_previous_findings(self) -> int:
        count = 0
        if not self.import_findings:
            return count

        imported = 0
        for session_dir in self.import_findings:
            findings_dir = session_dir / "findings"
            if not findings_dir.is_dir():
                logger.warning("No findings dir in %s", session_dir)
                continue
            for finding_dir in sorted(findings_dir.iterdir()):
                input_file = finding_dir / "input"
                if not input_file.is_file():
                    continue
                try:
                    data = input_file.read_bytes()
                    if not data:
                        continue
                    self._ingest_seed(Input(data=data), mutator_name="file_seed")
                    imported += 1
                    count += 1
                except Exception as exc:
                    logger.warning(
                        "Failed to import finding %s: %s",
                        input_file,
                        exc,
                    )
        logger.info(
            "Imported %d finding inputs from %d session(s)",
            imported,
            len(self.import_findings),
        )
        return count

    def _load_file_seeds(self) -> int:
        count = 0
        if not self.seeds_dir or not self.seeds_dir.is_dir():
            return count

        seed_files = sorted(path for path in self.seeds_dir.rglob("*") if path.is_file())
        logger.info("Loading %d seed files from %s", len(seed_files), self.seeds_dir)
        for seed_file in seed_files:
            if seed_file.name.startswith("."):
                continue
            try:
                data = seed_file.read_bytes()
                if not data:
                    continue
                self._ingest_seed(
                    Input(data=data),
                    mutator_name="file_seed",
                    track_deser_stdout=True,
                )
                count += 1
            except Exception as exc:
                logger.warning("Failed to load seed %s: %s", seed_file, exc)
        return count

    def _log_deser_seed_summary(self) -> None:
        if not getattr(self.stats, "deser_diag", None) and not hasattr(
            self.stats,
            "deser_diag",
        ):
            return
        self.sync_deser_diag()
        dd = self.stats.deser_diag
        if not dd:
            return
        logger.info(
            "Seed validation: %d seeds -> compiled=%d (%.0f%%) -> "
            "deserialized=%d (%.0f%%) | sinks=%s | findings=%d",
            dd["total"],
            dd["compiled"],
            dd["compiled"] / dd["total"] * 100 if dd["total"] else 0,
            dd["deserialized"],
            dd["deserialized"] / dd["total"] * 100 if dd["total"] else 0,
            dd.get("sink_hits", {}),
            self.stats.unique_findings,
        )
        exc = dd.get("exceptions_top5", [])
        if exc:
            for cls, cnt in exc[:3]:
                logger.info("  Top exception: %s (%d seeds)", cls, cnt)

    def _inject_guidance_seeds(self) -> int:
        guidance_seed_count = 0
        if not self.guidance_hooks or not self.guidance_hooks.active:
            return guidance_seed_count

        targeted_seeds = self.guidance_hooks.get_targeted_seeds()
        guidance_budget = max(
            int(self.initial_seed_count * self.GUIDANCE_TARGET_PCT),
            len(targeted_seeds),
        )
        variants_per_seed = max(guidance_budget // max(len(targeted_seeds), 1), 1)

        domain_mutator = None
        for mutator in self.mutators:
            if hasattr(mutator, "apply_guidance_weights"):
                domain_mutator = mutator
                break

        for seed_dict in targeted_seeds:
            try:
                if hasattr(self.input_source, "generate_from_fields"):
                    inp = self.input_source.generate_from_fields(seed_dict)
                else:
                    data = json.dumps(seed_dict.get("fields", seed_dict)).encode("utf-8")
                    inp = Input(data=data, metadata={"guidance_seed": True})
                self._ingest_seed(inp, mutator_name="guidance_seed")
                guidance_seed_count += 1

                if domain_mutator:
                    for _ in range(variants_per_seed - 1):
                        try:
                            mutated = domain_mutator.mutate(inp, None)
                            if mutated is None or mutated.data == inp.data:
                                continue
                            mutated.metadata["guidance_seed"] = True
                            self._ingest_seed(mutated, mutator_name="guidance_seed")
                            guidance_seed_count += 1
                        except Exception:
                            pass
            except Exception as exc:
                logger.warning("Failed to inject guidance seed: %s", exc)

        if guidance_seed_count:
            logger.info(
                "Injected %d guidance seeds (%d base + %d variants)",
                guidance_seed_count,
                len(targeted_seeds),
                guidance_seed_count - len(targeted_seeds),
            )

        weights = self.guidance_hooks.get_initial_weights()
        if weights:
            self.apply_guidance_weights(weights)
        return guidance_seed_count

    def _generate_grammar_seeds(
        self,
        file_seed_count: int,
        guidance_seed_count: int,
    ) -> None:
        gen_count = max(
            0,
            self.initial_seed_count - file_seed_count - guidance_seed_count,
        )
        logger.info(
            "Generating %d initial seeds (%d from files, %d from guidance)...",
            gen_count,
            file_seed_count,
            guidance_seed_count,
        )

        for _ in range(gen_count):
            inp = self.input_source.generate()
            primary, refs = self.rotate_primary()
            result = self.execute_on(primary, inp)
            ref_results = self.execute_on_refs(refs, inp)
            cov = self.collect_coverage(inp, result, ref_results=ref_results)
            is_novel = bool(
                cov
                and self.coverage
                and self.coverage.is_novel(self.corpus.global_coverage, cov)
            )
            self.corpus.force_add(inp, cov)
            found_crash = self.check_oracles(
                inp,
                result,
                mutator_name="seed",
                ref_results=ref_results,
            )
            self.stats.record_execution("seed")

            if hasattr(self.input_source, "update"):
                self.input_source.update(
                    inp,
                    ScheduleResult(
                        found_new_coverage=is_novel,
                        found_crash=found_crash,
                    ),
                )

    def _finalize(self) -> None:
        for seed in self.corpus.seeds:
            seed.coverage = None

        self.stats.update_corpus(len(self.corpus), self.corpus.total_bytes)
        self.stats.record_new_coverage(self.corpus.global_coverage.edge_count)
        logger.info(
            "Seeding done: %d seeds, %d edges",
            len(self.corpus),
            self.corpus.global_coverage.edge_count,
        )
        self.publisher.publish_stats(
            elapsed_seconds=self.stats.elapsed(),
            total_execs=self.stats.total_executions,
            execs_per_sec=self.stats.executions_per_second,
            corpus_size=self.stats.corpus_size,
            total_edges=self.stats.total_edges,
            unique_findings=self.stats.unique_findings,
        )
        self.publisher.publish_coverage(
            edge_count=self.corpus.global_coverage.edge_count,
            elapsed_sec=self.stats.elapsed(),
            exec_count=self.stats.total_executions,
            corpus_size=len(self.corpus),
        )
