"""Initial corpus seeding workflow for the fuzzing engine."""

from __future__ import annotations

import json
import logging

from .protocols import Input, ScheduleResult

logger = logging.getLogger(__name__)


class SeedingService:
    """Populate the initial corpus from findings, files, guidance, and grammar."""

    GUIDANCE_TARGET_PCT = 0.20
    SHORT_WAF_CAMPAIGN_MAX_TIME = 30.0
    _SHORT_WAF_AXIS_PARSERS_TO_SKIP = {
        "multipart_parse",
        "body_framing",
    }
    _SHADOW_REPLAY_TRIAGE_BOOSTS = {
        "promote_shadow_bucket": 4.0,
        "review_shadow_bucket": 2.5,
        "monitor_shadow_bucket": 1.25,
    }

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
        max_time_seconds: float,
        output_dir,
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
        self.max_time_seconds = max_time_seconds
        self.output_dir = output_dir
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
        file_seed_count += self._load_shadow_replay_seeds()
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
    ):
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
        seed = self.corpus.force_add(inp, cov)
        priority_boost = inp.metadata.get("priority_boost")
        if isinstance(priority_boost, (int, float)):
            seed.priority_boost = max(0.01, min(float(priority_boost), 10.0))
        self.check_oracles(
            inp,
            result,
            mutator_name=mutator_name,
            ref_results=ref_results,
        )
        self.stats.record_execution(mutator_name)
        return seed

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
        skipped = 0
        for seed_file in seed_files:
            if seed_file.name.startswith("."):
                continue
            try:
                data = seed_file.read_bytes()
                if not data:
                    continue
                if self._should_skip_file_seed(seed_file, data):
                    skipped += 1
                    continue
                self._ingest_seed(
                    Input(data=data),
                    mutator_name="file_seed",
                    track_deser_stdout=True,
                )
                count += 1
            except Exception as exc:
                logger.warning("Failed to load seed %s: %s", seed_file, exc)
        if skipped:
            logger.info(
                "Skipped %d timeout-prone file seeds for this campaign budget",
                skipped,
            )
        return count

    def _should_skip_file_seed(self, seed_file, data: bytes) -> bool:
        if not self._is_short_waf_campaign():
            return False
        meta = self._extract_waf_seed_headers(data)
        axis_parser = str(meta.get("axis_parser") or "").strip().lower()
        return axis_parser in self._SHORT_WAF_AXIS_PARSERS_TO_SKIP

    def _is_short_waf_campaign(self) -> bool:
        if not self.seeds_dir:
            return False
        if self.max_time_seconds <= 0 or self.max_time_seconds > self.SHORT_WAF_CAMPAIGN_MAX_TIME:
            return False
        return "waf_bypass_seeds" in str(self.seeds_dir).replace("\\", "/").lower()

    def _extract_waf_seed_headers(self, data: bytes) -> dict[str, str]:
        headers: dict[str, str] = {}
        try:
            head = data.split(b"\r\n\r\n", 1)[0]
            lines = head.split(b"\r\n")
            if len(lines) == 1:
                head = data.split(b"\n\n", 1)[0]
                lines = head.split(b"\n")
        except Exception:
            return headers
        for raw_line in lines[1:]:
            if b":" not in raw_line:
                continue
            name, value = raw_line.split(b":", 1)
            lower_name = name.strip().lower()
            if not lower_name.startswith(b"x-wf-"):
                continue
            key = lower_name.decode("ascii", errors="ignore")[5:].replace("-", "_")
            headers[key] = value.strip().decode("latin-1", errors="replace")
        return headers

    def _load_shadow_replay_seeds(self) -> int:
        """Load triage-promoted shadow replay seeds from the previous run.

        The replay directory is generated at shutdown when shadow buckets are
        promoted into a replay-ready mini corpus. On the next start with the
        same output directory, we automatically ingest those seeds before the
        normal file-seed pass so shadow-preserved variants get a fair replay.
        """
        count = 0
        replay_dir = (
            self.output_dir / "selection_shadow_replay"
            if self.output_dir is not None
            else None
        )
        if replay_dir is None or not replay_dir.is_dir():
            return count

        seed_files = sorted(path for path in replay_dir.glob("*.bin") if path.is_file())
        if not seed_files:
            return count

        manifest_by_seed = self._load_shadow_replay_manifest(replay_dir)

        logger.info(
            "Loading %d shadow replay seeds from %s",
            len(seed_files),
            replay_dir,
        )
        for seed_file in seed_files:
            try:
                data = seed_file.read_bytes()
                if not data:
                    continue
                manifest_entry = manifest_by_seed.get(seed_file.name, {})
                triage_action = str(manifest_entry.get("triage_action") or "")
                priority_boost = self._shadow_replay_priority_boost(manifest_entry)
                seed = self._ingest_seed(
                    Input(
                        data=data,
                        metadata={
                            "shadow_replay_seed": True,
                            "shadow_replay_source": str(seed_file),
                            "shadow_replay_triage_action": triage_action,
                            "session_key": manifest_entry.get("session_key", ""),
                            "prefix_depth": manifest_entry.get("prefix_depth"),
                            "replay_context": manifest_entry.get("replay_context"),
                            "priority_boost": priority_boost,
                        },
                    ),
                    mutator_name="shadow_replay_seed",
                    track_deser_stdout=True,
                )
                if seed is not None and self.publisher is not None and priority_boost > 1.0:
                    self.publisher.publish_priority_update(seed.id, priority_boost)
                if hasattr(self.stats, "record_shadow_replay_loaded"):
                    self.stats.record_shadow_replay_loaded()
                count += 1
            except Exception as exc:
                logger.warning("Failed to load shadow replay seed %s: %s", seed_file, exc)
        return count

    def _load_shadow_replay_manifest(self, replay_dir):
        manifest_path = replay_dir / "manifest.json"
        if not manifest_path.is_file():
            return {}
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to parse shadow replay manifest %s: %s", manifest_path, exc)
            return {}
        if not isinstance(manifest, list):
            return {}
        return {
            str(entry.get("seed_path")): entry
            for entry in manifest
            if isinstance(entry, dict) and entry.get("seed_path")
        }

    def _shadow_replay_priority_boost(self, manifest_entry) -> float:
        """Prefer replay seeds that preserve richer session/canonical distinctions."""
        triage_action = str(manifest_entry.get("triage_action") or "")
        boost = self._SHADOW_REPLAY_TRIAGE_BOOSTS.get(triage_action, 1.5)
        if manifest_entry.get("session_key"):
            boost *= 1.5
        if manifest_entry.get("prefix_depth") is not None:
            boost *= 1.25
        if manifest_entry.get("replay_context"):
            boost *= 1.1
        return round(min(max(boost, 1.0), 10.0), 2)

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

        # Deprioritize dead chains — seeds containing gadget patterns
        # that cannot fire in the current target environment.
        self._deprioritize_dead_chains()

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

    # ── Dead-chain deprioritization ──────────────────────────────

    # Binary patterns for gadget chain classes that require specific
    # JVM features absent in common targets. Each entry maps a UTF-8
    # class name fragment (as it appears in serialized streams) to the
    # JVM feature it depends on.
    _DEAD_CHAIN_PATTERNS: list[tuple[bytes, str]] = [
        # BadAttributeValueExpException.readObject() only calls
        # val.toString() when System.getSecurityManager() != null.
        # JEUS 8.5 has no SecurityManager → all BAVE chains are dead.
        (b"BadAttributeValueExpException", "SecurityManager"),
    ]

    def _deprioritize_dead_chains(self) -> None:
        """Lower priority_boost for corpus seeds containing dead chain patterns.

        Some gadget chains depend on JVM features (e.g., SecurityManager)
        that are absent in the target.  Spending mutation cycles on these
        seeds is wasted work, so we reduce their selection probability.
        """
        deprioritized = 0
        for seed in self.corpus.seeds:
            raw = seed.input.data
            for pattern, reason in self._DEAD_CHAIN_PATTERNS:
                if pattern in raw:
                    seed.priority_boost = 0.05  # 20× less likely to be selected
                    deprioritized += 1
                    break
        if deprioritized:
            logger.info(
                "Deprioritized %d dead-chain seeds (patterns: %s)",
                deprioritized,
                ", ".join(r for _, r in self._DEAD_CHAIN_PATTERNS),
            )
