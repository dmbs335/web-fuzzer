"""Status printing and result persistence helpers for the fuzzing engine."""

from __future__ import annotations

import json
import logging
import os
import sys
import time

from .selection_drop_analysis import (
    write_selection_drop_summary_artifacts,
    write_selection_shadow_replay_artifacts,
    write_selection_shadow_summary_artifacts,
)

logger = logging.getLogger(__name__)


class RuntimeReportingService:
    """Handle periodic status output and final result persistence."""

    def __init__(
        self,
        *,
        stats,
        publisher,
        output_dir,
        guidance_hooks,
        concolic,
        corpus,
        verify_queue,
        all_targets,
        running_getter,
        sync_deser_diag,
    ) -> None:
        self.stats = stats
        self.publisher = publisher
        self.output_dir = output_dir
        self.guidance_hooks = guidance_hooks
        self.concolic = concolic
        self.corpus = corpus
        self.verify_queue = verify_queue
        self.all_targets = all_targets
        self.running_getter = running_getter
        self.sync_deser_diag = sync_deser_diag

    def maybe_print_status(
        self,
        *,
        last_status_time: float,
        last_save_time: float,
        status_interval: float,
    ) -> tuple[float, float]:
        """Print periodic status and persist intermediate report data."""
        now = time.time()
        if now - last_status_time < status_interval:
            return last_status_time, last_save_time

        last_status_time = now
        self.sync_deser_diag()
        guidance_status = ""
        if self.guidance_hooks and self.guidance_hooks.active:
            guidance_status = self.guidance_hooks.get_status_line()

        status = self.stats.status_line()
        if guidance_status:
            status = f"{status} | G:{guidance_status}"
        if self.concolic is not None:
            status = f"{status} | {self.concolic.get_status_line()}"

        if self.publisher.enabled or os.environ.get("FUZZER_SESSION_ID"):
            print(status, flush=True, file=sys.stderr)
        else:
            print(f"\r{status}", end="", flush=True, file=sys.stderr)

        self.publisher.publish_stats(
            elapsed_seconds=self.stats.elapsed(),
            total_execs=self.stats.total_executions,
            execs_per_sec=self.stats.executions_per_second,
            corpus_size=self.stats.corpus_size,
            total_edges=self.stats.total_edges,
            unique_findings=self.stats.unique_findings,
            observed_findings=self.stats.observed_findings,
            selection_drops_total=self.stats.selection_drops_total,
            selection_summary=self.stats.selection_summary(),
            orbit_downgrades_total=self.stats.orbit_downgrades_total,
            shadow_replay_summary=self.stats.shadow_replay_summary(),
            interface_progress=self.stats.interface_progress_summary(),
        )

        if self.output_dir and now - last_save_time >= 30.0:
            last_save_time = now
            self.output_dir.mkdir(parents=True, exist_ok=True)
            report_text = self._build_report_text()
            (self.output_dir / "report.json").write_text(
                report_text,
                encoding="utf-8",
            )

        return last_status_time, last_save_time

    def cleanup(self, *, ref_pool=None) -> None:
        """Flush final artifacts and tear down runtime resources."""
        print("", file=sys.stderr)
        if ref_pool is not None:
            ref_pool.shutdown(wait=False)

        for target in self.all_targets:
            try:
                target.teardown()
            except Exception:
                pass

        if self.output_dir:
            try:
                self.stats.save(self.output_dir)
                self._rewrite_selection_drop_summary()
                self._rewrite_selection_shadow_summary()
                self._rewrite_selection_shadow_replay()
                self._rewrite_final_report()
            except Exception as exc:
                logger.error("Failed to save stats: %s", exc)
            try:
                self.corpus.save(self.output_dir / "corpus")
            except Exception as exc:
                logger.error("Failed to save corpus: %s", exc)
            else:
                logger.info("Results saved to %s", self.output_dir)

        if self.verify_queue:
            self.verify_queue.close()

        if self.running_getter():
            self.publisher.publish_status("completed")
        self.publisher.close()

    def _build_report_text(self) -> str:
        report_text = self.stats.report("json")
        if self.guidance_hooks and self.guidance_hooks.active:
            guidance_report = self.guidance_hooks.get_report_section()
            if guidance_report:
                try:
                    report_data = json.loads(report_text)
                    report_data["guidance"] = guidance_report
                    report_text = json.dumps(report_data, indent=2)
                except Exception:
                    pass
        if self.concolic is not None:
            try:
                report_data = json.loads(report_text)
                report_data["concolic"] = self.concolic.get_stats()
                report_text = json.dumps(report_data, indent=2)
            except Exception:
                pass
        return report_text

    def _rewrite_final_report(self) -> None:
        if not self.output_dir:
            return

        report_path = self.output_dir / "report.json"
        if not report_path.exists():
            return

        try:
            report_data = json.loads(report_path.read_text(encoding="utf-8"))
            if self.guidance_hooks and self.guidance_hooks.active:
                guidance_report = self.guidance_hooks.get_report_section()
                if guidance_report:
                    report_data["guidance"] = guidance_report
            self._attach_selection_policy_reports(report_data)
            report_path.write_text(
                json.dumps(report_data, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _attach_selection_policy_reports(self, report_data: dict) -> None:
        if not self.output_dir:
            return

        drop_summary_path = self.output_dir / "selection_drop_summary.json"
        if drop_summary_path.exists():
            try:
                report_data["selection_drop_analysis"] = json.loads(
                    drop_summary_path.read_text(encoding="utf-8"),
                )
            except Exception:
                logger.debug("Failed to attach selection drop summary", exc_info=True)

        shadow_summary_path = self.output_dir / "selection_shadow_summary.json"
        if shadow_summary_path.exists():
            try:
                report_data["selection_shadow_analysis"] = json.loads(
                    shadow_summary_path.read_text(encoding="utf-8"),
                )
            except Exception:
                logger.debug("Failed to attach selection shadow summary", exc_info=True)

        triage_path = self.output_dir / "selection_shadow_triage.json"
        if triage_path.exists():
            try:
                report_data["selection_shadow_triage"] = json.loads(
                    triage_path.read_text(encoding="utf-8"),
                )
            except Exception:
                logger.debug("Failed to attach selection shadow triage", exc_info=True)

        replay_manifest_path = self.output_dir / "selection_shadow_replay" / "manifest.json"
        if replay_manifest_path.exists():
            try:
                report_data["selection_shadow_replay"] = json.loads(
                    replay_manifest_path.read_text(encoding="utf-8"),
                )
            except Exception:
                logger.debug("Failed to attach selection shadow replay", exc_info=True)

    def _rewrite_selection_drop_summary(self) -> None:
        if not self.output_dir:
            return
        try:
            write_selection_drop_summary_artifacts(
                self.output_dir / "selection_drops.jsonl",
            )
        except Exception:
            logger.debug("Failed to rewrite selection drop summary", exc_info=True)

    def _rewrite_selection_shadow_summary(self) -> None:
        if not self.output_dir:
            return
        try:
            write_selection_shadow_summary_artifacts(
                self.output_dir / "selection_shadow_queue.jsonl",
            )
        except Exception:
            logger.debug("Failed to rewrite selection shadow summary", exc_info=True)

    def _rewrite_selection_shadow_replay(self) -> None:
        if not self.output_dir:
            return
        try:
            write_selection_shadow_replay_artifacts(
                self.output_dir / "selection_shadow_queue.jsonl",
            )
        except Exception:
            logger.debug("Failed to rewrite selection shadow replay artifacts", exc_info=True)
