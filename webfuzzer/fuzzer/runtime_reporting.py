"""Status printing and result persistence helpers for the fuzzing engine."""

from __future__ import annotations

import json
import logging
import os
import sys
import time

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
        if not self.guidance_hooks or not self.guidance_hooks.active:
            return

        report_path = self.output_dir / "report.json"
        if not report_path.exists():
            return

        try:
            report_data = json.loads(report_path.read_text(encoding="utf-8"))
            guidance_report = self.guidance_hooks.get_report_section()
            if guidance_report:
                report_data["guidance"] = guidance_report
                report_path.write_text(
                    json.dumps(report_data, indent=2),
                    encoding="utf-8",
                )
        except Exception:
            pass
