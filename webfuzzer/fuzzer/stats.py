"""Fuzzing session statistics and reporting."""

from __future__ import annotations

import json
import logging
import math
import time
from dataclasses import dataclass, field
from pathlib import Path

from .protocols import ExecutionResult, Finding, Input, Severity

logger = logging.getLogger(__name__)


# ── Phase 3C: Hill-MLE Pareto tail-index estimator ────────────────────────────

def hill_alpha(coverage_window: list[tuple[float, int]]) -> float | None:
    """Hill-MLE estimate of Pareto tail index α from a coverage-over-time window.

    Parameters
    ----------
    coverage_window:
        List of ``(elapsed_sec, edge_count)`` tuples (a slice of
        ``FuzzStats.coverage_over_time``).  Must contain ≥ 2 positive
        coverage increments; returns ``None`` otherwise.

    Returns
    -------
    float | None
        Estimated α̂ = 1 + n / Σᵢ log(δᵢ / (x_min − 0.5)).  Values below
        2 indicate heavy-tailed increments (infinite variance) where
        ``apply_learned_weights`` should use median normalisation.
        Returns ``None`` when the estimator is undefined (too few positive
        deltas or degenerate sequence).
    """
    counts = [c for _, c in coverage_window]
    deltas = [b - a for a, b in zip(counts, counts[1:]) if b > a]
    n = len(deltas)
    if n < 2:
        return None
    x_min = min(deltas)
    # Continuity correction: x_min - 0.5 ensures log > 0 even when all
    # deltas equal x_min (avoids log(1) = 0 → division by zero).
    x_thresh = max(x_min - 0.5, 0.5)
    denom = sum(math.log(d / x_thresh) for d in deltas)
    if denom <= 0.0:
        return None
    return round(1.0 + n / denom, 4)


@dataclass
class FuzzStats:
    """Tracks all statistics for a fuzzing session."""

    start_time: float = field(default_factory=time.time)

    # Execution
    total_iterations: int = 0
    total_executions: int = 0
    executions_per_second: float = 0.0

    # Coverage
    total_edges: int = 0
    peak_edges: int = 0
    coverage_over_time: list[tuple[float, int]] = field(default_factory=list)

    # Findings
    total_findings: int = 0
    unique_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_oracle: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    # Corpus
    corpus_size: int = 0
    corpus_bytes: int = 0

    # Mutator tracking
    mutations_by_mutator: dict[str, int] = field(default_factory=dict)
    findings_by_mutator: dict[str, int] = field(default_factory=dict)
    new_coverage_by_mutator: dict[str, int] = field(default_factory=dict)

    # Per-strategy tracking (e.g., saml mutator's 50 strategies)
    strategy_execs: dict[str, int] = field(default_factory=dict)
    strategy_coverage: dict[str, int] = field(default_factory=dict)
    strategy_findings: dict[str, int] = field(default_factory=dict)

    # Timing
    last_new_coverage_at: float = 0.0
    last_finding_at: float = 0.0

    # Deser pipeline diagnostics (populated by engine for deser oracle sessions)
    deser_diag: dict = field(default_factory=dict)

    # Phase 3C: live Pareto tail-index estimate from coverage increments.
    # Updated by the engine every 25 novel coverage events (Hill-MLE on a
    # sliding window of the last 300 entries in coverage_over_time).
    # None until at least 50 novel events have accumulated.
    alpha_estimate: float | None = None

    # Incremental finding save
    output_dir: Path | None = field(default=None, repr=False)
    _saved_finding_count: int = field(default=0, repr=False)

    def elapsed(self) -> float:
        return time.time() - self.start_time

    def record_execution(self, mutator_name: str = "") -> None:
        self.total_executions += 1
        elapsed = self.elapsed()
        if elapsed > 0:
            self.executions_per_second = self.total_executions / elapsed
        if mutator_name:
            self.mutations_by_mutator[mutator_name] = (
                self.mutations_by_mutator.get(mutator_name, 0) + 1
            )

    def record_iteration(self) -> None:
        self.total_iterations += 1

    def record_new_coverage(self, edge_count: int, mutator_name: str = "") -> None:
        self.total_edges = edge_count
        self.peak_edges = max(self.peak_edges, edge_count)
        now = time.time()
        self.last_new_coverage_at = now
        self.coverage_over_time.append((now - self.start_time, edge_count))
        # Cap to prevent unbounded growth (keep last 5000 entries)
        if len(self.coverage_over_time) > 5000:
            self.coverage_over_time = self.coverage_over_time[-2500:]
        if mutator_name:
            self.new_coverage_by_mutator[mutator_name] = (
                self.new_coverage_by_mutator.get(mutator_name, 0) + 1
            )

    def record_finding(self, finding: Finding, mutator_name: str = "") -> None:
        self.total_findings += 1
        self.unique_findings += 1
        self.findings.append(finding)
        self.last_finding_at = time.time()

        sev = finding.severity.value
        self.findings_by_severity[sev] = self.findings_by_severity.get(sev, 0) + 1
        self.findings_by_oracle[finding.oracle_name] = (
            self.findings_by_oracle.get(finding.oracle_name, 0) + 1
        )
        if mutator_name:
            self.findings_by_mutator[mutator_name] = (
                self.findings_by_mutator.get(mutator_name, 0) + 1
            )
        self._save_finding_incremental(finding)
        # Strip heavy data after disk save to prevent OOM in long sessions.
        # Keep only lightweight fields needed for dedup/reporting.
        self._strip_finding(finding)

    def record_strategies(self, strategies: list[str]) -> None:
        """Record which sub-strategies were applied in a mutation."""
        for s in strategies:
            self.strategy_execs[s] = self.strategy_execs.get(s, 0) + 1

    def record_strategy_coverage(self, strategies: list[str]) -> None:
        """Record that strategies led to new coverage."""
        for s in strategies:
            self.strategy_coverage[s] = self.strategy_coverage.get(s, 0) + 1

    def record_strategy_finding(self, strategies: list[str]) -> None:
        """Record that strategies led to a finding."""
        for s in strategies:
            self.strategy_findings[s] = self.strategy_findings.get(s, 0) + 1

    def update_corpus(self, size: int, total_bytes: int) -> None:
        self.corpus_size = size
        self.corpus_bytes = total_bytes

    def status_line(self) -> str:
        """One-line status for terminal output."""
        elapsed = self.elapsed()
        line = (
            f"[{elapsed:7.1f}s] "
            f"execs: {self.total_executions} "
            f"({self.executions_per_second:.0f}/s) | "
            f"corpus: {self.corpus_size} | "
            f"edges: {self.total_edges} | "
            f"findings: {self.unique_findings}"
        )
        # Append deser pipeline summary when available
        dd = self.deser_diag
        if dd.get("total", 0) > 0:
            total = dd["total"]
            comp_pct = dd.get("compiled", 0) / total * 100
            deser_pct = dd.get("deserialized", 0) / total * 100
            sinks = dd.get("sink_hits", {})
            sink_str = "+".join(f"{k}:{v}" for k, v in sorted(sinks.items())) if sinks else "none"
            line += f" | deser: comp={comp_pct:.0f}% deser={deser_pct:.0f}% sinks=[{sink_str}]"
        return line

    def report(self, fmt: str = "text") -> str:
        """Generate a full report."""
        if fmt == "json":
            return self._report_json()
        return self._report_text()

    def _report_text(self) -> str:
        elapsed = self.elapsed()
        lines = [
            "=" * 60,
            "  Fuzzing Session Report",
            "=" * 60,
            f"  Duration:        {elapsed:.1f}s",
            f"  Total execs:     {self.total_executions}",
            f"  Exec/s:          {self.executions_per_second:.1f}",
            f"  Corpus size:     {self.corpus_size}",
            f"  Total edges:     {self.total_edges}",
            f"  Peak edges:      {self.peak_edges}",
            f"  Unique findings: {self.unique_findings}",
            "",
        ]

        if self.findings_by_severity:
            lines.append("  Findings by severity:")
            for sev, count in sorted(self.findings_by_severity.items()):
                lines.append(f"    {sev:12s}: {count}")
            lines.append("")

        if self.findings_by_oracle:
            lines.append("  Findings by oracle:")
            for oracle, count in sorted(self.findings_by_oracle.items()):
                lines.append(f"    {oracle:20s}: {count}")
            lines.append("")

        if self.mutations_by_mutator:
            lines.append("  Mutations by mutator:")
            for mut, count in sorted(self.mutations_by_mutator.items()):
                cov = self.new_coverage_by_mutator.get(mut, 0)
                lines.append(f"    {mut:20s}: {count:8d} execs, {cov:6d} new cov")
            lines.append("")

        if self.strategy_execs:
            lines.append("  Strategy effectiveness:")
            # Sort by findings desc, then coverage desc
            ranked = sorted(
                self.strategy_execs.keys(),
                key=lambda s: (
                    self.strategy_findings.get(s, 0),
                    self.strategy_coverage.get(s, 0),
                ),
                reverse=True,
            )
            for s in ranked:
                execs = self.strategy_execs[s]
                cov = self.strategy_coverage.get(s, 0)
                finds = self.strategy_findings.get(s, 0)
                rate = (cov / execs * 100) if execs > 0 else 0
                lines.append(
                    f"    {s:35s}: {execs:6d} execs, {cov:4d} cov ({rate:5.1f}%), {finds:3d} finds"
                )
            lines.append("")

        dd = self.deser_diag
        if dd.get("total", 0) > 0:
            total = dd["total"]
            comp = dd.get("compiled", 0)
            deser = dd.get("deserialized", 0)
            lines.append("  Deser pipeline diagnostics:")
            lines.append(f"    Total executions:    {total}")
            lines.append(f"    Compiled:            {comp} ({comp/total*100:.1f}%)")
            lines.append(f"    Deserialized:        {deser} ({deser/total*100:.1f}%)")
            sinks = dd.get("sink_hits", {})
            if sinks:
                lines.append(f"    Sink hits:")
                for sk, cnt in sorted(sinks.items(), key=lambda x: -x[1]):
                    lines.append(f"      {sk:20s}: {cnt}")
            oracle_pos = dd.get("oracle_positive", 0)
            oracle_dedup = dd.get("oracle_deduped", 0)
            if oracle_pos:
                lines.append(f"    Oracle positive:     {oracle_pos}")
                lines.append(f"    After dedup:         {oracle_pos - oracle_dedup}")
            exc = dd.get("exceptions_top5", [])
            if exc:
                lines.append(f"    Top exceptions:")
                for cls, cnt in exc:
                    lines.append(f"      {cls:45s}: {cnt}")
            lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    def _report_json(self) -> str:
        return json.dumps({
            "elapsed_seconds": self.elapsed(),
            "total_executions": self.total_executions,
            "executions_per_second": round(self.executions_per_second, 1),
            "corpus_size": self.corpus_size,
            "total_edges": self.total_edges,
            "peak_edges": self.peak_edges,
            "unique_findings": self.unique_findings,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_oracle": self.findings_by_oracle,
            "mutations_by_mutator": self.mutations_by_mutator,
            "new_coverage_by_mutator": self.new_coverage_by_mutator,
            "findings_by_mutator": self.findings_by_mutator,
            "strategy_execs": self.strategy_execs,
            "strategy_coverage": self.strategy_coverage,
            "strategy_findings": self.strategy_findings,
            **({"deser_diagnostics": self.deser_diag} if self.deser_diag else {}),
        }, indent=2)

    @staticmethod
    def _strip_finding(finding: Finding) -> None:
        """Strip heavy data from a Finding to free memory.

        Called after incremental disk save.  Keeps title, severity,
        fingerprint, oracle_name, and a compact metadata summary.
        Preserves exit_code and duration_ms for post-session analysis.
        """
        finding.input = Input(data=b"", metadata={})
        finding.result = ExecutionResult(
            exit_code=finding.result.exit_code,
            duration_ms=finding.result.duration_ms,
        )

    def _save_finding_incremental(self, finding: Finding) -> None:
        """Write a single finding to disk immediately when discovered."""
        if self.output_dir is None:
            return
        try:
            findings_dir = self.output_dir / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            idx = len(self.findings) - 1
            f_dir = findings_dir / f"{idx:04d}_{finding.severity.value}_{finding.oracle_name}"
            f_dir.mkdir(exist_ok=True)
            input_data = finding.input.data
            if len(input_data) == 0:
                logger.warning("_save_finding_incremental: EMPTY input data for finding %d!", idx)
                (f_dir / "input").write_bytes(b"<empty>")
            else:
                (f_dir / "input").write_bytes(input_data)
            (f_dir / "info.json").write_text(json.dumps({
                "title": finding.title,
                "severity": finding.severity.value,
                "oracle": finding.oracle_name,
                "fingerprint": finding.fingerprint,
                "exit_code": finding.result.exit_code,
                "duration_ms": finding.result.duration_ms,
                "metadata": finding.metadata,
            }, default=str, indent=2), encoding="utf-8")
            self._saved_finding_count = len(self.findings)
        except Exception as e:
            logger.warning("Failed to save finding %d incrementally: %s", idx, e)

    def save(self, path: Path) -> None:
        """Save report and findings to disk.

        Findings already written incrementally are skipped.
        Each step is isolated so a single failure won't block the rest.
        """
        path.mkdir(parents=True, exist_ok=True)

        # Save reports first (lightweight, most likely to succeed)
        try:
            (path / "report.txt").write_text(self.report("text"), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to save report.txt: %s", e)
        try:
            (path / "report.json").write_text(self.report("json"), encoding="utf-8")
        except Exception as e:
            logger.error("Failed to save report.json: %s", e)

        # Save individual findings
        findings_dir = path / "findings"
        findings_dir.mkdir(exist_ok=True)
        save_errors = 0
        for i, finding in enumerate(self.findings):
            f_dir = findings_dir / f"{i:04d}_{finding.severity.value}_{finding.oracle_name}"
            if f_dir.exists():
                continue  # already saved incrementally
            try:
                f_dir.mkdir(exist_ok=True)
                (f_dir / "input").write_bytes(finding.input.data)
                (f_dir / "info.json").write_text(json.dumps({
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "oracle": finding.oracle_name,
                    "fingerprint": finding.fingerprint,
                    "exit_code": finding.result.exit_code,
                    "duration_ms": finding.result.duration_ms,
                    "metadata": finding.metadata,
                }, default=str, indent=2), encoding="utf-8")
            except Exception as e:
                save_errors += 1
                logger.error("Failed to save finding %d: %s", i, e)
        if save_errors:
            logger.error("Failed to save %d/%d findings", save_errors, len(self.findings))

    # ── Checkpoint (full state save/restore) ──────────────────────

    def to_checkpoint_dict(self) -> dict:
        """Serialize stats state for checkpoint (excludes Finding objects)."""
        return {
            "total_iterations": self.total_iterations,
            "total_executions": self.total_executions,
            "total_edges": self.total_edges,
            "peak_edges": self.peak_edges,
            "total_findings": self.total_findings,
            "unique_findings": self.unique_findings,
            "corpus_size": self.corpus_size,
            "corpus_bytes": self.corpus_bytes,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_oracle": self.findings_by_oracle,
            "mutations_by_mutator": self.mutations_by_mutator,
            "findings_by_mutator": self.findings_by_mutator,
            "new_coverage_by_mutator": self.new_coverage_by_mutator,
            "strategy_execs": self.strategy_execs,
            "strategy_coverage": self.strategy_coverage,
            "strategy_findings": self.strategy_findings,
            "coverage_over_time": self.coverage_over_time,
            "deser_diag": self.deser_diag,
            "elapsed_at_checkpoint": self.elapsed(),
        }

    def load_checkpoint_dict(self, d: dict, *, resumed_at: float | None = None) -> None:
        """Restore stats state from checkpoint dict.

        Time accounting: ``start_time`` is adjusted so that ``elapsed()``
        returns the total wall-clock across sessions.
        """
        self.total_iterations = d.get("total_iterations", 0)
        self.total_executions = d.get("total_executions", 0)
        self.total_edges = d.get("total_edges", 0)
        self.peak_edges = d.get("peak_edges", 0)
        self.total_findings = d.get("total_findings", 0)
        self.unique_findings = d.get("unique_findings", 0)
        self.corpus_size = d.get("corpus_size", 0)
        self.corpus_bytes = d.get("corpus_bytes", 0)
        self.findings_by_severity = d.get("findings_by_severity", {})
        self.findings_by_oracle = d.get("findings_by_oracle", {})
        self.mutations_by_mutator = d.get("mutations_by_mutator", {})
        self.findings_by_mutator = d.get("findings_by_mutator", {})
        self.new_coverage_by_mutator = d.get("new_coverage_by_mutator", {})
        self.strategy_execs = d.get("strategy_execs", {})
        self.strategy_coverage = d.get("strategy_coverage", {})
        self.strategy_findings = d.get("strategy_findings", {})
        self.coverage_over_time = d.get("coverage_over_time", [])
        self.deser_diag = d.get("deser_diag", {})

        # Adjust start_time so elapsed() is continuous across sessions
        prev_elapsed = d.get("elapsed_at_checkpoint", 0.0)
        now = resumed_at or time.time()
        self.start_time = now - prev_elapsed

        # Recompute exec/s
        if prev_elapsed > 0:
            self.executions_per_second = self.total_executions / prev_elapsed
