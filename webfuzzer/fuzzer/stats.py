"""Fuzzing session statistics and reporting."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .protocols import Finding, Severity


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
        return (
            f"[{elapsed:7.1f}s] "
            f"execs: {self.total_executions} "
            f"({self.executions_per_second:.0f}/s) | "
            f"corpus: {self.corpus_size} | "
            f"edges: {self.total_edges} | "
            f"findings: {self.unique_findings}"
        )

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
        }, indent=2)

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
            self._saved_finding_count = len(self.findings)
        except Exception:
            pass  # best-effort; full save at session end is the fallback

    def save(self, path: Path) -> None:
        """Save report and findings to disk.

        Findings already written incrementally are skipped.
        """
        path.mkdir(parents=True, exist_ok=True)
        (path / "report.txt").write_text(self.report("text"), encoding="utf-8")
        (path / "report.json").write_text(self.report("json"), encoding="utf-8")

        findings_dir = path / "findings"
        findings_dir.mkdir(exist_ok=True)
        for i, finding in enumerate(self.findings):
            f_dir = findings_dir / f"{i:04d}_{finding.severity.value}_{finding.oracle_name}"
            if f_dir.exists():
                continue  # already saved incrementally
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

        # Adjust start_time so elapsed() is continuous across sessions
        prev_elapsed = d.get("elapsed_at_checkpoint", 0.0)
        now = resumed_at or time.time()
        self.start_time = now - prev_elapsed

        # Recompute exec/s
        if prev_elapsed > 0:
            self.executions_per_second = self.total_executions / prev_elapsed
