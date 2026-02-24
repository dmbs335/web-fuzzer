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

    # Timing
    last_new_coverage_at: float = 0.0
    last_finding_at: float = 0.0

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
        }, indent=2)

    def save(self, path: Path) -> None:
        """Save report and findings to disk."""
        path.mkdir(parents=True, exist_ok=True)
        (path / "report.txt").write_text(self.report("text"), encoding="utf-8")
        (path / "report.json").write_text(self.report("json"), encoding="utf-8")

        findings_dir = path / "findings"
        findings_dir.mkdir(exist_ok=True)
        for i, finding in enumerate(self.findings):
            f_dir = findings_dir / f"{i:04d}_{finding.severity.value}_{finding.oracle_name}"
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
