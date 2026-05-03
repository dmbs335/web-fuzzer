"""Fuzzing session statistics and reporting."""

from __future__ import annotations

from collections import Counter
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
    observed_findings: int = 0
    total_findings: int = 0
    unique_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_oracle: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    selection_drops_total: int = 0
    selection_drops_by_reason: dict[str, int] = field(default_factory=dict)
    orbit_downgrades_total: int = 0
    orbit_downgrades_by_reason: dict[str, int] = field(default_factory=dict)
    shadow_replay_loaded_total: int = 0

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

    def _safe_ratio(self, numerator: int, denominator: int) -> float:
        if denominator <= 0:
            return 0.0
        return round(numerator / denominator, 4)

    def selection_summary(self) -> dict[str, object]:
        """Return survivor/drop summary for selection-blindness reporting."""
        observed = self.observed_findings
        survived = self.unique_findings
        dropped = self.selection_drops_total
        top_drop_reasons = [
            {
                "reason": reason,
                "count": count,
                "rate_over_observed": self._safe_ratio(count, observed),
                "share_of_drops": self._safe_ratio(count, dropped),
            }
            for reason, count in sorted(
                self.selection_drops_by_reason.items(),
                key=lambda item: (-item[1], item[0]),
            )[:3]
        ]
        reason_summary = {
            reason: {
                "count": count,
                "rate_over_observed": self._safe_ratio(count, observed),
                "share_of_drops": self._safe_ratio(count, dropped),
            }
            for reason, count in sorted(self.selection_drops_by_reason.items())
        }
        return {
            "observed_findings": observed,
            "survived_findings": survived,
            "dropped_findings": dropped,
            "survivor_rate": self._safe_ratio(survived, observed),
            "drop_rate": self._safe_ratio(dropped, observed),
            "drop_reasons": reason_summary,
            "top_drop_reasons": top_drop_reasons,
        }

    def shadow_replay_summary(self) -> dict[str, object]:
        """Return replay-loop summary for promoted shadow seeds."""
        execs = self.mutations_by_mutator.get("shadow_replay_seed", 0)
        findings = self.findings_by_mutator.get("shadow_replay_seed", 0)
        new_cov = self.new_coverage_by_mutator.get("shadow_replay_seed", 0)
        loaded = self.shadow_replay_loaded_total
        return {
            "loaded_seeds": loaded,
            "executions": execs,
            "findings": findings,
            "new_coverage_events": new_cov,
            "finding_rate_per_loaded": self._safe_ratio(findings, loaded),
            "execution_rate_per_loaded": self._safe_ratio(execs, loaded),
        }

    def interface_progress_summary(self) -> dict[str, object]:
        """Summarize progress across the observation/persistence/certificate pipeline.

        The current engine has a fully explicit observation and persistence
        layer, while certificate/promotion still coincides with persisted
        findings. We still report the three interfaces separately so runtime
        diagnostics can say where progress exists and where it stops.
        """
        observed = self.observed_findings
        persisted = self.unique_findings
        certified = self.total_findings
        return {
            "observation_candidates": observed,
            "persistence_survivors": persisted,
            "certificate_promotions": certified,
            "observation_nonzero": observed > 0,
            "persistence_nonzero": persisted > 0,
            "certificate_nonzero": certified > 0,
            "persistence_rate_over_observation": self._safe_ratio(persisted, observed),
            "certificate_rate_over_observation": self._safe_ratio(certified, observed),
            "certificate_rate_over_persistence": self._safe_ratio(certified, persisted),
        }

    def timeout_family_summary(self) -> dict[str, object]:
        """Summarize timeout findings by WAF timeout-family witness metadata."""
        timeout_findings = [
            finding
            for finding in self.findings
            if finding.oracle_name == "crash" and bool(finding.metadata.get("timeout"))
        ]
        if not timeout_findings:
            return {
                "total_timeouts": 0,
                "families": {},
                "parsers": {},
                "evasions": {},
                "transforms": {},
                "top_families": [],
            }

        family_counts: Counter[str] = Counter()
        parser_counts: Counter[str] = Counter()
        evasion_counts: Counter[str] = Counter()
        transform_counts: Counter[str] = Counter()

        for finding in timeout_findings:
            meta = finding.metadata or {}
            family = str(meta.get("waf_timeout_family") or "unclassified")
            parser = str(meta.get("waf_timeout_axis_parser") or "unknown")
            evasion = str(meta.get("waf_timeout_axis_evasion") or "unknown")
            family_counts[family] += 1
            parser_counts[parser] += 1
            evasion_counts[evasion] += 1
            for transform in meta.get("waf_timeout_transforms") or []:
                label = str(transform or "").strip()
                if label:
                    transform_counts[label] += 1

        top_families = [
            {"family": family, "count": count}
            for family, count in family_counts.most_common(3)
        ]
        return {
            "total_timeouts": len(timeout_findings),
            "families": dict(sorted(family_counts.items())),
            "parsers": dict(sorted(parser_counts.items())),
            "evasions": dict(sorted(evasion_counts.items())),
            "transforms": dict(sorted(transform_counts.items())),
            "top_families": top_families,
        }

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

    def record_observed_finding(self, finding: Finding) -> None:
        self.observed_findings += 1

    def record_selection_drop(self, drop_reason: str) -> None:
        self.selection_drops_total += 1
        self.selection_drops_by_reason[drop_reason] = (
            self.selection_drops_by_reason.get(drop_reason, 0) + 1
        )

    def record_orbit_downgrade(self, downgrade_reason: str) -> None:
        self.orbit_downgrades_total += 1
        self.orbit_downgrades_by_reason[downgrade_reason] = (
            self.orbit_downgrades_by_reason.get(downgrade_reason, 0) + 1
        )

    def record_shadow_replay_loaded(self, count: int = 1) -> None:
        self.shadow_replay_loaded_total += max(count, 0)

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
        selection = self.selection_summary()
        interface_progress = self.interface_progress_summary()
        line = (
            f"[{elapsed:7.1f}s] "
            f"execs: {self.total_executions} "
            f"({self.executions_per_second:.0f}/s) | "
            f"corpus: {self.corpus_size} | "
            f"edges: {self.total_edges} | "
            f"findings: {self.unique_findings}"
        )
        if self.selection_drops_total or self.orbit_downgrades_total:
            line += (
                f" | obs={self.observed_findings}"
                f" drop={self.selection_drops_total}"
                f" orbit_dg={self.orbit_downgrades_total}"
                f" surv={selection['survivor_rate']:.0%}"
                f" drop_rate={selection['drop_rate']:.0%}"
            )
            top_reasons = selection["top_drop_reasons"]
            if top_reasons:
                reasons_str = ",".join(
                    f"{entry['reason']}:{entry['count']}" for entry in top_reasons
                )
                line += f" top_drop=[{reasons_str}]"
        if any(
            interface_progress[key]
            for key in ("observation_candidates", "persistence_survivors", "certificate_promotions")
        ):
            line += (
                f" | iface=o:{int(interface_progress['observation_nonzero'])}"
                f"/p:{int(interface_progress['persistence_nonzero'])}"
                f"/c:{int(interface_progress['certificate_nonzero'])}"
            )
        shadow_replay = self.shadow_replay_summary()
        if shadow_replay["loaded_seeds"] or shadow_replay["executions"] or shadow_replay["findings"]:
            line += (
                f" | shadow=ld:{shadow_replay['loaded_seeds']}"
                f"/ex:{shadow_replay['executions']}"
                f"/fd:{shadow_replay['findings']}"
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
            f"  Observed findings:{self.observed_findings}",
            f"  Selection drops: {self.selection_drops_total}",
            f"  Orbit downgrades:{self.orbit_downgrades_total}",
            "",
        ]

        selection = self.selection_summary()
        shadow_replay = self.shadow_replay_summary()
        interface_progress = self.interface_progress_summary()
        timeout_summary = self.timeout_family_summary()
        if self.observed_findings or self.selection_drops_total:
            lines.extend([
                "  Selection summary:",
                f"    Survivors:          {selection['survived_findings']}",
                f"    Drops:              {selection['dropped_findings']}",
                f"    Survivor rate:      {selection['survivor_rate']:.1%}",
                f"    Drop rate:          {selection['drop_rate']:.1%}",
                "",
            ])

        if any(
            interface_progress[key]
            for key in ("observation_candidates", "persistence_survivors", "certificate_promotions")
        ):
            lines.extend([
                "  Interface progress:",
                f"    Observation:        {interface_progress['observation_candidates']}"
                f" (nonzero={interface_progress['observation_nonzero']})",
                f"    Persistence:        {interface_progress['persistence_survivors']}"
                f" (rate={interface_progress['persistence_rate_over_observation']:.1%})",
                f"    Certificate:        {interface_progress['certificate_promotions']}"
                f" (rate={interface_progress['certificate_rate_over_persistence']:.1%} over persistence)",
                "",
            ])

        if shadow_replay["loaded_seeds"] or shadow_replay["executions"] or shadow_replay["findings"]:
            lines.extend([
                "  Shadow replay summary:",
                f"    Loaded seeds:        {shadow_replay['loaded_seeds']}",
                f"    Replay execs:        {shadow_replay['executions']}",
                f"    Replay findings:     {shadow_replay['findings']}",
                f"    Replay new coverage: {shadow_replay['new_coverage_events']}",
                f"    Findings / loaded:   {shadow_replay['finding_rate_per_loaded']:.1%}",
                "",
            ])

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

        if timeout_summary["total_timeouts"]:
            lines.append("  Timeout family summary:")
            lines.append(f"    Total timeouts:      {timeout_summary['total_timeouts']}")
            for entry in timeout_summary["top_families"]:
                lines.append(f"    {entry['family']:20s}: {entry['count']}")
            lines.append("")

        if self.selection_drops_by_reason:
            lines.append("  Selection drops by reason:")
            for reason, count in sorted(self.selection_drops_by_reason.items()):
                reason_summary = selection["drop_reasons"][reason]
                lines.append(
                    "    "
                    f"{reason:20s}: {count}"
                    f" (obs_rate={reason_summary['rate_over_observed']:.1%},"
                    f" drop_share={reason_summary['share_of_drops']:.1%})"
                )
            lines.append("")
            top_reasons = selection["top_drop_reasons"]
            if top_reasons:
                lines.append("  Top selection drop reasons:")
                for entry in top_reasons:
                    lines.append(
                        "    "
                        f"{entry['reason']:20s}: {entry['count']}"
                        f" (obs_rate={entry['rate_over_observed']:.1%},"
                        f" drop_share={entry['share_of_drops']:.1%})"
                    )
                lines.append("")

        if self.orbit_downgrades_by_reason:
            lines.append("  Orbit downgrades by reason:")
            for reason, count in sorted(self.orbit_downgrades_by_reason.items()):
                lines.append(f"    {reason:20s}: {count}")
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
        selection = self.selection_summary()
        shadow_replay = self.shadow_replay_summary()
        interface_progress = self.interface_progress_summary()
        timeout_summary = self.timeout_family_summary()
        return json.dumps({
            "elapsed_seconds": self.elapsed(),
            "observed_findings": self.observed_findings,
            "total_executions": self.total_executions,
            "executions_per_second": round(self.executions_per_second, 1),
            "corpus_size": self.corpus_size,
            "total_edges": self.total_edges,
            "peak_edges": self.peak_edges,
            "unique_findings": self.unique_findings,
            "selection_drops_total": self.selection_drops_total,
            "selection_drops_by_reason": self.selection_drops_by_reason,
            "selection_summary": selection,
            "orbit_downgrades_total": self.orbit_downgrades_total,
            "orbit_downgrades_by_reason": self.orbit_downgrades_by_reason,
            "shadow_replay_loaded_total": self.shadow_replay_loaded_total,
            "shadow_replay_summary": shadow_replay,
            "interface_progress": interface_progress,
            "timeout_family_summary": timeout_summary,
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
            "observed_findings": self.observed_findings,
            "corpus_size": self.corpus_size,
            "corpus_bytes": self.corpus_bytes,
            "selection_drops_total": self.selection_drops_total,
            "selection_drops_by_reason": self.selection_drops_by_reason,
            "orbit_downgrades_total": self.orbit_downgrades_total,
            "orbit_downgrades_by_reason": self.orbit_downgrades_by_reason,
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
        self.observed_findings = d.get("observed_findings", 0)
        self.corpus_size = d.get("corpus_size", 0)
        self.corpus_bytes = d.get("corpus_bytes", 0)
        self.selection_drops_total = d.get("selection_drops_total", 0)
        self.selection_drops_by_reason = d.get("selection_drops_by_reason", {})
        self.orbit_downgrades_total = d.get("orbit_downgrades_total", 0)
        self.orbit_downgrades_by_reason = d.get("orbit_downgrades_by_reason", {})
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
