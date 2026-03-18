"""Verification loop: test whether seed candidates actually hit frontier branches.

Workflow:
  1. Load frontier report (from near_miss_analyzer)
  2. Run candidate seeds through instrumented targets
  3. Check if each seed's covered lines include the frontier branch line
  4. Report: which seeds hit which frontiers, which are still missed
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .collector import CoverageCollector, InputCoverage

logger = logging.getLogger(__name__)


@dataclass
class VerifyResult:
    """Result of verifying one seed against frontiers."""

    seed_file: str
    seed_data: str
    hits: list[FrontierHit]
    new_lines_by_file: dict[str, list[int]]  # new lines covered per file


@dataclass
class FrontierHit:
    """A seed successfully hit a frontier branch."""

    frontier_id: str
    file: str
    line: int
    function: str
    condition: str
    target: str


@dataclass
class VerifyReport:
    """Full verification report."""

    frontiers_total: int
    frontiers_hit: int
    frontiers_missed: int
    seeds_total: int
    seeds_with_hits: int
    results: list[VerifyResult]
    hit_frontier_ids: set[str]
    missed_frontier_ids: set[str]
    elapsed_seconds: float = 0.0


class FrontierVerifier:
    """Verify whether candidate seeds hit frontier branches."""

    def __init__(
        self,
        target_configs: dict[str, str],
        working_dir: Path | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.collector = CoverageCollector(
            target_configs=target_configs,
            working_dir=working_dir,
            timeout=timeout,
        )
        self.target_configs = target_configs

    def verify(
        self,
        frontier_report_path: Path,
        seed_dir: Path,
        target_filter: str | None = None,
    ) -> VerifyReport:
        """Run seeds and check which frontiers they hit.

        Args:
            frontier_report_path: Path to near_miss_frontiers.json
            seed_dir: Directory containing candidate seed files
            target_filter: Only check frontiers for this target (optional)
        """
        start = time.monotonic()

        # Load frontier report
        report_data = json.loads(frontier_report_path.read_text(encoding="utf-8"))
        frontiers = report_data.get("frontiers", [])
        if target_filter:
            frontiers = [f for f in frontiers if target_filter in f["target"]]

        if not frontiers:
            logger.warning("No frontiers to verify")
            return VerifyReport(
                frontiers_total=0, frontiers_hit=0, frontiers_missed=0,
                seeds_total=0, seeds_with_hits=0, results=[],
                hit_frontier_ids=set(), missed_frontier_ids=set(),
            )

        # Build frontier lookup: {(file_basename, line): frontier}
        frontier_lookup: dict[tuple[str, int], list[dict]] = {}
        for f in frontiers:
            key = (f["file_basename"], f["line"])
            frontier_lookup.setdefault(key, []).append(f)

        # Load seeds
        seed_files = sorted(seed_dir.iterdir())
        seed_files = [f for f in seed_files if f.is_file()]
        if not seed_files:
            logger.warning("No seed files in %s", seed_dir)
            return VerifyReport(
                frontiers_total=len(frontiers), frontiers_hit=0,
                frontiers_missed=len(frontiers), seeds_total=0,
                seeds_with_hits=0, results=[],
                hit_frontier_ids=set(),
                missed_frontier_ids={f["id"] for f in frontiers},
            )

        logger.info("Verifying %d seeds against %d frontiers", len(seed_files), len(frontiers))

        # Collect coverage for seeds
        # Write seeds as temporary corpus
        import tempfile
        import shutil
        tmpdir = Path(tempfile.mkdtemp(prefix="nearmiss_verify_"))
        try:
            for i, sf in enumerate(seed_files):
                dst = tmpdir / f"id_{i:06d}"
                shutil.copy2(sf, dst)

            coverage = self.collector.collect(tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        # Check hits
        results: list[VerifyResult] = []
        all_hit_ids: set[str] = set()

        for target_name, tcov in coverage.targets.items():
            for ic in tcov.per_input:
                # Map back to original seed file
                idx = int(ic.input_id.replace("id_", ""))
                if idx >= len(seed_files):
                    continue
                seed_file = seed_files[idx]

                hits: list[FrontierHit] = []

                # Check each covered file:line against frontier lookup
                for filename, lines in ic.covered_lines.items():
                    basename = Path(filename).name
                    for line in lines:
                        key = (basename, line)
                        if key in frontier_lookup:
                            for f in frontier_lookup[key]:
                                hit = FrontierHit(
                                    frontier_id=f["id"],
                                    file=f["file"],
                                    line=f["line"],
                                    function=f["function"],
                                    condition=f["condition"][:100],
                                    target=target_name,
                                )
                                hits.append(hit)
                                all_hit_ids.add(f["id"])

                # Compute new lines (lines not in original frontier's adjacent_covered)
                new_lines: dict[str, list[int]] = {}
                for filename, lines in ic.new_lines.items():
                    if lines:
                        new_lines[Path(filename).name] = sorted(lines)

                try:
                    input_str = ic.input_data.decode("utf-8", errors="replace")
                except Exception:
                    input_str = repr(ic.input_data[:200])

                results.append(VerifyResult(
                    seed_file=seed_file.name,
                    seed_data=input_str,
                    hits=hits,
                    new_lines_by_file=new_lines,
                ))

        all_frontier_ids = {f["id"] for f in frontiers}
        missed_ids = all_frontier_ids - all_hit_ids

        elapsed = time.monotonic() - start

        return VerifyReport(
            frontiers_total=len(frontiers),
            frontiers_hit=len(all_hit_ids),
            frontiers_missed=len(missed_ids),
            seeds_total=len(seed_files),
            seeds_with_hits=sum(1 for r in results if r.hits),
            results=results,
            hit_frontier_ids=all_hit_ids,
            missed_frontier_ids=missed_ids,
            elapsed_seconds=elapsed,
        )


def print_verify_report(report: VerifyReport) -> None:
    """Print verification results to terminal."""
    out = sys.stdout

    out.write("\n═══ Frontier Verification Report ═══\n")
    out.write(f"Seeds: {report.seeds_total} | Frontiers: {report.frontiers_total}\n")
    out.write(f"Elapsed: {report.elapsed_seconds:.1f}s\n\n")

    # Summary
    hit_pct = (report.frontiers_hit / report.frontiers_total * 100) if report.frontiers_total else 0
    out.write(f"── Results ──\n")
    out.write(f"  Frontiers HIT:    {report.frontiers_hit}/{report.frontiers_total} ({hit_pct:.0f}%)\n")
    out.write(f"  Frontiers MISSED: {report.frontiers_missed}/{report.frontiers_total}\n")
    out.write(f"  Seeds with hits:  {report.seeds_with_hits}/{report.seeds_total}\n\n")

    # Per-seed details
    if report.results:
        out.write("── Per-Seed Results ──\n")
        for r in report.results:
            if r.hits:
                marker = "✓"
                hit_ids = sorted(set(h.frontier_id for h in r.hits))
                out.write(f"\n  {marker} {r.seed_file} → HIT {hit_ids}\n")
                for h in r.hits:
                    out.write(f"      {h.frontier_id} {h.target} | {h.function} L{h.line}: {h.condition}\n")
            else:
                out.write(f"\n  ✗ {r.seed_file} → no frontier hits\n")

            if r.new_lines_by_file:
                for fname, lines in r.new_lines_by_file.items():
                    out.write(f"      new lines in {fname}: {lines[:20]}\n")

    # Missed frontiers
    if report.missed_frontier_ids:
        out.write(f"\n── Still Missed ({len(report.missed_frontier_ids)}) ──\n")
        for fid in sorted(report.missed_frontier_ids):
            out.write(f"  {fid}\n")

    out.write("\n")


def save_verify_report(report: VerifyReport, output_path: Path) -> None:
    """Save verification report as JSON."""
    data = {
        "frontiers_total": report.frontiers_total,
        "frontiers_hit": report.frontiers_hit,
        "frontiers_missed": report.frontiers_missed,
        "seeds_total": report.seeds_total,
        "seeds_with_hits": report.seeds_with_hits,
        "hit_frontier_ids": sorted(report.hit_frontier_ids),
        "missed_frontier_ids": sorted(report.missed_frontier_ids),
        "elapsed_seconds": round(report.elapsed_seconds, 2),
        "results": [
            {
                "seed_file": r.seed_file,
                "seed_data": r.seed_data[:2000],
                "hits": [
                    {
                        "frontier_id": h.frontier_id,
                        "file": h.file,
                        "line": h.line,
                        "function": h.function,
                        "condition": h.condition,
                        "target": h.target,
                    }
                    for h in r.hits
                ],
                "new_lines": r.new_lines_by_file,
            }
            for r in report.results
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("Verify report written to %s", output_path)
