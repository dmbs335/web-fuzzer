"""Report generation: JSON file + terminal summary for frontier analysis."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from .collector import CoverageReport
from .frontier import FrontierBranch

logger = logging.getLogger(__name__)


def generate_json_report(
    session_name: str,
    coverage: CoverageReport,
    frontiers: dict[str, list[FrontierBranch]],
    output_path: Path,
    multi_target_outputs: dict[str, dict[str, dict]] | None = None,
) -> None:
    """Write full JSON report to disk.

    Args:
        session_name: Human-readable session identifier.
        coverage: CoverageReport from collector.
        frontiers: {target_name: [FrontierBranch, ...]}
        output_path: Where to write the JSON file.
        multi_target_outputs: {input_id: {target_name: output_dict}} for diff context.
    """
    report = {
        "session": session_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "coverage_summary": _build_coverage_summary(coverage),
        "frontiers_total": sum(len(fl) for fl in frontiers.values()),
        "frontiers_security_relevant": sum(
            1 for fl in frontiers.values() for f in fl if f.security_score >= 0.3
        ),
        "frontiers": [],
    }

    frontier_id = 0
    for target_name, branch_list in frontiers.items():
        for fb in branch_list:
            frontier_id += 1
            entry = {
                "id": f"F{frontier_id:03d}",
                "target": target_name,
                "file": fb.file,
                "file_basename": fb.file_basename,
                "line": fb.line,
                "function": fb.function_name,
                "class": fb.class_name or None,
                "branch_type": fb.branch_type,
                "condition": fb.condition,
                "context": fb.context,
                "context_range": [fb.context_start, fb.context_end],
                "function_source": fb.function_source if fb.function_source else None,
                "function_range": [fb.function_start, fb.function_end] if fb.function_source else None,
                "security_score": round(fb.security_score, 3),
                "security_keywords": fb.security_keywords,
                "adjacent_covered_lines": fb.adjacent_covered,
            }

            # Full reaching input details
            if fb.reaching_input_details:
                entry["reaching_inputs"] = []
                for ri in fb.reaching_input_details:
                    ri_entry = {
                        "input_id": ri.input_id,
                        "input_data": ri.input_data,
                        "target_output": ri.output,
                        "covered_lines_in_file": ri.covered_lines_in_file,
                    }
                    # Add other targets' outputs for diff context
                    if multi_target_outputs and ri.input_id in multi_target_outputs:
                        other_outputs = {}
                        for other_target, other_out in multi_target_outputs[ri.input_id].items():
                            if other_target != target_name:
                                other_outputs[other_target] = other_out
                        if other_outputs:
                            ri_entry["other_targets"] = other_outputs
                    entry["reaching_inputs"].append(ri_entry)
            else:
                entry["reaching_inputs"] = fb.reaching_inputs[:20]

            report["frontiers"].append(entry)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    logger.info("JSON report written to %s", output_path)


def print_terminal_summary(
    session_name: str,
    coverage: CoverageReport,
    frontiers: dict[str, list[FrontierBranch]],
    top_n: int = 20,
    multi_target_outputs: dict[str, dict[str, dict]] | None = None,
) -> None:
    """Print formatted terminal summary."""
    out = sys.stdout

    out.write("\n")
    out.write("═══ Coverage Frontier Analysis ═══\n")
    out.write(f"Session: {session_name}\n")
    out.write(
        f"Corpus: {coverage.corpus_size} entries analyzed | "
        f"{len(coverage.targets)} targets | "
        f"{coverage.elapsed_seconds:.1f}s\n"
    )

    # Per-target coverage
    out.write("\n── Per-Target Coverage ──\n")
    for tname, tcov in coverage.targets.items():
        files_covered = len(tcov.global_covered)
        lines_covered = tcov.total_lines_covered
        out.write(f"  {tname:40s} {lines_covered:>5d} lines in {files_covered} files\n")

    # Security-relevant frontiers
    all_frontiers = []
    for target_name, branch_list in frontiers.items():
        all_frontiers.extend(branch_list)

    all_frontiers.sort(key=lambda f: -f.security_score)
    shown = all_frontiers[:top_n]

    total_frontiers = len(all_frontiers)
    total_relevant = sum(1 for f in all_frontiers if f.security_score >= 0.3)

    out.write(f"\n── Security-Relevant Frontiers (top {min(top_n, len(shown))}) ──\n")

    for i, fb in enumerate(shown):
        stars = _star_rating(fb.security_score)
        qualified = fb.function_name
        if fb.class_name:
            qualified = f"{fb.class_name}.{fb.function_name}"

        out.write(f"\n{'─'*70}\n")
        out.write(
            f"[F{i+1:03d}] {stars} {fb.target_name} | "
            f"{qualified} L{fb.line}\n"
        )
        out.write(f"  Branch: {fb.condition[:120]}\n")
        out.write(
            f"  Score: {fb.security_score:.2f} | "
            f"Reached by: {len(fb.reaching_inputs)} inputs | "
            f"Type: {fb.branch_type}\n"
        )

        # Show compact context (5 lines around frontier)
        if fb.context:
            out.write("\n  Source context:\n")
            ctx_lines = fb.context.split("\n")
            center_idx = None
            for j, line in enumerate(ctx_lines):
                if line.startswith("→"):
                    center_idx = j
                    break
            if center_idx is not None:
                start = max(0, center_idx - 3)
                end = min(len(ctx_lines), center_idx + 4)
                for line in ctx_lines[start:end]:
                    marker = "  ◀ FRONTIER" if line.startswith("→") else ""
                    out.write(f"    {line}{marker}\n")

        # Show reaching inputs with full data + output
        if fb.reaching_input_details:
            out.write(f"\n  Reaching inputs ({len(fb.reaching_input_details)}):\n")
            for ri in fb.reaching_input_details[:3]:
                out.write(f"\n    [{ri.input_id}]\n")
                # Full input data (cap at 500 chars for terminal)
                input_preview = ri.input_data[:500]
                if len(ri.input_data) > 500:
                    input_preview += f"... ({len(ri.input_data)} total)"
                out.write(f"    Input: {input_preview}\n")
                # Target output
                if ri.output:
                    out_str = json.dumps(ri.output, ensure_ascii=False, default=str)
                    if len(out_str) > 300:
                        out_str = out_str[:300] + "..."
                    out.write(f"    Output: {out_str}\n")
                # Covered lines in this file
                if ri.covered_lines_in_file:
                    out.write(f"    Covered lines in {fb.file_basename}: {ri.covered_lines_in_file}\n")

                # Diff with other targets
                if multi_target_outputs and ri.input_id in multi_target_outputs:
                    others = multi_target_outputs[ri.input_id]
                    for other_name, other_out in others.items():
                        if other_name != fb.target_name and other_out:
                            other_str = json.dumps(other_out, ensure_ascii=False, default=str)
                            if len(other_str) > 300:
                                other_str = other_str[:300] + "..."
                            out.write(f"    [{other_name}]: {other_str}\n")

    out.write(f"\n{'─'*70}\n")
    out.write("── Summary ──\n")
    out.write(
        f"{total_frontiers} total frontiers | "
        f"{total_relevant} security-relevant (score >= 0.3)\n"
    )


def _build_coverage_summary(coverage: CoverageReport) -> dict:
    """Build coverage summary dict for JSON report."""
    per_target = {}
    for tname, tcov in coverage.targets.items():
        files_detail = {}
        for fname, lines in tcov.global_covered.items():
            files_detail[fname] = {
                "lines_covered": len(lines),
                "line_range": [min(lines), max(lines)] if lines else [0, 0],
            }
        per_target[tname] = {
            "files_covered": len(tcov.global_covered),
            "lines_covered": tcov.total_lines_covered,
            "files": files_detail,
        }

    return {
        "corpus_analyzed": coverage.corpus_size,
        "targets_instrumented": len(coverage.targets),
        "elapsed_seconds": round(coverage.elapsed_seconds, 2),
        "per_target": per_target,
    }


def _star_rating(score: float) -> str:
    """Convert security score to star rating."""
    if score >= 0.7:
        return "★★★"
    elif score >= 0.5:
        return "★★☆"
    elif score >= 0.3:
        return "★☆☆"
    else:
        return "☆☆☆"
