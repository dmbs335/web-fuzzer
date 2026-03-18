"""Gadget scoring and reporting for DOM Clobbering analysis.

Scores each source->sink gadget based on exploitability factors:
sink severity, chain depth, guard presence, framework patterns.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from .js_ast_parser import ClobberSource, ClobberSink, Guard
from .js_framework_patterns import match_property
from .js_taint_tracker import Gadget

logger = logging.getLogger(__name__)


# Sink severity scores
SINK_SCORES: dict[str, int] = {
    # CRITICAL
    "eval": 30, "Function": 30, "document.write": 30, "document.writeln": 30,
    "innerHTML": 30, "outerHTML": 30, "import()": 30,
    # HIGH
    "script.src": 20, "iframe.src": 20, "a.href": 20,
    "form.action": 20, "location": 20, "location.assign": 20,
    "location.replace": 20, "window.open": 20,
    "fetch": 20, "XMLHttpRequest.open": 20,
    "src_assignment": 20, "href_assignment": 20,
    # MEDIUM
    "postMessage": 10, "$.html": 10, "$.append": 10, "$.prepend": 10,
    "$.after": 10, "$.before": 10, "$.replaceWith": 10,
    "document.createElement": 10,
    # LOW
    "textContent": 0,
}


def score_gadget(gadget: Gadget) -> float:
    """Compute exploitability score (0-100) for a gadget."""
    score = 50.0

    # Sink severity
    score += SINK_SCORES.get(gadget.sink.sink_type, 10)

    # Chain depth penalty
    if gadget.chain_depth_required == 2:
        score -= 15
    elif gadget.chain_depth_required >= 3:
        score -= 15 + 15 * (gadget.chain_depth_required - 2)

    # Guard penalties
    for guard in gadget.guards:
        if guard.kind == "typeof_check":
            score -= 20
        elif guard.kind == "optional_chain":
            score -= 10
        elif guard.kind == "or_default":
            score -= 5
        elif guard.kind == "nullish_coalescing":
            score -= 5
        elif guard.kind == "hasOwnProperty":
            score -= 15
        elif guard.kind == "in_check":
            score -= 10

    # Known CVE pattern bonus
    if gadget.framework_pattern:
        score += 15

    # Interprocedural path bonus (harder to find manually)
    if len(gadget.path) > 3:
        score += 5

    # String coercion at sink
    if gadget.coercion_needed:
        score -= 5

    # Source priority penalty
    if gadget.source.priority == 2:
        score -= 5
    elif gadget.source.priority == 3:
        score -= 15
    elif gadget.source.priority >= 4:
        score -= 20

    return max(0.0, min(100.0, score))


def score_all_gadgets(gadgets: list[Gadget]) -> list[Gadget]:
    """Score all gadgets and sort by score descending."""
    for g in gadgets:
        g.score = score_gadget(g)
    gadgets.sort(key=lambda g: -g.score)
    return gadgets


def deduplicate_gadgets(gadgets: list[Gadget]) -> list[Gadget]:
    """Remove duplicate gadgets (same source property + same sink type)."""
    seen: set[tuple[str, str, int]] = set()
    result = []
    for g in gadgets:
        key = (g.source.property_name, g.sink.sink_type, g.chain_depth_required)
        if key not in seen:
            seen.add(key)
            result.append(g)
    return result


def generate_report(gadgets: list[Gadget], file_index, output_path: str) -> None:
    """Generate JSON report of all gadgets."""
    report = {
        "total_gadgets": len(gadgets),
        "critical": sum(1 for g in gadgets if g.score >= 70),
        "high": sum(1 for g in gadgets if 50 <= g.score < 70),
        "medium": sum(1 for g in gadgets if 30 <= g.score < 50),
        "low": sum(1 for g in gadgets if g.score < 30),
        "files_analyzed": len(file_index.files) if file_index else 0,
        "gadgets": [g.to_dict() for g in gadgets],
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("Report written to %s: %d gadgets", output_path, len(gadgets))


def generate_seeds(gadgets: list[Gadget], output_dir: str, min_score: float = 30.0) -> int:
    """Generate fuzzer seed files from discovered gadgets."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    count = 0
    for i, g in enumerate(gadgets):
        if g.score < min_score:
            continue
        template = g.to_exploit_template()
        seed_file = out / f"gadget_{i:03d}_{g.source.property_name}.html"
        seed_file.write_bytes(template.encode("utf-8"))
        count += 1
    logger.info("Generated %d seeds in %s", count, output_dir)
    return count
