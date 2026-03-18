"""Priority triage: decide which corpus entries to analyze first.

P1: coverage-novel entries (discovered new code paths)
P2: finding-adjacent entries (structurally similar to known findings)
P3: stall-breaker entries (from coverage plateau periods)
P4: everything else
"""

from __future__ import annotations

import json
import logging
from enum import IntEnum
from pathlib import Path

logger = logging.getLogger(__name__)


class Priority(IntEnum):
    P1_COVERAGE_FRONTIER = 1
    P2_FINDING_ADJACENT = 2
    P3_STALL_BREAKER = 3
    P4_EXHAUSTIVE = 4


def triage_corpus(
    corpus_dir: Path,
    findings_dir: Path | None = None,
    report_json: Path | None = None,
) -> dict[Priority, list[str]]:
    """Triage corpus entries into priority buckets.

    Returns {Priority: [input_id, ...]}.
    """
    result: dict[Priority, list[str]] = {p: [] for p in Priority}

    # Load all corpus entry IDs and metadata
    all_ids: list[str] = []
    metas: dict[str, dict] = {}

    if not corpus_dir.is_dir():
        return result

    for f in sorted(corpus_dir.iterdir()):
        if f.suffix == ".meta" or f.is_dir():
            continue
        input_id = f.name
        all_ids.append(input_id)

        meta_file = f.with_suffix(f.suffix + ".meta") if f.suffix else Path(str(f) + ".meta")
        if meta_file.exists():
            try:
                metas[input_id] = json.loads(meta_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                metas[input_id] = {}
        else:
            metas[input_id] = {}

    if not all_ids:
        return result

    assigned: set[str] = set()

    # P1: entries with non-empty feature_set (coverage-novel)
    for input_id in all_ids:
        meta = metas.get(input_id, {})
        feature_set = meta.get("feature_set", [])
        if feature_set:
            result[Priority.P1_COVERAGE_FRONTIER].append(input_id)
            assigned.add(input_id)

    # P2: entries structurally similar to findings
    if findings_dir and findings_dir.is_dir():
        finding_inputs = _load_finding_inputs(findings_dir)
        if finding_inputs:
            for input_id in all_ids:
                if input_id in assigned:
                    continue
                corpus_data = _read_corpus_entry(corpus_dir / input_id)
                if corpus_data and _is_finding_adjacent(corpus_data, finding_inputs):
                    result[Priority.P2_FINDING_ADJACENT].append(input_id)
                    assigned.add(input_id)

    # P3: entries from stall periods (coverage plateau)
    if report_json and report_json.exists():
        stall_ids = _detect_stall_entries(report_json, metas, all_ids)
        for input_id in stall_ids:
            if input_id not in assigned:
                result[Priority.P3_STALL_BREAKER].append(input_id)
                assigned.add(input_id)

    # P4: everything else
    for input_id in all_ids:
        if input_id not in assigned:
            result[Priority.P4_EXHAUSTIVE].append(input_id)

    logger.info(
        "Priority triage: P1=%d, P2=%d, P3=%d, P4=%d",
        len(result[Priority.P1_COVERAGE_FRONTIER]),
        len(result[Priority.P2_FINDING_ADJACENT]),
        len(result[Priority.P3_STALL_BREAKER]),
        len(result[Priority.P4_EXHAUSTIVE]),
    )
    return result


def select_by_priority(
    triage: dict[Priority, list[str]],
    priorities: list[Priority] | None = None,
) -> list[str]:
    """Select input IDs based on priority filter.

    If priorities is None, returns all entries in priority order.
    """
    if priorities is None:
        priorities = list(Priority)

    result = []
    for p in sorted(priorities):
        result.extend(triage.get(p, []))
    return result


def _load_finding_inputs(findings_dir: Path) -> list[bytes]:
    """Load input data from findings directory."""
    inputs = []
    for fdir in sorted(findings_dir.iterdir()):
        if not fdir.is_dir():
            continue
        input_file = fdir / "input"
        if input_file.exists():
            try:
                inputs.append(input_file.read_bytes())
            except OSError:
                continue
    return inputs


def _read_corpus_entry(filepath: Path) -> bytes | None:
    """Read a single corpus entry."""
    try:
        return filepath.read_bytes()
    except OSError:
        return None


def _is_finding_adjacent(corpus_data: bytes, finding_inputs: list[bytes]) -> bool:
    """Check if corpus_data is structurally similar to any finding input.

    Uses byte-level Jaccard similarity on 4-grams.
    """
    corpus_ngrams = _ngrams(corpus_data, 4)
    if not corpus_ngrams:
        return False

    for finding_data in finding_inputs:
        finding_ngrams = _ngrams(finding_data, 4)
        if not finding_ngrams:
            continue
        intersection = len(corpus_ngrams & finding_ngrams)
        union = len(corpus_ngrams | finding_ngrams)
        if union > 0 and intersection / union > 0.7:
            return True
    return False


def _ngrams(data: bytes, n: int) -> set[bytes]:
    """Extract n-grams from bytes."""
    if len(data) < n:
        return set()
    return {data[i:i + n] for i in range(len(data) - n + 1)}


def _detect_stall_entries(
    report_json: Path,
    metas: dict[str, dict],
    all_ids: list[str],
) -> list[str]:
    """Find corpus entries created during coverage plateaus."""
    try:
        report = json.loads(report_json.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []

    coverage_over_time = report.get("coverage_over_time", [])
    if len(coverage_over_time) < 10:
        return []

    # Find plateau periods (long stretches with no new coverage)
    stall_starts: list[float] = []
    stall_ends: list[float] = []
    for i in range(1, len(coverage_over_time)):
        prev_t, prev_cov = coverage_over_time[i - 1]
        curr_t, curr_cov = coverage_over_time[i]
        if curr_cov == prev_cov and curr_t - prev_t > 60:  # 60s+ plateau
            if not stall_starts or stall_ends[-1] != prev_t:
                stall_starts.append(prev_t)
            stall_ends.append(curr_t) if len(stall_ends) < len(stall_starts) else None
            if len(stall_ends) == len(stall_starts) - 1:
                stall_ends.append(curr_t)
            else:
                stall_ends[-1] = curr_t

    if not stall_starts:
        return []

    # Find corpus entries created during stall periods
    stall_ids = []
    for input_id in all_ids:
        meta = metas.get(input_id, {})
        created = meta.get("created_at", 0)
        if created:
            for s, e in zip(stall_starts, stall_ends):
                if s <= created <= e:
                    stall_ids.append(input_id)
                    break

    return stall_ids
