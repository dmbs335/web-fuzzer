"""Post-run analysis helpers for selection_drops.jsonl."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .heuristic_policy import SelectionEvidence, choose_selection_branch


def _load_jsonl_records(path: Path) -> list[dict[str, Any]]:
    """Load newline-delimited JSON records from disk."""
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def load_selection_drop_records(path: Path) -> list[dict[str, Any]]:
    """Load newline-delimited selection-drop records from disk."""
    return _load_jsonl_records(path)


def load_selection_shadow_records(path: Path) -> list[dict[str, Any]]:
    """Load newline-delimited shadow-queue records from disk."""
    return _load_jsonl_records(path)


def _sorted_list(values: set[str]) -> list[str]:
    return sorted(v for v in values if v)


def _fingerprint_mode(record: dict[str, Any]) -> str:
    metadata = record.get("metadata", {}) or {}
    components = metadata.get("fingerprint_components", {}) or {}
    return str(components.get("mode") or "unknown")


def _coarse_key(record: dict[str, Any]) -> str:
    metadata = record.get("metadata", {}) or {}
    components = metadata.get("fingerprint_components", {}) or {}
    mode = _fingerprint_mode(record)

    if mode == "birkhoff_bitvector":
        atoms = components.get("bitvector_atoms", []) or []
        if atoms:
            return "bv:" + "|".join(str(atom) for atom in atoms)
        return "bv:<empty>"

    if mode == "diff_pattern_hash":
        diff_hash = components.get("diff_pattern_hash") or metadata.get("diff_pattern_hash") or ""
        return f"diff:{diff_hash or '<missing>'}"

    if mode == "fallback_error_skeleton":
        error_sig = components.get("error_signature") or "<missing>"
        skeleton = components.get("input_skeleton") or "<missing>"
        return f"fallback:{error_sig}::{skeleton}"

    fingerprint = record.get("fingerprint") or "<missing>"
    return f"{mode}:{fingerprint}"


def recommended_selection_branch(
    *,
    drop_reason: str,
    fingerprint_mode: str,
    unique_fine_fingerprints: int,
    strategy_count: int,
    oracle_count: int,
    orbit_count: int,
    session_count: int = 0,
    witness_families: list[str] | set[str] | tuple[str, ...] | None = None,
) -> str:
    """Choose a remediation branch for a selection-drop hotspot.

    The branch names are intentionally operational: they describe the next
    mitigation we should try rather than the root cause itself.
    """
    evidence = SelectionEvidence.from_values(
        drop_reason=drop_reason,
        fingerprint_mode=fingerprint_mode,
        unique_fine_fingerprints=unique_fine_fingerprints,
        strategy_count=strategy_count,
        oracle_count=oracle_count,
        orbit_count=orbit_count,
        session_count=session_count,
        witness_families=witness_families,
    )
    return choose_selection_branch(evidence).value


def summarize_selection_drops(
    records: list[dict[str, Any]],
    *,
    top_n: int = 10,
) -> dict[str, Any]:
    """Summarize selection-drop records into hotspot-oriented aggregates."""
    drop_reasons: Counter[str] = Counter()
    fingerprint_modes: Counter[str] = Counter()
    policy_branches: Counter[str] = Counter()
    policy_contracts: Counter[str] = Counter()
    policy_missing = 0
    hotspots: dict[tuple[str, str, str], dict[str, Any]] = {}
    unique_coarse_keys_by_reason: dict[str, set[str]] = defaultdict(set)

    for record in records:
        reason = str(record.get("drop_reason") or "unknown")
        mode = _fingerprint_mode(record)
        coarse_key = _coarse_key(record)
        metadata = record.get("metadata", {}) or {}
        category = str(metadata.get("category") or "")
        strategy = str(metadata.get("strategy") or "")
        witness_family = str(metadata.get("waf_witness_family") or "")
        oracle_name = str(record.get("oracle_name") or "")
        fine_fingerprint = str(metadata.get("fine_fingerprint") or "")
        diff_fields = metadata.get("diff_fields", []) or []
        orbit_key = str(metadata.get("orbit_canonical_key") or "")
        session_key = str(metadata.get("session_key") or "")
        selection_policy = metadata.get("selection_policy", {}) or {}

        drop_reasons[reason] += 1
        fingerprint_modes[mode] += 1
        unique_coarse_keys_by_reason[reason].add(coarse_key)
        if selection_policy:
            branch = str(selection_policy.get("branch") or "unknown")
            policy_branches[branch] += 1
            contract_key = (
                "ok"
                if selection_policy.get("contract_ok") is True
                else "violation"
                if selection_policy.get("contract_ok") is False
                else "unknown"
            )
            policy_contracts[contract_key] += 1
        else:
            policy_missing += 1

        hotspot_key = (reason, mode, coarse_key)
        hotspot = hotspots.setdefault(
            hotspot_key,
            {
                "drop_reason": reason,
                "fingerprint_mode": mode,
                "coarse_key": coarse_key,
                "count": 0,
                "oracle_names": set(),
                "categories": set(),
                "strategies": set(),
                "witness_families": set(),
                "fine_fingerprints": set(),
                "diff_fields_union": set(),
                "orbit_keys": set(),
                "session_keys": set(),
            },
        )
        hotspot["count"] += 1
        if oracle_name:
            hotspot["oracle_names"].add(oracle_name)
        if category:
            hotspot["categories"].add(category)
        if strategy:
            hotspot["strategies"].add(strategy)
        if witness_family:
            hotspot["witness_families"].add(witness_family)
        if fine_fingerprint:
            hotspot["fine_fingerprints"].add(fine_fingerprint)
        hotspot["diff_fields_union"].update(str(field) for field in diff_fields if field)
        if orbit_key:
            hotspot["orbit_keys"].add(orbit_key)
        if session_key:
            hotspot["session_keys"].add(session_key)

    hotspot_rows = []
    branch_recommendations: Counter[str] = Counter()
    for hotspot in hotspots.values():
        strategies = _sorted_list(hotspot["strategies"])
        oracle_names = _sorted_list(hotspot["oracle_names"])
        orbit_keys = _sorted_list(hotspot["orbit_keys"])
        session_keys = _sorted_list(hotspot["session_keys"])
        unique_fine_fingerprints = len(hotspot["fine_fingerprints"])
        recommended_branch = recommended_selection_branch(
            drop_reason=hotspot["drop_reason"],
            fingerprint_mode=hotspot["fingerprint_mode"],
            unique_fine_fingerprints=unique_fine_fingerprints,
            strategy_count=len(strategies),
            oracle_count=len(oracle_names),
            orbit_count=len(orbit_keys),
            session_count=len(session_keys),
            witness_families=hotspot["witness_families"],
        )
        branch_recommendations[recommended_branch] += hotspot["count"]
        hotspot_rows.append(
            {
                "drop_reason": hotspot["drop_reason"],
                "fingerprint_mode": hotspot["fingerprint_mode"],
                "coarse_key": hotspot["coarse_key"],
                "count": hotspot["count"],
                "unique_fine_fingerprints": unique_fine_fingerprints,
                "oracle_names": oracle_names,
                "categories": _sorted_list(hotspot["categories"]),
                "strategies": strategies,
                "witness_families": _sorted_list(hotspot["witness_families"]),
                "diff_fields_union": _sorted_list(hotspot["diff_fields_union"]),
                "orbit_keys": orbit_keys,
                "session_keys": session_keys,
                "recommended_branch": recommended_branch,
            }
        )

    hotspot_rows.sort(
        key=lambda row: (
            -int(row["count"]),
            str(row["drop_reason"]),
            str(row["fingerprint_mode"]),
            str(row["coarse_key"]),
        ),
    )

    return {
        "total_records": len(records),
        "drop_reasons": dict(sorted(drop_reasons.items())),
        "fingerprint_modes": dict(sorted(fingerprint_modes.items())),
        "unique_coarse_keys_by_reason": {
            reason: len(keys) for reason, keys in sorted(unique_coarse_keys_by_reason.items())
        },
        "branch_recommendations": dict(sorted(branch_recommendations.items())),
        "policy_summary": {
            "branches": dict(sorted(policy_branches.items())),
            "contracts": dict(sorted(policy_contracts.items())),
            "missing_policy_records": policy_missing,
        },
        "hotspots": hotspot_rows[:top_n],
    }


def render_selection_drop_summary(summary: dict[str, Any]) -> str:
    """Render a human-readable hotspot summary."""
    lines = [
        "Selection Drop Analysis",
        f"  total_records: {summary.get('total_records', 0)}",
    ]

    drop_reasons = summary.get("drop_reasons", {}) or {}
    if drop_reasons:
        lines.append("  drop_reasons:")
        for reason, count in drop_reasons.items():
            unique_keys = (summary.get("unique_coarse_keys_by_reason", {}) or {}).get(reason, 0)
            lines.append(f"    {reason}: {count} (unique_keys={unique_keys})")

    fingerprint_modes = summary.get("fingerprint_modes", {}) or {}
    if fingerprint_modes:
        lines.append("  fingerprint_modes:")
        for mode, count in fingerprint_modes.items():
            lines.append(f"    {mode}: {count}")

    branch_recommendations = summary.get("branch_recommendations", {}) or {}
    if branch_recommendations:
        lines.append("  branch_recommendations:")
        for branch, count in branch_recommendations.items():
            lines.append(f"    {branch}: {count}")

    policy_summary = summary.get("policy_summary", {}) or {}
    policy_branches = policy_summary.get("branches", {}) or {}
    policy_contracts = policy_summary.get("contracts", {}) or {}
    missing_policy = policy_summary.get("missing_policy_records", 0)
    if policy_branches or policy_contracts or missing_policy:
        lines.append("  policy_summary:")
        if policy_branches:
            lines.append("    branches:")
            for branch, count in policy_branches.items():
                lines.append(f"      {branch}: {count}")
        if policy_contracts:
            lines.append("    contracts:")
            for status, count in policy_contracts.items():
                lines.append(f"      {status}: {count}")
        if missing_policy:
            lines.append(f"    missing_policy_records: {missing_policy}")

    hotspots = summary.get("hotspots", []) or []
    if hotspots:
        lines.append("  hotspots:")
        for idx, hotspot in enumerate(hotspots, start=1):
            lines.append(
                f"    {idx}. {hotspot['drop_reason']} | {hotspot['fingerprint_mode']} | "
                f"{hotspot['coarse_key']} | count={hotspot['count']} | "
                f"unique_fine={hotspot['unique_fine_fingerprints']} | "
                f"branch={hotspot['recommended_branch']}"
            )
            if hotspot["categories"]:
                lines.append(f"       categories={','.join(hotspot['categories'])}")
            if hotspot["strategies"]:
                lines.append(f"       strategies={','.join(hotspot['strategies'])}")
            if hotspot["diff_fields_union"]:
                lines.append(f"       diff_fields={','.join(hotspot['diff_fields_union'])}")
            if hotspot["witness_families"]:
                lines.append(
                    f"       witness_families={','.join(hotspot['witness_families'])}"
                )
            if hotspot["session_keys"]:
                lines.append(f"       session_keys={','.join(hotspot['session_keys'])}")

    return "\n".join(lines)


def write_selection_drop_summary_artifacts(
    path: Path,
    *,
    top_n: int = 10,
) -> dict[str, Any] | None:
    """Write text and JSON hotspot summaries next to a drop log."""
    if not path.exists():
        return None

    summary = summarize_selection_drops(
        load_selection_drop_records(path),
        top_n=top_n,
    )
    path.with_name("selection_drop_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    path.with_name("selection_drop_summary.txt").write_text(
        render_selection_drop_summary(summary),
        encoding="utf-8",
    )
    return summary


def _recommended_shadow_triage(
    *,
    unique_fine_fingerprints: int,
    strategy_count: int,
    oracle_count: int,
) -> str:
    """Choose a post-run triage action for a shadow bucket."""
    if unique_fine_fingerprints > 1 and (strategy_count > 1 or oracle_count > 1):
        return "promote_shadow_bucket"
    if unique_fine_fingerprints > 1:
        return "review_shadow_bucket"
    return "monitor_shadow_bucket"


def summarize_selection_shadow_queue(
    records: list[dict[str, Any]],
    *,
    top_n: int = 10,
) -> dict[str, Any]:
    """Summarize shadow-queue records into post-run triage candidates."""
    shadow_reasons: Counter[str] = Counter()
    triage_actions: Counter[str] = Counter()
    buckets: dict[tuple[str, str, str], dict[str, Any]] = {}

    for record in records:
        shadow_reason = str(record.get("shadow_reason") or "unknown")
        mode = _fingerprint_mode(record)
        coarse_key = _coarse_key(record)
        metadata = record.get("metadata", {}) or {}
        strategy = str(metadata.get("strategy") or "")
        oracle_name = str(record.get("oracle_name") or "")
        fine_fingerprint = str(metadata.get("fine_fingerprint") or "")
        category = str(metadata.get("category") or "")
        session_key = str(metadata.get("session_key") or "")

        shadow_reasons[shadow_reason] += 1
        bucket_key = (shadow_reason, mode, coarse_key)
        bucket = buckets.setdefault(
            bucket_key,
            {
                "shadow_reason": shadow_reason,
                "fingerprint_mode": mode,
                "coarse_key": coarse_key,
                "count": 0,
                "oracle_names": set(),
                "strategies": set(),
                "categories": set(),
                "fine_fingerprints": set(),
                "session_keys": set(),
            },
        )
        bucket["count"] += 1
        if oracle_name:
            bucket["oracle_names"].add(oracle_name)
        if strategy:
            bucket["strategies"].add(strategy)
        if category:
            bucket["categories"].add(category)
        if fine_fingerprint:
            bucket["fine_fingerprints"].add(fine_fingerprint)
        if session_key:
            bucket["session_keys"].add(session_key)

    bucket_rows = []
    triage_candidates = []
    for bucket in buckets.values():
        strategies = _sorted_list(bucket["strategies"])
        oracle_names = _sorted_list(bucket["oracle_names"])
        unique_fine_fingerprints = len(bucket["fine_fingerprints"])
        triage_action = _recommended_shadow_triage(
            unique_fine_fingerprints=unique_fine_fingerprints,
            strategy_count=len(strategies),
            oracle_count=len(oracle_names),
        )
        triage_actions[triage_action] += bucket["count"]
        row = {
            "shadow_reason": bucket["shadow_reason"],
            "fingerprint_mode": bucket["fingerprint_mode"],
            "coarse_key": bucket["coarse_key"],
            "count": bucket["count"],
            "unique_fine_fingerprints": unique_fine_fingerprints,
            "oracle_names": oracle_names,
            "strategies": strategies,
            "categories": _sorted_list(bucket["categories"]),
            "session_keys": _sorted_list(bucket["session_keys"]),
            "triage_action": triage_action,
        }
        bucket_rows.append(row)
        if triage_action != "monitor_shadow_bucket":
            triage_candidates.append(row)

    bucket_rows.sort(
        key=lambda row: (
            -int(row["count"]),
            str(row["shadow_reason"]),
            str(row["fingerprint_mode"]),
            str(row["coarse_key"]),
        ),
    )
    triage_candidates.sort(
        key=lambda row: (
            -int(row["count"]),
            str(row["triage_action"]),
            str(row["coarse_key"]),
        ),
    )

    return {
        "total_records": len(records),
        "shadow_reasons": dict(sorted(shadow_reasons.items())),
        "triage_actions": dict(sorted(triage_actions.items())),
        "shadow_buckets": bucket_rows[:top_n],
        "triage_candidates": triage_candidates[:top_n],
    }


def render_selection_shadow_summary(summary: dict[str, Any]) -> str:
    """Render a human-readable shadow-queue triage summary."""
    lines = [
        "Selection Shadow Queue Analysis",
        f"  total_records: {summary.get('total_records', 0)}",
    ]

    shadow_reasons = summary.get("shadow_reasons", {}) or {}
    if shadow_reasons:
        lines.append("  shadow_reasons:")
        for reason, count in shadow_reasons.items():
            lines.append(f"    {reason}: {count}")

    triage_actions = summary.get("triage_actions", {}) or {}
    if triage_actions:
        lines.append("  triage_actions:")
        for action, count in triage_actions.items():
            lines.append(f"    {action}: {count}")

    buckets = summary.get("shadow_buckets", []) or []
    if buckets:
        lines.append("  shadow_buckets:")
        for idx, bucket in enumerate(buckets, start=1):
            lines.append(
                f"    {idx}. {bucket['shadow_reason']} | {bucket['fingerprint_mode']} | "
                f"{bucket['coarse_key']} | count={bucket['count']} | "
                f"unique_fine={bucket['unique_fine_fingerprints']} | "
                f"triage={bucket['triage_action']}"
            )
            if bucket["categories"]:
                lines.append(f"       categories={','.join(bucket['categories'])}")
            if bucket["strategies"]:
                lines.append(f"       strategies={','.join(bucket['strategies'])}")
            if bucket["session_keys"]:
                lines.append(f"       session_keys={','.join(bucket['session_keys'])}")

    triage_candidates = summary.get("triage_candidates", []) or []
    if triage_candidates:
        lines.append("  triage_candidates:")
        for idx, candidate in enumerate(triage_candidates, start=1):
            lines.append(
                f"    {idx}. {candidate['triage_action']} | {candidate['coarse_key']} | "
                f"count={candidate['count']}"
            )

    return "\n".join(lines)


def write_selection_shadow_summary_artifacts(
    path: Path,
    *,
    top_n: int = 10,
) -> dict[str, Any] | None:
    """Write text and JSON shadow-queue summaries next to a shadow log."""
    if not path.exists():
        return None

    summary = summarize_selection_shadow_queue(
        load_selection_shadow_records(path),
        top_n=top_n,
    )
    path.with_name("selection_shadow_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    path.with_name("selection_shadow_summary.txt").write_text(
        render_selection_shadow_summary(summary),
        encoding="utf-8",
    )
    path.with_name("selection_shadow_triage.json").write_text(
        json.dumps(summary.get("triage_candidates", []), indent=2),
        encoding="utf-8",
    )
    return summary


def write_selection_shadow_replay_artifacts(
    path: Path,
    *,
    top_n: int = 10,
) -> list[dict[str, Any]] | None:
    """Materialize triage-worthy shadow records as a replay seed corpus."""
    if not path.exists():
        return None

    records = load_selection_shadow_records(path)
    summary = summarize_selection_shadow_queue(records, top_n=top_n)
    triage_candidates = summary.get("triage_candidates", []) or []
    if not triage_candidates:
        return []

    triage_keys = {
        (
            str(candidate.get("shadow_reason") or ""),
            str(candidate.get("fingerprint_mode") or ""),
            str(candidate.get("coarse_key") or ""),
        )
        for candidate in triage_candidates
    }
    triage_candidate_by_key = {
        (
            str(candidate.get("shadow_reason") or ""),
            str(candidate.get("fingerprint_mode") or ""),
            str(candidate.get("coarse_key") or ""),
        ): candidate
        for candidate in triage_candidates
    }

    replay_dir = path.with_name("selection_shadow_replay")
    replay_dir.mkdir(parents=True, exist_ok=True)

    manifests: list[dict[str, Any]] = []
    seen_variants: set[tuple[str, str]] = set()
    for record in records:
        key = (
            str(record.get("shadow_reason") or ""),
            _fingerprint_mode(record),
            _coarse_key(record),
        )
        if key not in triage_keys:
            continue

        metadata = record.get("metadata", {}) or {}
        fine_fingerprint = str(metadata.get("fine_fingerprint") or "")
        variant_key = (key[2], fine_fingerprint)
        if variant_key in seen_variants:
            continue

        input_b64 = str(record.get("input_b64") or "")
        if not input_b64:
            continue
        try:
            input_data = base64.b64decode(input_b64.encode("ascii"))
        except Exception:
            continue

        seen_variants.add(variant_key)
        triage_candidate = triage_candidate_by_key.get(key, {})
        name_hash = hashlib.sha1(
            f"{key[2]}\x1f{fine_fingerprint}".encode("utf-8", errors="replace")
        ).hexdigest()[:12]
        seed_path = replay_dir / f"{len(manifests)+1:03d}_{name_hash}.bin"
        seed_path.write_bytes(input_data)
        manifests.append(
            {
                "seed_path": str(seed_path.name),
                "shadow_reason": key[0],
                "fingerprint_mode": key[1],
                "coarse_key": key[2],
                "fine_fingerprint": fine_fingerprint,
                "oracle_name": record.get("oracle_name", ""),
                "strategy": metadata.get("strategy", ""),
                "category": metadata.get("category", ""),
                "session_key": metadata.get("session_key", ""),
                "prefix_depth": metadata.get("prefix_depth"),
                "replay_context": metadata.get("replay_context"),
                "triage_action": triage_candidate.get("triage_action", ""),
                "input_size": len(input_data),
            }
        )

    replay_dir.joinpath("manifest.json").write_text(
        json.dumps(manifests, indent=2),
        encoding="utf-8",
    )
    return manifests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze selection_drops.jsonl hotspots.")
    parser.add_argument("path", type=Path, help="Path to selection_drops.jsonl")
    parser.add_argument("--top", type=int, default=10, help="Number of hotspots to include")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format",
    )
    args = parser.parse_args(argv)

    summary = summarize_selection_drops(
        load_selection_drop_records(args.path),
        top_n=args.top,
    )
    if args.format == "json":
        print(json.dumps(summary, indent=2))
    else:
        print(render_selection_drop_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
