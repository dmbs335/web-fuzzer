from __future__ import annotations

import json
import base64

from webfuzzer.fuzzer.selection_drop_analysis import (
    load_selection_drop_records,
    load_selection_shadow_records,
    recommended_selection_branch,
    render_selection_drop_summary,
    render_selection_shadow_summary,
    summarize_selection_drops,
    summarize_selection_shadow_queue,
    write_selection_drop_summary_artifacts,
    write_selection_shadow_replay_artifacts,
    write_selection_shadow_summary_artifacts,
)


def test_selection_drop_analysis_summarizes_hotspots(tmp_path):
    path = tmp_path / "selection_drops.jsonl"
    records = [
        {
            "title": "a",
            "oracle_name": "diff",
            "severity": "medium",
            "fingerprint": "fp-1",
            "drop_stage": "dedup",
            "drop_reason": "duplicate_fingerprint",
            "metadata": {
                "category": "accept_reject",
                "strategy": "output",
                "strategies": ["grammar", "structural"],
                "diff_fields": ["host"],
                "all_diff_fields": ["host"],
                "diff_pattern_hash": "hash-a",
                "accepting_side": "left",
                "waf_witness_family": "body_headers",
                "fine_fingerprint": "fine-1",
                "fingerprint_components": {
                    "mode": "diff_pattern_hash",
                    "diff_pattern_hash": "hash-a",
                },
                "selection_policy": {
                    "branch": "fine_preserve_bucket",
                    "contract_ok": True,
                    "evidence": {"has_preservation_witness": True},
                },
                "orbit_canonical_key": "",
            },
        },
        {
            "title": "b",
            "oracle_name": "diff",
            "severity": "medium",
            "fingerprint": "fp-2",
            "drop_stage": "dedup",
            "drop_reason": "duplicate_fingerprint",
            "metadata": {
                "category": "accept_reject",
                "strategy": "output",
                "strategies": ["grammar", "structural"],
                "diff_fields": ["host", "path"],
                "all_diff_fields": ["host", "path"],
                "diff_pattern_hash": "hash-a",
                "accepting_side": "left",
                "waf_witness_family": "body_headers+path",
                "fine_fingerprint": "fine-2",
                "fingerprint_components": {
                    "mode": "diff_pattern_hash",
                    "diff_pattern_hash": "hash-a",
                },
                "selection_policy": {
                    "branch": "fine_preserve_bucket",
                    "contract_ok": True,
                    "evidence": {"has_preservation_witness": True},
                },
                "orbit_canonical_key": "",
            },
        },
        {
            "title": "c",
            "oracle_name": "diff",
            "severity": "medium",
            "fingerprint": "fp-3",
            "drop_stage": "dedup",
            "drop_reason": "duplicate_fingerprint",
            "metadata": {
                "category": "header_smuggling",
                "strategy": "structural",
                "strategies": ["havoc", "structural"],
                "diff_fields": ["header"],
                "all_diff_fields": ["header"],
                "diff_pattern_hash": "",
                "accepting_side": "right",
                "fine_fingerprint": "fine-3",
                "fingerprint_components": {
                    "mode": "birkhoff_bitvector",
                    "bitvector_atoms": ["header", "path"],
                },
                "orbit_canonical_key": "",
            },
        },
    ]
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    summary = summarize_selection_drops(load_selection_drop_records(path), top_n=5)

    assert summary["total_records"] == 3
    assert summary["drop_reasons"]["duplicate_fingerprint"] == 3
    assert summary["fingerprint_modes"]["diff_pattern_hash"] == 2
    assert summary["fingerprint_modes"]["birkhoff_bitvector"] == 1
    assert summary["unique_coarse_keys_by_reason"]["duplicate_fingerprint"] == 2
    assert summary["branch_recommendations"]["fine_preserve_bucket"] == 2
    assert summary["branch_recommendations"]["monitor_only"] == 1
    assert summary["policy_summary"]["branches"]["fine_preserve_bucket"] == 2
    assert summary["policy_summary"]["contracts"]["ok"] == 2
    assert summary["policy_summary"]["missing_policy_records"] == 1

    first_hotspot = summary["hotspots"][0]
    assert first_hotspot["drop_reason"] == "duplicate_fingerprint"
    assert first_hotspot["fingerprint_mode"] == "diff_pattern_hash"
    assert first_hotspot["coarse_key"] == "diff:hash-a"
    assert first_hotspot["count"] == 2
    assert first_hotspot["unique_fine_fingerprints"] == 2
    assert first_hotspot["recommended_branch"] == "fine_preserve_bucket"
    assert first_hotspot["categories"] == ["accept_reject"]
    assert first_hotspot["strategies"] == ["output"]
    assert first_hotspot["witness_families"] == ["body_headers", "body_headers+path"]
    assert first_hotspot["diff_fields_union"] == ["host", "path"]


def test_selection_drop_analysis_surfaces_policy_contract_violations(tmp_path):
    path = tmp_path / "selection_drops.jsonl"
    record = {
        "title": "bad-policy",
        "oracle_name": "diff",
        "severity": "medium",
        "fingerprint": "fp-1",
        "drop_stage": "dedup",
        "drop_reason": "duplicate_exact_pattern",
        "metadata": {
            "fingerprint_components": {
                "mode": "diff_pattern_hash",
                "diff_pattern_hash": "hash-a",
            },
            "selection_policy": {
                "branch": "fine_preserve_bucket",
                "contract_ok": False,
                "evidence": {"has_preservation_witness": False},
            },
        },
    }
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    summary = summarize_selection_drops(load_selection_drop_records(path), top_n=5)
    rendered = render_selection_drop_summary(summary)

    assert summary["policy_summary"]["contracts"]["violation"] == 1
    assert "violation: 1" in rendered


def test_selection_drop_analysis_renders_text_summary(tmp_path):
    path = tmp_path / "selection_drops.jsonl"
    record = {
        "title": "x",
        "oracle_name": "diff",
        "severity": "medium",
        "fingerprint": "fp-1",
        "drop_stage": "dedup",
        "drop_reason": "duplicate_fingerprint",
        "metadata": {
            "category": "accept_reject",
            "strategy": "output",
            "strategies": ["grammar"],
            "diff_fields": ["host"],
            "all_diff_fields": ["host"],
            "diff_pattern_hash": "hash-a",
            "accepting_side": "left",
            "waf_witness_family": "body_headers",
            "fine_fingerprint": "fine-1",
            "fingerprint_components": {
                "mode": "diff_pattern_hash",
                "diff_pattern_hash": "hash-a",
            },
            "orbit_canonical_key": "",
        },
    }
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")

    summary = summarize_selection_drops(load_selection_drop_records(path), top_n=5)
    rendered = render_selection_drop_summary(summary)

    assert "Selection Drop Analysis" in rendered
    assert "duplicate_fingerprint: 1" in rendered
    assert "diff_pattern_hash: 1" in rendered
    assert "diff:hash-a" in rendered
    assert "unique_fine=1" in rendered
    assert "witness_families=body_headers" in rendered
    assert "branch=monitor_only" in rendered


def test_selection_drop_analysis_recommends_shadow_queue_and_writes_artifacts(tmp_path):
    path = tmp_path / "selection_drops.jsonl"
    records = [
        {
            "title": "x",
            "oracle_name": "diff",
            "severity": "medium",
            "fingerprint": "fp-1",
            "drop_stage": "dedup",
            "drop_reason": "duplicate_coarse_bv",
            "metadata": {
                "category": "accept_reject",
                "strategy": "output",
                "strategies": ["grammar"],
                "diff_fields": ["host"],
                "all_diff_fields": ["host"],
                "diff_pattern_hash": "",
                "accepting_side": "left",
                "fine_fingerprint": "fine-1",
                "fingerprint_components": {
                    "mode": "birkhoff_bitvector",
                    "bitvector_atoms": ["host", "path"],
                },
                "orbit_canonical_key": "orbit-a",
            },
        },
        {
            "title": "y",
            "oracle_name": "state",
            "severity": "medium",
            "fingerprint": "fp-2",
            "drop_stage": "dedup",
            "drop_reason": "duplicate_coarse_bv",
            "metadata": {
                "category": "accept_reject",
                "strategy": "structural",
                "strategies": ["structural"],
                "diff_fields": ["path"],
                "all_diff_fields": ["path"],
                "diff_pattern_hash": "",
                "accepting_side": "left",
                "fine_fingerprint": "fine-2",
                "fingerprint_components": {
                    "mode": "birkhoff_bitvector",
                    "bitvector_atoms": ["host", "path"],
                },
                "orbit_canonical_key": "orbit-b",
            },
        },
    ]
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    summary = summarize_selection_drops(load_selection_drop_records(path), top_n=5)
    hotspot = summary["hotspots"][0]
    assert hotspot["recommended_branch"] == "shadow_queue_review"
    assert summary["branch_recommendations"]["shadow_queue_review"] == 2

    written = write_selection_drop_summary_artifacts(path, top_n=5)
    assert written is not None
    assert (tmp_path / "selection_drop_summary.json").exists()
    assert (tmp_path / "selection_drop_summary.txt").exists()


def test_selection_shadow_analysis_builds_triage_candidates_and_artifacts(tmp_path):
    path = tmp_path / "selection_shadow_queue.jsonl"
    records = [
        {
            "title": "x",
            "oracle_name": "oracle-a",
            "severity": "medium",
            "fingerprint": "fp-1",
            "shadow_reason": "shadow_queue_review",
            "input_b64": base64.b64encode(b"seed-a").decode("ascii"),
            "metadata": {
                "category": "accept_reject",
                "strategy": "output",
                "fine_fingerprint": "fine-1",
                "fingerprint_components": {
                    "mode": "birkhoff_bitvector",
                    "bitvector_atoms": ["host", "path"],
                },
            },
        },
        {
            "title": "y",
            "oracle_name": "oracle-b",
            "severity": "medium",
            "fingerprint": "fp-2",
            "shadow_reason": "shadow_queue_review",
            "input_b64": base64.b64encode(b"seed-b").decode("ascii"),
            "metadata": {
                "category": "accept_reject",
                "strategy": "structural",
                "fine_fingerprint": "fine-2",
                "fingerprint_components": {
                    "mode": "birkhoff_bitvector",
                    "bitvector_atoms": ["host", "path"],
                },
            },
        },
    ]
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")

    summary = summarize_selection_shadow_queue(load_selection_shadow_records(path), top_n=5)
    assert summary["total_records"] == 2
    assert summary["shadow_reasons"]["shadow_queue_review"] == 2
    assert summary["triage_actions"]["promote_shadow_bucket"] == 2
    assert summary["triage_candidates"][0]["triage_action"] == "promote_shadow_bucket"

    rendered = render_selection_shadow_summary(summary)
    assert "Selection Shadow Queue Analysis" in rendered
    assert "promote_shadow_bucket" in rendered

    written = write_selection_shadow_summary_artifacts(path, top_n=5)
    assert written is not None
    assert (tmp_path / "selection_shadow_summary.json").exists()
    assert (tmp_path / "selection_shadow_summary.txt").exists()
    assert (tmp_path / "selection_shadow_triage.json").exists()

    manifests = write_selection_shadow_replay_artifacts(path, top_n=5)
    assert manifests is not None
    assert len(manifests) == 2
    replay_dir = tmp_path / "selection_shadow_replay"
    assert replay_dir.exists()
    assert (replay_dir / "manifest.json").exists()
    assert any((replay_dir / entry["seed_path"]).exists() for entry in manifests)
    assert all(entry["triage_action"] == "promote_shadow_bucket" for entry in manifests)


def test_block_status_witness_family_prefers_fine_preserve_bucket():
    branch = recommended_selection_branch(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=2,
        strategy_count=2,
        oracle_count=2,
        orbit_count=1,
        session_count=1,
        witness_families={"body_headers+block_status", "timing+body_headers"},
    )

    assert branch == "fine_preserve_bucket"


def test_pure_timing_witness_family_stays_monitor_only_without_diversity():
    branch = recommended_selection_branch(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=1,
        strategy_count=1,
        oracle_count=1,
        orbit_count=1,
        session_count=1,
        witness_families={"timing"},
    )

    assert branch == "monitor_only"


def test_plain_body_headers_requires_multiple_fine_variants():
    branch = recommended_selection_branch(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=1,
        strategy_count=1,
        oracle_count=1,
        orbit_count=1,
        session_count=1,
        witness_families={"body_headers"},
    )

    assert branch == "monitor_only"


def test_plain_body_headers_preserves_when_multiple_fine_variants_exist():
    branch = recommended_selection_branch(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=2,
        strategy_count=1,
        oracle_count=1,
        orbit_count=1,
        session_count=1,
        witness_families={"body_headers"},
    )

    assert branch == "fine_preserve_bucket"


def test_block_status_family_beats_plain_body_headers_policy():
    branch = recommended_selection_branch(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=1,
        strategy_count=1,
        oracle_count=1,
        orbit_count=1,
        session_count=1,
        witness_families={"body_headers+block_status"},
    )

    assert branch == "fine_preserve_bucket"


def test_timing_mixed_block_status_requires_multiple_fine_variants():
    branch = recommended_selection_branch(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=1,
        strategy_count=1,
        oracle_count=1,
        orbit_count=1,
        session_count=1,
        witness_families={"timing+body_headers+block_status"},
    )

    assert branch == "monitor_only"


def test_pure_block_status_family_preserves_aggressively():
    branch = recommended_selection_branch(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=1,
        strategy_count=1,
        oracle_count=1,
        orbit_count=1,
        session_count=1,
        witness_families={"body_headers+block_status"},
    )

    assert branch == "fine_preserve_bucket"
