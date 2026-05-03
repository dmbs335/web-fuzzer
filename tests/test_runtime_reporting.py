import json

from webfuzzer.fuzzer.runtime_reporting import RuntimeReportingService


def test_final_report_attaches_selection_policy_artifacts(tmp_path):
    (tmp_path / "report.json").write_text(
        json.dumps({"elapsed_seconds": 1.0}),
        encoding="utf-8",
    )
    (tmp_path / "selection_drop_summary.json").write_text(
        json.dumps({
            "policy_summary": {
                "branches": {"fine_preserve_bucket": 2},
                "contracts": {"ok": 2},
                "missing_policy_records": 0,
            },
        }),
        encoding="utf-8",
    )
    (tmp_path / "selection_shadow_summary.json").write_text(
        json.dumps({"triage_candidates": [{"triage_action": "promote_shadow_bucket"}]}),
        encoding="utf-8",
    )
    (tmp_path / "selection_shadow_triage.json").write_text(
        json.dumps([{"triage_action": "promote_shadow_bucket"}]),
        encoding="utf-8",
    )
    replay_dir = tmp_path / "selection_shadow_replay"
    replay_dir.mkdir()
    (replay_dir / "manifest.json").write_text(
        json.dumps([{"seed_path": "001_seed.bin"}]),
        encoding="utf-8",
    )

    service = RuntimeReportingService(
        stats=None,
        publisher=None,
        output_dir=tmp_path,
        guidance_hooks=None,
        concolic=None,
        corpus=None,
        verify_queue=None,
        all_targets=[],
        running_getter=lambda: False,
        sync_deser_diag=lambda: None,
    )

    service._rewrite_final_report()

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert report["selection_drop_analysis"]["policy_summary"]["contracts"]["ok"] == 2
    assert report["selection_shadow_analysis"]["triage_candidates"][0]["triage_action"] == "promote_shadow_bucket"
    assert report["selection_shadow_triage"][0]["triage_action"] == "promote_shadow_bucket"
    assert report["selection_shadow_replay"][0]["seed_path"] == "001_seed.bin"
