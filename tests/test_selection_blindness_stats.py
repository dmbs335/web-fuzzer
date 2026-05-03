from __future__ import annotations

import json

from webfuzzer.fuzzer.protocols import ExecutionResult, Finding, Input, Severity
from webfuzzer.fuzzer.stats import FuzzStats


def _finding() -> Finding:
    return Finding(
        title="x",
        severity=Severity.MEDIUM,
        input=Input(data=b"abc"),
        result=ExecutionResult(),
        oracle_name="differential",
        metadata={},
    )


def _timeout_finding(
    *,
    family: str,
    parser: str,
    evasion: str,
    transforms: list[str] | None = None,
) -> Finding:
    return Finding(
        title="Timeout: 3000ms",
        severity=Severity.MEDIUM,
        input=Input(data=b"timeout"),
        result=ExecutionResult(exit_code=-1, duration_ms=3000),
        oracle_name="crash",
        metadata={
            "timeout": True,
            "waf_timeout_family": family,
            "waf_timeout_axis_parser": parser,
            "waf_timeout_axis_evasion": evasion,
            "waf_timeout_transforms": transforms or [],
        },
    )


def test_selection_blindness_counters_appear_in_json_report():
    stats = FuzzStats()
    stats.record_observed_finding(_finding())
    stats.record_observed_finding(_finding())
    stats.record_selection_drop("duplicate_exact_pattern")
    stats.record_orbit_downgrade("same_orbit_same_pattern")
    stats.record_finding(_finding())

    report = json.loads(stats.report("json"))
    assert report["observed_findings"] == 2
    assert report["selection_drops_total"] == 1
    assert report["selection_drops_by_reason"]["duplicate_exact_pattern"] == 1
    assert report["selection_summary"]["survived_findings"] == 1
    assert report["selection_summary"]["dropped_findings"] == 1
    assert report["selection_summary"]["survivor_rate"] == 0.5
    assert report["selection_summary"]["drop_rate"] == 0.5
    assert report["selection_summary"]["drop_reasons"]["duplicate_exact_pattern"]["rate_over_observed"] == 0.5
    assert report["selection_summary"]["drop_reasons"]["duplicate_exact_pattern"]["share_of_drops"] == 1.0
    assert report["orbit_downgrades_total"] == 1
    assert report["orbit_downgrades_by_reason"]["same_orbit_same_pattern"] == 1
    assert report["interface_progress"]["observation_candidates"] == 2
    assert report["interface_progress"]["persistence_survivors"] == 1
    assert report["interface_progress"]["certificate_promotions"] == 1
    assert report["interface_progress"]["observation_nonzero"] is True
    assert report["interface_progress"]["persistence_nonzero"] is True
    assert report["interface_progress"]["certificate_nonzero"] is True


def test_selection_blindness_counters_appear_in_status_line():
    stats = FuzzStats()
    stats.record_observed_finding(_finding())
    stats.record_finding(_finding())
    stats.record_selection_drop("duplicate_exact_pattern")
    stats.record_orbit_downgrade("same_orbit_same_pattern")

    line = stats.status_line()
    assert "obs=1" in line
    assert "drop=1" in line
    assert "orbit_dg=1" in line
    assert "surv=100%" in line
    assert "drop_rate=100%" in line
    assert "top_drop=[duplicate_exact_pattern:1]" in line


def test_selection_blindness_text_report_shows_reason_rates():
    stats = FuzzStats()
    stats.record_observed_finding(_finding())
    stats.record_observed_finding(_finding())
    stats.record_finding(_finding())
    stats.record_selection_drop("duplicate_exact_pattern")

    report = stats.report("text")
    assert "Selection summary:" in report
    assert "Survivor rate:      50.0%" in report
    assert "Drop rate:          50.0%" in report
    assert "duplicate_exact_pattern" in report
    assert "obs_rate=50.0%" in report
    assert "drop_share=100.0%" in report
    assert "Top selection drop reasons:" in report
    assert "Interface progress:" in report
    assert "Observation:        2 (nonzero=True)" in report
    assert "Persistence:        1 (rate=50.0%)" in report


def test_selection_summary_tracks_top_drop_reasons():
    stats = FuzzStats()
    for _ in range(4):
        stats.record_observed_finding(_finding())
    stats.record_finding(_finding())
    stats.record_selection_drop("duplicate_exact_pattern")
    stats.record_selection_drop("duplicate_exact_pattern")
    stats.record_selection_drop("orbit_duplicate")

    summary = json.loads(stats.report("json"))["selection_summary"]
    assert summary["top_drop_reasons"][0]["reason"] == "duplicate_exact_pattern"
    assert summary["top_drop_reasons"][0]["count"] == 2
    assert summary["top_drop_reasons"][1]["reason"] == "orbit_duplicate"
    assert summary["top_drop_reasons"][1]["count"] == 1


def test_shadow_replay_summary_appears_in_reports_and_status_line():
    stats = FuzzStats()
    stats.record_shadow_replay_loaded()
    stats.record_shadow_replay_loaded()
    stats.record_execution("shadow_replay_seed")
    stats.record_execution("shadow_replay_seed")
    stats.record_finding(_finding(), "shadow_replay_seed")

    summary = json.loads(stats.report("json"))["shadow_replay_summary"]
    assert summary["loaded_seeds"] == 2
    assert summary["executions"] == 2
    assert summary["findings"] == 1
    assert summary["finding_rate_per_loaded"] == 0.5

    report = stats.report("text")
    assert "Shadow replay summary:" in report
    assert "Loaded seeds:        2" in report
    assert "Replay execs:        2" in report
    assert "Replay findings:     1" in report

    line = stats.status_line()
    assert "iface=o:0/p:1/c:1" in line
    assert "shadow=ld:2/ex:2/fd:1" in line


def test_timeout_family_summary_appears_in_reports():
    stats = FuzzStats()
    stats.record_finding(
        _timeout_finding(
            family="hdr_http10_downgrade",
            parser="header_parse",
            evasion="header_leniency",
            transforms=["case_scramble"],
        )
    )
    stats.record_finding(
        _timeout_finding(
            family="hdr_http10_downgrade",
            parser="header_parse",
            evasion="header_leniency",
        )
    )
    stats.record_finding(
        _timeout_finding(
            family="ct_duplicate",
            parser="header_parse",
            evasion="content_type",
        )
    )

    report_json = json.loads(stats.report("json"))
    summary = report_json["timeout_family_summary"]
    assert summary["total_timeouts"] == 3
    assert summary["families"]["hdr_http10_downgrade"] == 2
    assert summary["families"]["ct_duplicate"] == 1
    assert summary["parsers"]["header_parse"] == 3
    assert summary["evasions"]["header_leniency"] == 2
    assert summary["transforms"]["case_scramble"] == 1
    assert summary["top_families"][0] == {
        "family": "hdr_http10_downgrade",
        "count": 2,
    }

    report_text = stats.report("text")
    assert "Timeout family summary:" in report_text
    assert "Total timeouts:      3" in report_text
    assert "hdr_http10_downgrade" in report_text
