from webfuzzer.fuzzer.heuristic_policy import (
    SelectionBranch,
    SelectionEvidence,
    ShortWafEvidence,
    bounded_boost,
    cap_priority,
    choose_selection_branch,
    selection_branch_contract,
    short_waf_priority_cap,
    should_skip_short_waf_execution,
)


def test_preserve_branch_requires_preservation_witness():
    evidence = SelectionEvidence.from_values(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=1,
        strategy_count=1,
        oracle_count=1,
        orbit_count=1,
        witness_families={"body_headers+block_status"},
    )

    branch = choose_selection_branch(evidence)

    assert branch == SelectionBranch.FINE_PRESERVE
    assert evidence.has_preservation_witness is True
    assert selection_branch_contract(branch, evidence) is True
    assert evidence.to_metadata()["has_preservation_witness"] is True


def test_shadow_branch_requires_replayable_diversity_witness():
    evidence = SelectionEvidence.from_values(
        drop_reason="duplicate_exact_pattern",
        fingerprint_mode="diff_pattern_hash",
        unique_fine_fingerprints=3,
        strategy_count=2,
        oracle_count=1,
        orbit_count=1,
        witness_families={"timing"},
    )

    branch = choose_selection_branch(evidence)

    assert branch == SelectionBranch.SHADOW_REVIEW
    assert evidence.has_shadow_witness is True
    assert selection_branch_contract(branch, evidence) is True
    assert evidence.to_metadata()["has_shadow_witness"] is True


def test_short_waf_skip_requires_full_resource_witness():
    data = (
        b"POST /reflect HTTP/1.1\r\n"
        b"Host: target.local\r\n"
        b"X-WF-Family: fuzz\r\n"
        b"Transfer-Encoding:\tchunked\r\n\r\n"
        + b"A" * 700
    )

    evidence = ShortWafEvidence.from_input(
        input_data=data,
        mutator_name="waf_bypass",
        max_time_seconds=18,
    )

    assert evidence.short_campaign is True
    assert evidence.waf_marked is True
    assert evidence.large_wire is True
    assert evidence.timeout_prone_shape is True
    assert evidence.to_metadata()["skip_witness"] is True
    assert should_skip_short_waf_execution(
        input_data=data,
        mutator_name="waf_bypass",
        max_time_seconds=18,
    ) is True


def test_short_waf_priority_cap_and_priority_helpers_are_bounded():
    data = b"GET / HTTP/1.1\r\nHost: x\r\nX-WF-Family: fuzz\r\n\r\n" + (b"A" * 900)

    assert short_waf_priority_cap(
        input_data=data,
        mutator_name="waf_bypass",
        max_time_seconds=18,
    ) == 0.10
    assert cap_priority(0.8, 0.4) == 0.4
    assert cap_priority(0.2, 0.4) == 0.2
    assert bounded_boost(0.5, 2.0, 1.25) == 1.25
    assert bounded_boost(0.5, 0.8, 1.25) == 0.8
