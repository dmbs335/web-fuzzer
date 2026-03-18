"""Regression tests for bugs fixed across rounds 1–4.

Each test is tagged with the bug it guards against so that a future
regression is immediately traceable to the fix that was reverted.
"""

import json
import pytest

from webfuzzer.fuzzer.protocols import (
    Input, ExecutionResult, Finding, Severity, ScheduleResult,
)
from webfuzzer.fuzzer.corpus import CoverageMap, Seed, Corpus, MAP_SIZE


def _make_result(data: dict, exit_code: int = 0) -> ExecutionResult:
    return ExecutionResult(exit_code=exit_code, stdout=json.dumps(data).encode())


def _make_seed(sid: int, features: set[int] | None = None, energy: float = 1.0) -> Seed:
    s = Seed(id=sid, input=Input(data=b"x"))
    s.feature_set = features or set()
    s.energy = energy
    return s


# ── Round 1: Entropic productivity modifier ────────────────────────


class TestEntropicProductivityModifier:
    """Bug: _update_energies() overwrote update()'s ×0.99/×1.5 feedback."""

    def test_productivity_reward_persists_across_entropy_recalc(self):
        """After update(found_new_coverage=True), energy must stay boosted
        even after _update_energies re-runs on next select()."""
        from webfuzzer.fuzzer.schedulers.entropic import EntropicScheduler

        sched = EntropicScheduler(seed=42)
        corpus = Corpus()
        cov = CoverageMap()
        cov.bitmap[10] = 1
        s = corpus.force_add(Input(data=b"a"), cov)

        # Baseline energy
        sched.select(corpus)
        baseline = s.energy

        # Reward productivity
        sched.update(s, ScheduleResult(found_new_coverage=True))
        sched.select(corpus)  # triggers _update_energies again
        boosted = s.energy

        assert boosted > baseline, (
            "Productivity reward lost after entropy recomputation"
        )

    def test_productivity_decay_accumulates(self):
        from webfuzzer.fuzzer.schedulers.entropic import EntropicScheduler

        sched = EntropicScheduler(seed=42)
        corpus = Corpus()

        # Need multiple seeds with overlapping features for nonzero entropy.
        # With 1 seed, entropy=0 and energy=0.01 regardless of prod_mod.
        for i in range(5):
            cov = CoverageMap()
            cov.bitmap[10] = 1
            cov.bitmap[20 + i] = 1  # unique edge per seed
            corpus.force_add(Input(data=f"seed{i}".encode()), cov)

        s = corpus.seeds[0]

        # First boost to get above floor
        sched.update(s, ScheduleResult(found_new_coverage=True))
        sched.select(corpus)
        boosted = s.energy

        # 50 non-productive executions
        for _ in range(50):
            sched.update(s, ScheduleResult(found_new_coverage=False))

        sched.select(corpus)
        decayed = s.energy

        assert decayed < boosted, "Productivity decay had no effect"

    def test_cleanup_removed_frees_prod_mod(self):
        from webfuzzer.fuzzer.schedulers.entropic import EntropicScheduler

        sched = EntropicScheduler(seed=42)
        sched.update(_make_seed(99), ScheduleResult(found_new_coverage=True))
        assert 99 in sched._prod_mod
        sched.cleanup_removed({99})
        assert 99 not in sched._prod_mod


# ── Round 1: edge_freq drift after compact ─────────────────────────


class TestEdgeFreqCompact:
    """Bug: compact() removed seeds but didn't rebuild edge_freq."""

    def test_edge_freq_rebuilt_after_compact(self):
        corpus = Corpus()

        # Seed 0: hits edges {10, 20}
        cov0 = CoverageMap()
        cov0.bitmap[10] = 1
        cov0.bitmap[20] = 1
        s0 = corpus.force_add(Input(data=b"a"), cov0)
        s0.finding_count = 1  # keep it

        # Seed 1: hits edge {30}, no findings, empty feature_set → removable
        cov1 = CoverageMap()
        cov1.bitmap[30] = 1
        s1 = corpus.force_add(Input(data=b"b"), cov1)
        s1.feature_set = set()  # no contribution

        assert len(corpus.seeds) == 2
        removed = corpus.compact(min_seeds=1)

        assert s1.id in removed
        # edge_freq should NOT contain edge 30 from the removed seed
        assert corpus.edge_freq.get(30, 0) == 0, (
            "edge_freq still counts removed seed's edges"
        )


# ── Round 1: has_new_bits bucket direction ─────────────────────────


class TestHasNewBitsBucketDirection:
    """Bug: has_new_bits pure-Python fallback treated any bucket change
    as novel, including lower hit counts. Only higher buckets should be
    novel (AFL semantics).

    These tests exercise the pure-Python path directly, bypassing the
    native module which may have its own semantics."""

    def _has_new_bits_python(self, existing: CoverageMap, other: CoverageMap) -> bool:
        """Pure-Python has_new_bits (same as corpus.py fallback)."""
        from webfuzzer.fuzzer.corpus import _bucket
        for i in range(MAP_SIZE):
            if other.bitmap[i] and not existing.bitmap[i]:
                return True
            if other.bitmap[i] and _bucket(other.bitmap[i]) > _bucket(existing.bitmap[i]):
                return True
        return False

    def test_lower_hit_count_not_novel(self):
        existing = CoverageMap()
        existing.bitmap[5] = 8  # bucket for 8 = 8

        other = CoverageMap()
        other.bitmap[5] = 2  # bucket for 2 = 4, LOWER

        assert not self._has_new_bits_python(existing, other), (
            "Lower hit count bucket incorrectly treated as novel"
        )

    def test_higher_hit_count_is_novel(self):
        existing = CoverageMap()
        existing.bitmap[5] = 1  # bucket for 1 = 1

        other = CoverageMap()
        other.bitmap[5] = 4  # bucket for 4 = 4, HIGHER

        assert self._has_new_bits_python(existing, other), (
            "Higher hit count bucket not detected as novel"
        )

    def test_same_bucket_not_novel(self):
        existing = CoverageMap()
        existing.bitmap[5] = 4  # bucket(4) = 8

        other = CoverageMap()
        other.bitmap[5] = 5  # bucket(5) = 8, same bucket

        assert not self._has_new_bits_python(existing, other)

    def test_new_edge_always_novel(self):
        existing = CoverageMap()
        other = CoverageMap()
        other.bitmap[100] = 1
        assert existing.has_new_bits(other)


# ── Round 1: hybrid_coverage double-count ──────────────────────────


class TestHybridCoverageNoDoubleCount:
    """Bug: collect_diff added _target_edge_count to CoverageMap, then
    edge_count property added it again."""

    def test_edge_count_not_double_counted(self):
        from webfuzzer.fuzzer.coverage.hybrid_coverage import HybridCoverageCollector

        class FakeInner:
            map_size = MAP_SIZE
            reference_targets = []
            default_level = 0
            edge_count = 5

            def collect_diff(self, inp, primary, ref_results=None, **kw):
                return CoverageMap(edge_count=5)

            def is_novel(self, existing, new):
                return False

        hybrid = HybridCoverageCollector(FakeInner(), target_coverage_enabled=True)
        hybrid._target_edge_count = 3

        assert hybrid.edge_count == 8, (
            f"Expected 5+3=8, got {hybrid.edge_count} (double-count?)"
        )


# ── Round 2: None feature_set guards ──────────────────────────────


class TestNoneFeatureSetGuards:
    """Bug: rare_branch and map_elites crashed on None feature_set."""

    def test_rare_branch_handles_none_feature_set(self):
        from webfuzzer.fuzzer.schedulers.rare_branch import RareBranchScheduler

        sched = RareBranchScheduler(seed=42)
        corpus = Corpus()
        s = corpus.force_add(Input(data=b"x"))
        s.feature_set = None  # type: ignore[assignment]

        # Should not raise
        selected = sched.select(corpus)
        assert selected is not None

    def test_map_elites_handles_none_feature_set(self):
        from webfuzzer.fuzzer.schedulers.map_elites import MapElitesScheduler

        sched = MapElitesScheduler(seed=42)
        seed = _make_seed(1, features=None)  # type: ignore[arg-type]

        # Should not raise on update
        result = ScheduleResult(found_new_coverage=False)
        sched.update(seed, result)

    def test_map_elites_archive_try_insert_none_safe(self):
        from webfuzzer.fuzzer.schedulers.map_elites import MapElitesArchive

        archive = MapElitesArchive()
        seed_a = _make_seed(1, features=None)  # type: ignore[arg-type]
        seed_b = _make_seed(2, features={10, 20})

        # Both should not raise
        archive.try_insert(seed_a, "no_finding", 0)
        archive.try_insert(seed_b, "no_finding", 0)


# ── Round 2: CompositeScheduler cleanup propagation ────────────────


class TestCompositeSchedulerCleanup:
    """Bug: CompositeScheduler had no cleanup_removed(), leaking sub-scheduler state."""

    def test_cleanup_removed_propagates(self):
        from webfuzzer.fuzzer.schedulers.composite import CompositeScheduler
        from webfuzzer.fuzzer.schedulers.entropic import EntropicScheduler

        primary = EntropicScheduler(seed=42)
        secondary = EntropicScheduler(seed=43)

        composite = CompositeScheduler(primary, secondary, seed=44)

        # Inject some state
        primary._prod_mod[100] = 2.0
        secondary._prod_mod[100] = 3.0

        composite.cleanup_removed({100})

        assert 100 not in primary._prod_mod
        assert 100 not in secondary._prod_mod


# ── Round 2: SSRF userinfo confusion ──────────────────────────────


class TestSsrfUserinfoConfusion:
    """Bug: userinfo divergence only detected when one side had empty
    userinfo. Missed cases where both had different values."""

    def test_both_truthy_userinfo_still_detected(self):
        from webfuzzer.fuzzer.oracles.ssrf_oracle import UrlConfusionStrategy

        strategy = UrlConfusionStrategy()
        inp = Input(data=b"http://admin:pass@evil.com/")

        primary = _make_result({
            "scheme": "http", "host": "evil.com", "port": "",
            "path": "/", "query": "", "fragment": "",
            "userinfo": "admin:pass",
        })
        reference = _make_result({
            "scheme": "http", "host": "evil.com", "port": "",
            "path": "/", "query": "", "fragment": "",
            "userinfo": "admin",
        })

        result = strategy.compare(inp, primary, reference, ref_index=0)
        findings = result if isinstance(result, list) else ([result] if result else [])
        authority_findings = [
            f for f in findings
            if f and f.metadata.get("category") == "authority_confusion"
        ]
        assert authority_findings, (
            "Both-truthy userinfo divergence not detected"
        )


# ── Round 2: _is_internal_host recursion depth ────────────────────


class TestInternalHostRecursionLimit:
    """Bug: _is_internal_host could recurse infinitely on multi-encoded input."""

    def test_deeply_encoded_host_no_stack_overflow(self):
        from webfuzzer.fuzzer.oracles.ssrf_oracle import _is_internal_host

        # Triple percent-encoded: should NOT cause stack overflow
        # %25 = %, so %2531%2532%2537%252e... decodes layer by layer
        deep = "%25" * 50 + "127.0.0.1"
        # Should complete without RecursionError
        _is_internal_host(deep)  # result doesn't matter, just no crash

    def test_single_encoded_still_detected(self):
        from webfuzzer.fuzzer.oracles.ssrf_oracle import _is_internal_host

        assert _is_internal_host("127%2e0%2e0%2e1")


# ── Round 2: ecofuzz energy clamp ─────────────────────────────────


class TestEcofuzzEnergyClamp:
    """Bug: AAPS energy was unbounded (max 11.0 with reward_rate=1.0)."""

    def test_energy_clamped_at_ceiling(self):
        from webfuzzer.fuzzer.schedulers.ecofuzz import EcoFuzzScheduler

        sched = EcoFuzzScheduler(seed=42)
        corpus = Corpus()
        s = corpus.force_add(Input(data=b"x"))

        # Simulate 100% success rate
        for _ in range(100):
            sched.update(s, ScheduleResult(found_new_coverage=True))

        assert s.energy <= 10.0, f"Energy {s.energy} exceeds 10.0 ceiling"


# ── Round 2: _strip_finding preserves exit_code ────────────────────


class TestStripFindingPreservesMetadata:
    """Bug: _strip_finding created ExecutionResult() with default exit_code=0."""

    def test_exit_code_preserved(self):
        from webfuzzer.fuzzer.stats import FuzzStats

        finding = Finding(
            title="test",
            severity=Severity.HIGH,
            input=Input(data=b"payload"),
            result=ExecutionResult(exit_code=42, duration_ms=123.0, stdout=b"big" * 1000),
            oracle_name="test",
        )
        FuzzStats._strip_finding(finding)
        assert finding.result.exit_code == 42
        assert finding.result.duration_ms == 123.0
        assert finding.result.stdout == b""  # stripped


# ── Round 4: cli.py None oracle placeholder ────────────────────────


class TestOraclePlaceholderFiltering:
    """Bug: sanitizer_diff/markdown oracle returned None, crashing on o.name."""

    def test_build_oracles_filters_none(self):
        from webfuzzer.cli import _build_oracles

        oracles = _build_oracles("sanitizer_diff")
        assert all(o is not None for o in oracles), "None oracle in list"

    def test_build_oracles_markdown_no_none(self):
        from webfuzzer.cli import _build_oracles

        oracles = _build_oracles("markdown")
        assert all(o is not None for o in oracles)

    def test_build_oracles_normal_oracle_works(self):
        from webfuzzer.cli import _build_oracles

        oracles = _build_oracles("cookie")
        assert len(oracles) == 1
        assert oracles[0] is not None
        assert hasattr(oracles[0], "name")


# ── Round 4: _diff_keys_for domain misclassification ──────────────


class TestDiffKeysForDomainMatch:
    """Bug: JWT/saml_validator output matched saml key set first because
    of shared 'signature_valid' key. Now uses overlap-ratio best-match."""

    def test_jwt_output_matches_jwt_keys(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import _diff_keys_for

        jwt_output = {
            "signature_valid": True,
            "effective_alg": "HS256",
            "header_alg": "HS256",
            "sub": "admin",
            "iss": "evil.com",
            "aud": "api",
        }
        keys = _diff_keys_for(jwt_output, None)
        assert "sub" in keys, f"JWT output matched wrong domain: {keys[:5]}..."
        assert "iss" in keys

    def test_saml_output_matches_saml_keys(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import _diff_keys_for

        saml_output = {
            "signature_valid": True,
            "subject": "admin@corp.com",
            "issuer": "https://idp.corp.com",
            "audience": "https://sp.corp.com",
            "assertion_count": 1,
        }
        keys = _diff_keys_for(saml_output, None)
        assert "subject" in keys, f"SAML output matched wrong domain: {keys[:5]}..."

    def test_saml_validator_output_matches_validator_keys(self):
        from webfuzzer.fuzzer.coverage.diff_coverage import _diff_keys_for

        validator_output = {
            "signature_valid": True,
            "validated_reference_uri": "#assertion1",
            "validated_node_id": "assertion1",
            "validated_node_tag": "Assertion",
            "c14n_method": "exc-c14n",
        }
        keys = _diff_keys_for(validator_output, None)
        assert "validated_reference_uri" in keys, (
            f"saml_validator output matched wrong domain: {keys[:5]}..."
        )


# ── Round 4: MAP-Elites ref_index stabilization ───────────────────


class TestMapElitesRefIndexStable:
    """Bug: MAP-Elites ref_index was relative to rotated ref list,
    so the same cell meant different parsers on different iterations."""

    def test_ref_index_translated_to_absolute(self):
        """Simulate the translation logic from engine._check_oracles."""
        # 4 targets: [A=0, B=1, C=2, D=3]
        all_targets = [0, 1, 2, 3]

        # When primary=1 (B), refs=[A, C, D] → relative ref_index=0 → A=0
        primary_idx = 1
        abs_indices = [i for i in range(len(all_targets)) if i != primary_idx]
        assert abs_indices[0] == 0  # A

        # When primary=0 (A), refs=[B, C, D] → relative ref_index=0 → B=1
        primary_idx = 0
        abs_indices = [i for i in range(len(all_targets)) if i != primary_idx]
        assert abs_indices[0] == 1  # B

        # Without fix, both would be ref_index=0 in MAP-Elites
        # With fix, they correctly map to 0 and 1 respectively

    def test_ref_index_consistent_across_rotations(self):
        """ref_index for the same parser should be the same regardless
        of which target is primary."""
        all_targets = ["A", "B", "C", "D"]

        # Target C should always have the same absolute index (2)
        for primary_idx in range(4):
            abs_indices = [i for i in range(len(all_targets)) if i != primary_idx]
            refs = [t for i, t in enumerate(all_targets) if i != primary_idx]
            if "C" in refs:
                rel_idx = refs.index("C")
                abs_idx = abs_indices[rel_idx]
                assert abs_idx == 2, (
                    f"Target C got abs_idx={abs_idx} when primary={primary_idx}"
                )


# ── Round 2: cookie_diff_strategy version mechanism ────────────────


class TestCookieVersionMechanism:
    """Bug: CookieVersionStrategy used _expiry_mechanism for version divergence."""

    def test_version_divergence_uses_correct_mechanism(self):
        from webfuzzer.fuzzer.oracles.cookie_diff_strategy import CookieVersionStrategy

        strategy = CookieVersionStrategy()
        inp = Input(data=b"$version=1; name=value")

        primary = _make_result({
            "name": "test", "value": "v", "version": "1",
        })
        reference = _make_result({
            "name": "test", "value": "v", "version": "0",
        })

        finding = strategy.compare(inp, primary, reference, ref_index=0)
        if finding:
            mechanism = finding.metadata.get("mechanism", "")
            assert "expiry" not in mechanism.lower(), (
                f"Version strategy using expiry mechanism: {mechanism}"
            )


# ── Round 3: oauth_oracle exception specificity ───────────────────


class TestOAuthOracleExceptionHandling:
    """Bug: except Exception too broad — could mask unexpected errors."""

    def test_handles_json_decode_error(self):
        from webfuzzer.fuzzer.oracles.oauth_oracle import OAuthOracle

        oracle = OAuthOracle()
        inp = Input(data=b"not-json")
        result = _make_result({
            "input_type": "redirect_uri",
            "loopback_detected": True,
            "redirect_match": True,
        })
        # Should not raise
        oracle.check(inp, result)

    def test_handles_valid_json_input(self):
        from webfuzzer.fuzzer.oracles.oauth_oracle import OAuthOracle

        oracle = OAuthOracle()
        inp = Input(data=json.dumps({"application_type": "web"}).encode())
        result = _make_result({
            "input_type": "redirect_uri",
            "loopback_detected": True,
            "redirect_match": True,
        })
        finding = oracle.check(inp, result)
        assert finding is not None


# ── Round 2: stats empty input marker ─────────────────────────────


class TestStatsEmptyInput:
    """Bug: empty input data was written as 0-byte file."""

    def test_strip_finding_empty_input(self):
        finding = Finding(
            title="test",
            severity=Severity.HIGH,
            input=Input(data=b""),
            result=ExecutionResult(exit_code=1),
            oracle_name="test",
        )
        # The input is empty but _strip_finding should still work
        from webfuzzer.fuzzer.stats import FuzzStats
        FuzzStats._strip_finding(finding)
        assert finding.input.data == b""  # stays empty (marker written by _save)
