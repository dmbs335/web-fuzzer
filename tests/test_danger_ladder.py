"""Tests for the domain-agnostic danger ladder system.

Covers:
  - compute_danger / _rung_matches operator semantics
  - Per-domain ladder progression (JWT, OAuth, SAML)
  - _detect_domain profile matching
  - mXSS danger path is not overridden by generic ladder
  - DangerBooster integration with generic danger levels
"""

from __future__ import annotations

import pytest

from webfuzzer.fuzzer.domain import (
    DangerRung,
    DomainProfile,
    compute_danger,
    _rung_matches,
    get_profile,
)
from webfuzzer.fuzzer.coverage.diff_coverage import _detect_domain


# ── Unit tests: compute_danger / _rung_matches ───────────────


class TestRungMatches:
    def test_empty_conditions(self):
        """Empty conditions always match."""
        assert _rung_matches({"a": 1}, ())

    def test_truthy_pass(self):
        assert _rung_matches({"x": "hello"}, (("x", "truthy", None),))

    def test_truthy_fail_absent(self):
        assert not _rung_matches({}, (("x", "truthy", None),))

    def test_truthy_fail_falsy(self):
        assert not _rung_matches({"x": ""}, (("x", "truthy", None),))
        assert not _rung_matches({"x": 0}, (("x", "truthy", None),))
        assert not _rung_matches({"x": False}, (("x", "truthy", None),))

    def test_falsy_pass(self):
        assert _rung_matches({}, (("x", "falsy", None),))
        assert _rung_matches({"x": ""}, (("x", "falsy", None),))

    def test_falsy_fail(self):
        assert not _rung_matches({"x": "yes"}, (("x", "falsy", None),))

    def test_eq_pass(self):
        assert _rung_matches({"v": True}, (("v", "eq", True),))
        assert _rung_matches({"v": "none"}, (("v", "eq", "none"),))

    def test_eq_fail(self):
        assert not _rung_matches({"v": False}, (("v", "eq", True),))

    def test_neq_pass(self):
        assert _rung_matches({"v": "RS256"}, (("v", "neq", "none"),))

    def test_neq_fail(self):
        assert not _rung_matches({"v": "none"}, (("v", "neq", "none"),))

    def test_in_pass(self):
        assert _rung_matches({"a": "sha1"}, (("a", "in", ("sha1", "md5")),))

    def test_in_fail(self):
        assert not _rung_matches({"a": "sha256"}, (("a", "in", ("sha1", "md5")),))

    def test_present_pass(self):
        assert _rung_matches({"k": None}, (("k", "present", None),))

    def test_present_fail(self):
        assert not _rung_matches({}, (("k", "present", None),))

    def test_gt_pass(self):
        assert _rung_matches({"n": 3}, (("n", "gt", 1),))

    def test_gt_fail(self):
        assert not _rung_matches({"n": 1}, (("n", "gt", 1),))
        assert not _rung_matches({"n": "abc"}, (("n", "gt", 1),))

    def test_any_present_pass(self):
        assert _rung_matches({"jku_source": "x"}, (("", "any_present", ("jku_source", "kid")),))

    def test_any_present_fail(self):
        assert not _rung_matches({"other": "x"}, (("", "any_present", ("jku_source", "kid")),))

    def test_any_truthy_pass(self):
        assert _rung_matches({"a": "", "b": "yes"}, (("", "any_truthy", ("a", "b")),))

    def test_any_truthy_fail(self):
        assert not _rung_matches({"a": "", "b": 0}, (("", "any_truthy", ("a", "b")),))

    def test_and_semantics(self):
        """All conditions must match (AND)."""
        conds = (("a", "eq", True), ("b", "eq", True))
        assert _rung_matches({"a": True, "b": True}, conds)
        assert not _rung_matches({"a": True, "b": False}, conds)

    def test_unknown_op_fails_safe(self):
        assert not _rung_matches({"x": 1}, (("x", "unknown_op", None),))


class TestComputeDanger:
    def test_empty_parsed(self):
        ladder = (DangerRung(1, (("x", "truthy", None),)),)
        assert compute_danger(None, ladder) == 0
        assert compute_danger({}, ladder) == 0

    def test_empty_ladder(self):
        assert compute_danger({"x": 1}, ()) == 0

    def test_single_rung_match(self):
        ladder = (DangerRung(3, (("x", "truthy", None),)),)
        assert compute_danger({"x": "yes"}, ladder) == 3

    def test_single_rung_no_match(self):
        ladder = (DangerRung(3, (("x", "truthy", None),)),)
        assert compute_danger({"x": ""}, ladder) == 0

    def test_max_semantics(self):
        """Highest matching level wins."""
        ladder = (
            DangerRung(1, (("a", "truthy", None),)),
            DangerRung(3, (("b", "truthy", None),)),
            DangerRung(5, (("c", "truthy", None),)),
        )
        assert compute_danger({"a": 1, "b": 1, "c": 0}, ladder) == 3
        assert compute_danger({"a": 1, "b": 1, "c": 1}, ladder) == 5

    def test_multiple_rungs_same_level(self):
        """Multiple rungs at same level — any match is sufficient."""
        ladder = (
            DangerRung(4, (("a", "truthy", None),)),
            DangerRung(4, (("b", "truthy", None),)),
        )
        assert compute_danger({"a": 1}, ladder) == 4
        assert compute_danger({"b": 1}, ladder) == 4


# ── Domain-specific ladder progression ───────────────────────


class TestJwtLadder:
    @pytest.fixture
    def ladder(self):
        profile = get_profile("jwt")
        assert profile is not None
        return profile.danger_ladder

    def test_level_0_no_output(self, ladder):
        assert compute_danger({}, ladder) == 0

    def test_level_0_parse_success_not_rewarded(self, ladder):
        """Parse success (effective_alg present/truthy) no longer triggers danger."""
        assert compute_danger({"effective_alg": ""}, ladder) == 0
        assert compute_danger({"effective_alg": "RS256"}, ladder) == 0

    def test_level_2_external_key_hint(self, ladder):
        assert compute_danger({
            "jku_source": "https://evil.com/jwks",
        }, ladder) == 2

    def test_level_2_resolved_kid(self, ladder):
        assert compute_danger({"resolved_kid": "evil-key-id"}, ladder) == 2

    def test_level_3_nested_jwt_with_inner_sig_valid(self, ladder):
        # nested_jwt=True but inner sig explicitly valid → stays at 3
        assert compute_danger({"nested_jwt": True, "inner_signature_valid": True}, ladder) == 3

    def test_level_4_nested_jwt_inner_sig_unknown(self, ladder):
        # nested_jwt=True without inner sig info → danger 4 (unchecked)
        assert compute_danger({"nested_jwt": True}, ladder) == 4

    def test_level_3_token_type_mismatch(self, ladder):
        # JWE observed when JWS expected → type confusion
        assert compute_danger({
            "token_type_observed": "jwe",
        }, ladder) == 3

    def test_level_0_token_type_jws(self, ladder):
        # Normal JWS → no danger from type rung
        assert compute_danger({"token_type_observed": "jws"}, ladder) == 0

    def test_level_4_external_key_accepted(self, ladder):
        """External key hint + valid signature = key confusion succeeded."""
        assert compute_danger({
            "jku_source": "https://evil.com/jwks", "signature_valid": True,
        }, ladder) == 4

    def test_level_4_inner_sig_unchecked(self, ladder):
        assert compute_danger({
            "nested_jwt": True, "inner_signature_valid": False,
        }, ladder) == 4

    def test_level_5_crit_ignored(self, ladder):
        assert compute_danger({
            "signature_valid": True, "crit_processed": False,
        }, ladder) == 5

    def test_level_5_temporal_gap(self, ladder):
        assert compute_danger({
            "signature_valid": True, "time_valid": False,
        }, ladder) == 5

    def test_level_6_alg_none(self, ladder):
        assert compute_danger({
            "effective_alg": "none", "signature_valid": True,
        }, ladder) == 6


class TestOauthLadder:
    @pytest.fixture
    def ladder(self):
        profile = get_profile("oauth")
        assert profile is not None
        return profile.danger_ladder

    def test_level_0(self, ladder):
        assert compute_danger({}, ladder) == 0

    def test_level_0_parse_success_not_rewarded(self, ladder):
        """Parse success (normalized/host) no longer triggers danger."""
        assert compute_danger({"candidate_normalized": "https://example.com"}, ladder) == 0
        assert compute_danger({
            "candidate_normalized": "https://a.com", "candidate_host": "a.com",
        }, ladder) == 0

    def test_level_2_fragment(self, ladder):
        assert compute_danger({"fragment_present": True}, ladder) == 2

    def test_level_2_loopback(self, ladder):
        assert compute_danger({"loopback_detected": True}, ladder) == 2

    def test_level_3_redirect_with_fragment(self, ladder):
        assert compute_danger({
            "redirect_match": True, "fragment_present": True,
        }, ladder) == 3

    def test_level_3_redirect_with_loopback(self, ladder):
        assert compute_danger({
            "redirect_match": True, "loopback_detected": True,
        }, ladder) == 3

    def test_redirect_match_alone_no_danger(self, ladder):
        """redirect_match=True without suspicious shape → no danger."""
        assert compute_danger({"redirect_match": True}, ladder) == 0

    def test_level_4_scope_expansion(self, ladder):
        assert compute_danger({"scope_match": False}, ladder) == 4

    def test_level_5_pkce_partial(self, ladder):
        assert compute_danger({
            "challenge_was_absent": True, "challenge_match": False,
        }, ladder) == 5

    def test_level_6_pkce_full_bypass(self, ladder):
        assert compute_danger({
            "challenge_was_absent": True, "challenge_match": True,
        }, ladder) == 6


class TestSamlLadder:
    @pytest.fixture
    def ladder(self):
        profile = get_profile("saml")
        assert profile is not None
        return profile.danger_ladder

    def test_level_0(self, ladder):
        assert compute_danger({}, ladder) == 0

    def test_level_0_subject_only_not_rewarded(self, ladder):
        """Subject extraction alone (parse success) no longer triggers danger."""
        assert compute_danger({"subject": "user@example.com"}, ladder) == 0

    def test_level_2_multi_assertion(self, ladder):
        # Must set reference_matches=True to avoid triggering rung 4
        # (absent field is falsy → rung 4 matches)
        assert compute_danger({
            "assertion_count": 2,
            "reference_matches_selected_assertion": True,
        }, ladder) == 2

    def test_level_3_multi_assertion_with_subject(self, ladder):
        assert compute_danger({
            "assertion_count": 2, "subject": "admin",
            "reference_matches_selected_assertion": True,
        }, ladder) == 3

    def test_level_4_reference_mismatch(self, ladder):
        # Rung 4 requires assertion_count > 1 AND reference mismatch
        assert compute_danger({
            "assertion_count": 2,
            "reference_matches_selected_assertion": False,
        }, ladder) == 4

    def test_level_4_reference_absent_in_multi_assertion(self, ladder):
        """Absent reference field is falsy → also triggers rung 4."""
        assert compute_danger({
            "assertion_count": 2, "subject": "admin",
        }, ladder) == 4

    def test_level_4_reference_mismatch_in_multi_assertion(self, ladder):
        assert compute_danger({
            "assertion_count": 2, "subject": "admin",
            "reference_matches_selected_assertion": False,
        }, ladder) == 4

    def test_level_5_weak_algo_short(self, ladder):
        assert compute_danger({"signature_method": "sha1"}, ladder) == 5

    def test_level_5_weak_algo_uri(self, ladder):
        assert compute_danger({
            "signature_method": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        }, ladder) == 5

    def test_single_assertion_ref_mismatch_not_level_4(self, ladder):
        """Single assertion with ref mismatch should NOT reach level 4."""
        assert compute_danger({
            "reference_matches_selected_assertion": False,
        }, ladder) < 4

    def test_level_4_reference_none(self, ladder):
        """None (unresolved URI) is falsy → rung 4 with multi-assertion."""
        assert compute_danger({
            "assertion_count": 2,
            "reference_matches_selected_assertion": None,
        }, ladder) == 4

    def test_level_6_sig_bypass(self, ladder):
        assert compute_danger({
            "signature_valid": True,
            "assertion_count": 2,
            "reference_matches_selected_assertion": False,
        }, ladder) == 6

    def test_level_6_sig_bypass_none_ref(self, ladder):
        """sig_valid + multi-assertion + None ref → level 6."""
        assert compute_danger({
            "signature_valid": True,
            "assertion_count": 2,
            "reference_matches_selected_assertion": None,
        }, ladder) == 6

    def test_level_6_requires_multi_assertion(self, ladder):
        """sig_valid + ref mismatch but single assertion → NOT level 6."""
        assert compute_danger({
            "signature_valid": True,
            "reference_matches_selected_assertion": False,
        }, ladder) < 6


# ── _detect_domain ────────────────────────────────────────────


class TestDetectDomain:
    def test_jwt_detected(self):
        parsed = {"signature_valid": True, "effective_alg": "RS256", "sub": "user"}
        keys, profile = _detect_domain(parsed, None)
        assert profile is not None
        assert profile.name == "jwt"

    def test_saml_detected(self):
        parsed = {"signature_valid": True, "subject": "admin", "assertion_count": 1,
                   "reference_matches_selected_assertion": True}
        keys, profile = _detect_domain(parsed, None)
        assert profile is not None
        assert profile.name == "saml"

    def test_oauth_detected(self):
        parsed = {"redirect_match": True, "candidate_host": "example.com",
                   "candidate_normalized": "https://example.com"}
        keys, profile = _detect_domain(parsed, None)
        assert profile is not None
        assert profile.name == "oauth"

    def test_sanitizer_detected(self):
        parsed = {"has_script": False, "has_event_handler": False,
                   "has_javascript_uri": False, "empty_output": True}
        keys, profile = _detect_domain(parsed, None)
        assert profile is not None
        assert profile.name == "sanitizer"

    def test_none_returns_default(self):
        keys, profile = _detect_domain(None, None)
        assert profile is None

    def test_unknown_keys_no_profile(self):
        parsed = {"completely_unknown_field": "value"}
        keys, profile = _detect_domain(parsed, None)
        assert profile is None


# ── mXSS danger path preservation ─────────────────────────────


class TestMxssDangerUnchanged:
    """Ensure the sanitizer domain does NOT have a danger_ladder,
    so the mXSS hardcoded path in diff_coverage.py is not overridden."""

    def test_sanitizer_no_ladder(self):
        profile = get_profile("sanitizer")
        assert profile is not None
        assert profile.danger_ladder == ()

    def test_url_no_ladder(self):
        profile = get_profile("url")
        assert profile is not None
        assert profile.danger_ladder == ()


# ── DangerBooster integration ─────────────────────────────────


class TestDangerBoosterIntegration:
    def test_jwt_danger_activates_booster(self):
        """DangerBooster should boost seeds when JWT danger >= 2."""
        from webfuzzer.fuzzer.schedulers.danger_booster import DangerBooster, DangerBoostConfig
        from webfuzzer.fuzzer.corpus import Corpus, Seed, CoverageMap
        from webfuzzer.fuzzer.protocols import Input

        booster = DangerBooster(DangerBoostConfig())
        corpus = Corpus()

        inp = Input(data=b"test", metadata={})
        cov = CoverageMap(bitmap=bytearray(65536), edge_count=1)
        cov.bitmap[0] = 1
        seed = corpus.add(inp, cov)
        assert seed is not None

        initial_boost = seed.priority_boost

        # Danger level 3 should trigger a boost
        booster.on_execution(seed, 3, corpus)
        assert seed.priority_boost > initial_boost

        # Same level should NOT re-boost (escalation-only)
        boosted = seed.priority_boost
        booster.on_execution(seed, 3, corpus)
        assert seed.priority_boost == boosted

        # Higher level should boost again
        booster.on_execution(seed, 5, corpus)
        assert seed.priority_boost > boosted
