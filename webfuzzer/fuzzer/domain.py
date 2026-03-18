"""Domain profile registry for differential fuzzing.

Each fuzzing domain (URL, SAML, etc.) declares its comparison keys,
finding categories, and field-to-category mappings in ONE place.
Components query the registry instead of hardcoding domain knowledge.

Adding a new domain:
    register(DomainProfile(
        name="jwt",
        comparison_keys=("alg", "sub", "iss", "aud", "exp"),
        categories=("alg_none_bypass", "key_confusion"),
        field_category_map={"alg": ("alg_confusion", Severity.CRITICAL)},
        field_priority=("alg", "sub", "iss"),
    ))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .protocols import Severity


# ── Danger Ladder ─────────────────────────────────────────────

@dataclass(frozen=True)
class DangerRung:
    """One level of the danger ladder.

    Each rung defines a danger ``level`` (0-6) and a tuple of
    ``conditions`` that must ALL be true for the rung to match.

    Condition format: ``(field_name, operator, value)``

    Operators:
        truthy   — bool(parsed[field]) is true
        falsy    — parsed[field] is falsy or absent
        eq       — parsed[field] == value
        neq      — parsed[field] != value
        in       — parsed[field] in value  (value is a tuple)
        present  — field exists in parsed dict
        gt       — parsed[field] > value
        any_present — any(f in parsed for f in value)
        any_truthy  — any(parsed.get(f) for f in value)
    """

    level: int
    conditions: tuple[tuple[str, str, Any], ...]


def _rung_matches(parsed: dict, conditions: tuple[tuple[str, str, Any], ...]) -> bool:
    """Check whether ALL conditions of a rung are satisfied."""
    for fld, op, val in conditions:
        if op == "truthy":
            if not parsed.get(fld):
                return False
        elif op == "falsy":
            if parsed.get(fld):
                return False
        elif op == "eq":
            if parsed.get(fld) != val:
                return False
        elif op == "neq":
            if fld not in parsed or parsed[fld] == val:
                return False
        elif op == "in":
            if parsed.get(fld) not in val:
                return False
        elif op == "present":
            if fld not in parsed:
                return False
        elif op == "gt":
            v = parsed.get(fld)
            if not (isinstance(v, (int, float)) and v > val):
                return False
        elif op == "any_present":
            if not any(f in parsed for f in val):
                return False
        elif op == "any_truthy":
            if not any(parsed.get(f) for f in val):
                return False
        else:
            return False  # Unknown operator — fail safe
    return True


def compute_danger(
    parsed: dict | None, ladder: tuple[DangerRung, ...],
) -> int:
    """Evaluate danger ladder against parsed JSON output.

    Returns the highest matching level (0 if nothing matches).
    """
    if not parsed or not ladder:
        return 0
    max_level = 0
    for rung in ladder:
        if rung.level > max_level and _rung_matches(parsed, rung.conditions):
            max_level = rung.level
    return max_level


@dataclass(frozen=True)
class DomainProfile:
    """Declaration of domain-specific constants consumed by fuzzer components.

    Attributes:
        name: Short identifier (e.g. "url", "saml").
        comparison_keys: JSON output keys for DiffCoverageCollector.
            Order is stable and used for deterministic feature hashing.
        categories: Finding categories for MAP-Elites grid.
        field_category_map: OutputStrategy field → (category, severity).
        field_priority: Priority order for field-based classification.
        danger_ladder: Declarative danger levels (0-6) for gradient-guided
            search.  Each rung defines conditions on parsed JSON output.
            Evaluated by DiffCoverageCollector to set CoverageMap.danger_lvl.
    """

    name: str
    comparison_keys: tuple[str, ...]
    categories: tuple[str, ...]
    field_category_map: dict[str, tuple[str, Severity]] = field(
        default_factory=dict, hash=False,
    )
    field_priority: tuple[str, ...] = ()
    danger_ladder: tuple[DangerRung, ...] = ()


# ── Registry ────────────────────────────────────────────────────

_registry: dict[str, DomainProfile] = {}

# Cached derived views — invalidated on register().
_cached_key_sets: list[tuple[str, ...]] | None = None
_cached_categories: list[str] | None = None
_cached_fcm: dict[str, tuple[str, Severity]] | None = None
_cached_fp: list[str] | None = None


def _invalidate_cache() -> None:
    global _cached_key_sets, _cached_categories, _cached_fcm, _cached_fp
    _cached_key_sets = None
    _cached_categories = None
    _cached_fcm = None
    _cached_fp = None


def register(profile: DomainProfile) -> None:
    """Register a domain profile. Later registrations override earlier ones."""
    _registry[profile.name] = profile
    _invalidate_cache()


def get_profile(name: str) -> DomainProfile | None:
    """Look up a specific domain profile by name."""
    return _registry.get(name)


def all_profiles() -> list[DomainProfile]:
    """All registered profiles in registration order."""
    return list(_registry.values())


# ── Derived views (cached, recomputed after register()) ─────────

def get_all_key_sets() -> list[tuple[str, ...]]:
    """All registered comparison key sets (for DiffCoverageCollector)."""
    global _cached_key_sets
    if _cached_key_sets is None:
        _cached_key_sets = [p.comparison_keys for p in _registry.values()]
    return _cached_key_sets


def get_all_categories() -> list[str]:
    """All registered categories + generic suffixes (for MAP-Elites).

    Deduplicates while preserving order. Generic categories are always
    appended last, with ``no_finding`` guaranteed to be the final entry.
    """
    global _cached_categories
    if _cached_categories is None:
        seen: set[str] = set()
        cats: list[str] = []
        for profile in _registry.values():
            for c in profile.categories:
                if c not in seen:
                    seen.add(c)
                    cats.append(c)
        for gc in _GENERIC_CATEGORIES:
            if gc not in seen:
                seen.add(gc)
                cats.append(gc)
        _cached_categories = cats
    return _cached_categories


def get_merged_field_category_map() -> dict[str, tuple[str, Severity]]:
    """Merged field_category_map from all profiles (for OutputStrategy).

    Later profiles override earlier ones for the same field name.
    """
    global _cached_fcm
    if _cached_fcm is None:
        merged: dict[str, tuple[str, Severity]] = {}
        for profile in _registry.values():
            merged.update(profile.field_category_map)
        _cached_fcm = merged
    return _cached_fcm


def get_merged_field_priority() -> list[str]:
    """Merged field_priority from all profiles (for OutputStrategy).

    Concatenates each profile's priority list in registration order,
    deduplicating while preserving order.
    """
    global _cached_fp
    if _cached_fp is None:
        seen: set[str] = set()
        result: list[str] = []
        for profile in _registry.values():
            for f in profile.field_priority:
                if f not in seen:
                    seen.add(f)
                    result.append(f)
        _cached_fp = result
    return _cached_fp


# ── Generic categories (always present) ─────────────────────────

_GENERIC_CATEGORIES = (
    "accept_reject",
    "accept_reject_host",
    "accept_reject_scheme",
    "output",
    "timing",
    "error_pattern",
    "no_finding",
)


# ── Built-in profiles ──────────────────────────────────────────

register(DomainProfile(
    name="url",
    comparison_keys=(
        "scheme", "userinfo", "host", "port", "path", "query", "fragment",
    ),
    categories=(
        "ssrf_host_confusion",
        "open_redirect",
        "scheme_confusion",
        "authority_confusion",
        "path_traversal",
        "port_confusion",
        "path_confusion",
        "query_confusion",
        "fragment_confusion",
    ),
    field_category_map={
        "host": ("host_mismatch", Severity.MEDIUM),
        "scheme": ("scheme_mismatch", Severity.MEDIUM),
        "path": ("path_mismatch", Severity.MEDIUM),
        "port": ("port_mismatch", Severity.LOW),
        "query": ("query_mismatch", Severity.LOW),
        "fragment": ("fragment_mismatch", Severity.LOW),
        "userinfo": ("authority_mismatch", Severity.MEDIUM),
    },
    field_priority=(
        "host", "scheme", "userinfo", "path", "port", "query", "fragment",
    ),
))

register(DomainProfile(
    name="saml",
    comparison_keys=(
        "signature_valid", "subject", "issuer", "audience",
        "assertion_count", "assertion_id", "selected_assertion_index",
        "selection_mode", "reference_uri",
        "reference_matches_selected_assertion",
        "transform_chain_length", "c14n_method_used",
        "reference_resolution_mode",
    ),
    categories=(
        "signature_bypass",
        "subject_confusion",
        "attribute_confusion",
        "assertion_count_divergence",
        "assertion_selection_divergence",
        "reference_scope_divergence",
        "extraction_divergence",
        "one_sided_accept",
        "algorithm_confusion",
        "issuer_confusion",
        "audience_confusion",
        "encoding_parse_divergence",
        "encoding_subject_confusion",
        "transform_confusion",
        "multiple_assertions",
        "weak_algorithm",
    ),
    field_category_map={
        "signature_valid": ("signature_bypass", Severity.CRITICAL),
        "subject": ("subject_confusion", Severity.CRITICAL),
        "issuer": ("issuer_confusion", Severity.MEDIUM),
        "audience": ("audience_confusion", Severity.MEDIUM),
        "assertion_count": ("assertion_count_divergence", Severity.HIGH),
        "assertion_id": ("assertion_selection_divergence", Severity.HIGH),
        "selected_assertion_index": ("assertion_selection_divergence", Severity.HIGH),
        "selection_mode": ("assertion_selection_divergence", Severity.MEDIUM),
        "reference_uri": ("reference_scope_divergence", Severity.MEDIUM),
        "reference_matches_selected_assertion": ("reference_scope_divergence", Severity.HIGH),
    },
    field_priority=(
        "signature_valid", "subject", "reference_matches_selected_assertion",
        "assertion_id", "selected_assertion_index", "selection_mode",
        "reference_uri", "issuer", "audience", "assertion_count",
    ),
    danger_ladder=(
        # 2: Multiple assertions present — wrapping attack surface
        DangerRung(2, (("assertion_count", "gt", 1),)),
        # 3: Multiple assertions AND subject extracted — selection happened
        DangerRung(3, (("assertion_count", "gt", 1), ("subject", "truthy", None))),
        # 4: Multi-assertion AND reference scope doesn't cover selected assertion
        #    (falsy catches both False and None — None means URI couldn't resolve)
        DangerRung(4, (("assertion_count", "gt", 1), ("reference_matches_selected_assertion", "falsy", None))),
        # 5: Weak signature algorithm accepted (short names + XML DSig URIs)
        DangerRung(5, (("signature_method", "in", (
            "sha1", "md5", "hmac-sha1", "rsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            "http://www.w3.org/2000/09/xmldsig#sha1",
            "http://www.w3.org/2001/04/xmldsig-more#md5",
        )),)),
        # 6: Signature valid BUT assertion outside signed scope — full bypass
        DangerRung(6, (("signature_valid", "eq", True), ("assertion_count", "gt", 1), ("reference_matches_selected_assertion", "falsy", None))),
    ),
))

register(DomainProfile(
    name="saml_validator",
    comparison_keys=(
        "signature_valid",
        "validated_reference_uri",
        "validated_node_id",
        "validated_node_tag",
        "resolved_id_attribute",
        "id_resolution_mode",
        "transform_chain",
        "transform_chain_length",
        "c14n_method",
        "c14n_method_used",
        "signature_method",
        "digest_method",
        "digest_input_hash",
        "signed_info_hash",
        "key_source",
        "keyinfo_type",
        "reference_resolution_mode",
    ),
    categories=(
        "validator_accept_reject",
        "validator_reference_target_divergence",
        "validator_digest_input_divergence",
        "validator_c14n_divergence",
        "validator_transform_divergence",
        "validator_id_resolution_divergence",
        "validator_key_source_divergence",
    ),
    field_category_map={
        "signature_valid": ("validator_accept_reject", Severity.CRITICAL),
        "validated_reference_uri": ("validator_reference_target_divergence", Severity.HIGH),
        "validated_node_id": ("validator_reference_target_divergence", Severity.CRITICAL),
        "validated_node_tag": ("validator_reference_target_divergence", Severity.HIGH),
        "resolved_id_attribute": ("validator_id_resolution_divergence", Severity.HIGH),
        "id_resolution_mode": ("validator_id_resolution_divergence", Severity.MEDIUM),
        "transform_chain": ("validator_transform_divergence", Severity.HIGH),
        "transform_chain_length": ("validator_transform_divergence", Severity.MEDIUM),
        "c14n_method": ("validator_c14n_divergence", Severity.MEDIUM),
        "c14n_method_used": ("validator_c14n_divergence", Severity.HIGH),
        "signed_info_hash": ("validator_c14n_divergence", Severity.HIGH),
        "reference_resolution_mode": ("validator_reference_target_divergence", Severity.HIGH),
        "digest_input_hash": ("validator_digest_input_divergence", Severity.HIGH),
        "key_source": ("validator_key_source_divergence", Severity.HIGH),
        "keyinfo_type": ("validator_key_source_divergence", Severity.MEDIUM),
    },
    field_priority=(
        "signature_valid",
        "validated_node_id",
        "validated_reference_uri",
        "digest_input_hash",
        "signed_info_hash",
        "resolved_id_attribute",
        "transform_chain",
        "transform_chain_length",
        "reference_resolution_mode",
        "key_source",
        "keyinfo_type",
        "validated_node_tag",
        "id_resolution_mode",
        "c14n_method",
        "c14n_method_used",
        "signature_method",
        "digest_method",
    ),
))

register(DomainProfile(
    name="jwt",
    comparison_keys=(
        "signature_valid", "effective_alg", "header_alg", "key_source",
        "token_type_observed", "sub", "iss", "aud", "role", "scope",
        "time_valid", "resolved_kid", "nested_jwt",
        "inner_signature_valid", "duplicate_claim_keys", "duplicate_header_keys",
        "crit_processed", "b64_mode",
        "claim_parse_mode", "jku_source",
        "claim_types",
        "zip_processed",
    ),
    categories=(
        "alg_none_bypass",
        "algorithm_confusion",
        "key_confusion",
        "header_policy_confusion",
        "nested_token_confusion",
        "subject_confusion",
        "issuer_confusion",
        "audience_confusion",
        "role_confusion",
        "scope_confusion",
        "temporal_confusion",
        "token_type_confusion",
        "duplicate_key_confusion",
        "claim_type_confusion",
        "zip_format_confusion",
    ),
    field_category_map={
        "signature_valid": ("alg_none_bypass", Severity.CRITICAL),
        "effective_alg": ("algorithm_confusion", Severity.CRITICAL),
        "header_alg": ("algorithm_confusion", Severity.HIGH),
        "key_source": ("key_confusion", Severity.CRITICAL),
        "resolved_kid": ("key_confusion", Severity.HIGH),
        "token_type_observed": ("token_type_confusion", Severity.CRITICAL),
        "nested_jwt": ("nested_token_confusion", Severity.HIGH),
        "inner_signature_valid": ("nested_token_confusion", Severity.CRITICAL),
        "sub": ("subject_confusion", Severity.CRITICAL),
        "iss": ("issuer_confusion", Severity.MEDIUM),
        "aud": ("audience_confusion", Severity.MEDIUM),
        "role": ("role_confusion", Severity.HIGH),
        "scope": ("scope_confusion", Severity.HIGH),
        "time_valid": ("temporal_confusion", Severity.HIGH),
        "duplicate_claim_keys": ("duplicate_key_confusion", Severity.HIGH),
        "duplicate_header_keys": ("duplicate_key_confusion", Severity.HIGH),
        "crit_processed": ("header_policy_confusion", Severity.HIGH),
        "b64_mode": ("header_policy_confusion", Severity.MEDIUM),
        "claim_parse_mode": ("duplicate_key_confusion", Severity.HIGH),
        "jku_source": ("key_confusion", Severity.HIGH),
        "claim_types": ("claim_type_confusion", Severity.HIGH),
        "zip_processed": ("zip_format_confusion", Severity.HIGH),
    },
    field_priority=(
        "signature_valid", "effective_alg", "header_alg", "key_source",
        "token_type_observed", "inner_signature_valid", "sub",
        "role", "scope", "resolved_kid", "nested_jwt",
        "time_valid", "crit_processed", "b64_mode",
        "duplicate_claim_keys", "duplicate_header_keys",
        "claim_parse_mode", "jku_source",
        "iss", "aud",
    ),
    danger_ladder=(
        # 2: External key hint observed — attack surface for key confusion
        DangerRung(2, (("", "any_truthy", ("jku_source", "resolved_kid")),)),
        # 3a: Nested JWT opened — token confusion surface
        DangerRung(3, (("nested_jwt", "eq", True),)),
        # 3b: Token type mismatch — observed != expected (e.g. JWE received when JWS expected)
        DangerRung(3, (("token_type_observed", "neq", "jws"),)),
        # 4a: External key accepted with valid signature — key confusion succeeded
        DangerRung(4, (("", "any_truthy", ("jku_source", "resolved_kid")), ("signature_valid", "eq", True))),
        # 4b: Nested JWT with inner signature unchecked or failed
        DangerRung(4, (("nested_jwt", "eq", True), ("inner_signature_valid", "in", (False, None)))),
        # 5a: Signature valid but critical header present and ignored
        DangerRung(5, (("signature_valid", "eq", True), ("crit_processed", "eq", False))),
        # 5b: Signature valid but temporal validation failed
        DangerRung(5, (("signature_valid", "eq", True), ("time_valid", "eq", False))),
        # 6: alg=none bypass — signature accepted with no algorithm
        DangerRung(6, (("signature_valid", "eq", True), ("effective_alg", "in", ("none", "None", "NONE")))),
    ),
))

register(DomainProfile(
    name="sanitizer",
    comparison_keys=(
        "has_script", "has_event_handler", "has_javascript_uri",
        "has_data_uri", "has_svg", "has_math", "has_style",
        "has_form", "has_base", "has_iframe", "has_object_embed",
        "has_noscript", "empty_output",
    ),
    categories=(
        "script_bypass",
        "event_handler_bypass",
        "javascript_uri_bypass",
        "data_uri_bypass",
        "iframe_bypass",
        "object_embed_bypass",
        "base_tag_bypass",
        "namespace_divergence",
        "structural_mutation",
        "normalization_divergence",
        "dom_clobbering",
        "post_sanitization_gadget",
    ),
    field_category_map={
        "has_script": ("script_bypass", Severity.CRITICAL),
        "has_event_handler": ("event_handler_bypass", Severity.CRITICAL),
        "has_javascript_uri": ("javascript_uri_bypass", Severity.CRITICAL),
        "has_data_uri": ("data_uri_bypass", Severity.HIGH),
        "has_iframe": ("iframe_bypass", Severity.HIGH),
        "has_object_embed": ("object_embed_bypass", Severity.HIGH),
        "has_base": ("base_tag_bypass", Severity.HIGH),
        "has_svg": ("namespace_divergence", Severity.MEDIUM),
        "has_math": ("namespace_divergence", Severity.MEDIUM),
        "has_noscript": ("normalization_divergence", Severity.LOW),
    },
    field_priority=(
        "has_script", "has_event_handler", "has_javascript_uri",
        "has_data_uri", "has_iframe", "has_object_embed", "has_base",
        "has_svg", "has_math", "has_style", "has_form", "has_noscript",
        "empty_output",
    ),
))

register(DomainProfile(
    name="oauth",
    comparison_keys=(
        "redirect_match", "redirect_matched_index",
        "candidate_scheme", "candidate_host", "candidate_port",
        "candidate_path", "candidate_normalized",
        "loopback_detected", "fragment_present",
        "scope_match", "scope_count_granted",
        "scope_count_requested", "scope_empty_elements",
        "scope_parsed_granted", "scope_parsed_requested",
        "challenge_computed", "challenge_match",
        "verifier_valid", "challenge_has_padding",
        "method_resolved",
        # Token request fields
        "grant_type_valid", "grant_type_normalized",
        "client_id_valid", "client_secret_format_valid",
        "redirect_uri_format_valid", "code_format_valid",
        "overall_valid",
        # Token response fields
        "token_type_normalized", "token_type_valid",
        "expires_in_valid", "expires_in_raw_type",
        "scope_subset_of_requested", "scope_changed",
        "is_error_response", "parse_success",
    ),
    categories=(
        "redirect_uri_bypass",
        "redirect_host_confusion",
        "redirect_scheme_confusion",
        "redirect_port_confusion",
        "redirect_path_confusion",
        "redirect_uri_normalization",
        "fragment_handling_divergence",
        "loopback_divergence",
        "scope_expansion",
        "scope_parsing_divergence",
        "pkce_match_divergence",
        "pkce_padding_divergence",
        "pkce_verifier_divergence",
        "pkce_method_divergence",
        # Token exchange categories
        "token_request_validity_divergence",
        "grant_type_confusion",
        "code_format_divergence",
        "token_type_confusion",
        "expires_in_confusion",
        "scope_downgrade_divergence",
        "error_handling_divergence",
    ),
    field_category_map={
        "redirect_match": ("redirect_uri_bypass", Severity.CRITICAL),
        "candidate_host": ("redirect_host_confusion", Severity.CRITICAL),
        "candidate_scheme": ("redirect_scheme_confusion", Severity.HIGH),
        "candidate_port": ("redirect_port_confusion", Severity.MEDIUM),
        "candidate_path": ("redirect_path_confusion", Severity.HIGH),
        "candidate_normalized": ("redirect_uri_normalization", Severity.MEDIUM),
        "loopback_detected": ("loopback_divergence", Severity.MEDIUM),
        "fragment_present": ("fragment_handling_divergence", Severity.HIGH),
        "scope_match": ("scope_expansion", Severity.HIGH),
        "scope_count_granted": ("scope_parsing_divergence", Severity.MEDIUM),
        "scope_count_requested": ("scope_parsing_divergence", Severity.MEDIUM),
        "scope_empty_elements": ("scope_parsing_divergence", Severity.LOW),
        "scope_parsed_granted": ("scope_parsing_divergence", Severity.MEDIUM),
        "scope_parsed_requested": ("scope_parsing_divergence", Severity.MEDIUM),
        "challenge_match": ("pkce_match_divergence", Severity.CRITICAL),
        "challenge_computed": ("pkce_padding_divergence", Severity.HIGH),
        "verifier_valid": ("pkce_verifier_divergence", Severity.MEDIUM),
        "challenge_has_padding": ("pkce_padding_divergence", Severity.MEDIUM),
        "method_resolved": ("pkce_method_divergence", Severity.HIGH),
        # Token request fields
        "overall_valid": ("token_request_validity_divergence", Severity.CRITICAL),
        "grant_type_valid": ("grant_type_confusion", Severity.HIGH),
        "grant_type_normalized": ("grant_type_confusion", Severity.MEDIUM),
        "client_id_valid": ("token_request_validity_divergence", Severity.HIGH),
        "code_format_valid": ("code_format_divergence", Severity.MEDIUM),
        "redirect_uri_format_valid": ("token_request_validity_divergence", Severity.HIGH),
        # Token response fields
        "token_type_valid": ("token_type_confusion", Severity.CRITICAL),
        "token_type_normalized": ("token_type_confusion", Severity.HIGH),
        "expires_in_valid": ("expires_in_confusion", Severity.HIGH),
        "expires_in_raw_type": ("expires_in_confusion", Severity.MEDIUM),
        "scope_subset_of_requested": ("scope_downgrade_divergence", Severity.HIGH),
        "scope_changed": ("scope_downgrade_divergence", Severity.MEDIUM),
        "is_error_response": ("error_handling_divergence", Severity.HIGH),
    },
    field_priority=(
        "redirect_match", "candidate_host", "candidate_scheme",
        "candidate_path", "candidate_normalized",
        "loopback_detected", "fragment_present",
        "candidate_port", "redirect_matched_index",
        "scope_match", "scope_count_granted",
        "scope_count_requested", "scope_empty_elements",
        "scope_parsed_granted", "scope_parsed_requested",
        "challenge_match", "challenge_computed",
        "verifier_valid", "challenge_has_padding",
        "method_resolved",
        # Token exchange priority
        "overall_valid", "grant_type_valid", "grant_type_normalized",
        "token_type_valid", "token_type_normalized",
        "expires_in_valid", "is_error_response",
        "scope_subset_of_requested", "scope_changed",
        "client_id_valid", "code_format_valid",
        "redirect_uri_format_valid", "expires_in_raw_type",
    ),
    danger_ladder=(
        # 2a: Fragment present in redirect URI — suspicious shape
        DangerRung(2, (("fragment_present", "eq", True),)),
        # 2b: Loopback detected — suspicious shape
        DangerRung(2, (("loopback_detected", "eq", True),)),
        # 3a: Redirect accepted AND fragment present (RFC violation accepted)
        DangerRung(3, (("redirect_match", "eq", True), ("fragment_present", "eq", True))),
        # 3b: Redirect accepted AND loopback (internal redirect accepted)
        DangerRung(3, (("redirect_match", "eq", True), ("loopback_detected", "eq", True))),
        # 4: Scope expansion — granted scopes don't match requested
        DangerRung(4, (("scope_match", "eq", False),)),
        # 5: PKCE partially bypassed (challenge absent, match failed)
        DangerRung(5, (("challenge_was_absent", "eq", True), ("challenge_match", "eq", False))),
        # 6: Full PKCE bypass (challenge absent but accepted)
        DangerRung(6, (("challenge_was_absent", "eq", True), ("challenge_match", "eq", True))),
    ),
))

register(DomainProfile(
    name="graphql_exec",
    comparison_keys=(
        "parsed", "valid", "executed",
        "data_hash", "data_shape",
        "null_path_hash", "error_path_hash",
        "error_count_exec", "has_partial_data",
        "null_propagation_depth",
    ),
    categories=(
        "exec_acceptance_split",
        "exec_null_propagation_divergence",
        "exec_data_shape_divergence",
        "exec_error_path_divergence",
        "exec_partial_data_divergence",
        "exec_data_value_divergence",
    ),
    field_category_map={
        "executed": ("exec_acceptance_split", Severity.CRITICAL),
        "data_hash": ("exec_data_value_divergence", Severity.MEDIUM),
        "data_shape": ("exec_data_shape_divergence", Severity.HIGH),
        "null_path_hash": ("exec_null_propagation_divergence", Severity.CRITICAL),
        "error_path_hash": ("exec_error_path_divergence", Severity.HIGH),
        "has_partial_data": ("exec_partial_data_divergence", Severity.HIGH),
        "null_propagation_depth": ("exec_null_propagation_divergence", Severity.HIGH),
    },
    field_priority=(
        "executed", "null_path_hash", "data_shape",
        "error_path_hash", "has_partial_data", "data_hash",
        "null_propagation_depth", "error_count_exec",
    ),
))

register(DomainProfile(
    name="graphql",
    comparison_keys=(
        "parsed", "valid", "operation_type", "operation_name",
        "selection_count", "max_depth", "error_count",
        "has_introspection", "has_subscription", "has_mutation",
        "alias_count", "inline_fragment_count", "spread_count",
        "field_set_hash", "directive_set_hash", "fragment_set_hash",
        "error_categories",
    ),
    categories=(
        "parse_divergence",
        "validation_divergence",
        "field_resolution_divergence",
        "directive_recognition_divergence",
        "directive_validation_divergence",
        "type_condition_divergence",
        "enum_coercion_divergence",
        "depth_complexity_divergence",
        "introspection_divergence",
        "operation_type_divergence",
        "fragment_divergence",
        "error_count_divergence",
    ),
    field_category_map={
        "parsed": ("parse_divergence", Severity.HIGH),
        "valid": ("validation_divergence", Severity.HIGH),
        "operation_type": ("operation_type_divergence", Severity.MEDIUM),
        "selection_count": ("field_resolution_divergence", Severity.MEDIUM),
        "max_depth": ("depth_complexity_divergence", Severity.MEDIUM),
        "has_introspection": ("introspection_divergence", Severity.HIGH),
        "has_subscription": ("operation_type_divergence", Severity.MEDIUM),
        "has_mutation": ("operation_type_divergence", Severity.MEDIUM),
        "alias_count": ("field_resolution_divergence", Severity.LOW),
        "inline_fragment_count": ("type_condition_divergence", Severity.MEDIUM),
        "spread_count": ("fragment_divergence", Severity.MEDIUM),
        "error_count": ("error_count_divergence", Severity.LOW),
    },
    field_priority=(
        "parsed", "valid", "has_introspection",
        "operation_type", "max_depth", "selection_count",
        "inline_fragment_count", "spread_count",
        "alias_count", "error_count",
        "has_subscription", "has_mutation", "operation_name",
    ),
))

register(DomainProfile(
    name="markdown",
    comparison_keys=(
        "has_raw_html", "has_script", "has_event_handler",
        "has_javascript_uri", "has_data_uri", "has_iframe",
        "has_link", "has_image", "autolinks_found",
        "html_blocks_preserved", "empty_output",
        "link_count", "image_count", "element_set_hash",
        # Semantic signals (break boolean ceiling)
        "dangerous_link_count", "dangerous_scheme_set",
        "event_handler_set", "tag_category_set",
        "link_context_set",
        "has_form", "has_object_embed", "has_foreign_ns", "has_base_meta",
    ),
    categories=(
        "xss_script_injection",
        "xss_event_handler",
        "javascript_uri_injection",
        "data_uri_injection",
        "xss_html_injection",
        "link_injection",
        "image_injection",
        "raw_html_divergence",
        "autolink_divergence",
        "html_block_divergence",
        "tag_category_divergence",
        "event_handler_type_divergence",
        "link_context_divergence",
        "form_divergence",
        "foreign_ns_divergence",
    ),
    field_category_map={
        "has_script": ("xss_script_injection", Severity.CRITICAL),
        "has_event_handler": ("xss_event_handler", Severity.CRITICAL),
        "has_javascript_uri": ("javascript_uri_injection", Severity.CRITICAL),
        "has_data_uri": ("data_uri_injection", Severity.HIGH),
        "has_iframe": ("xss_html_injection", Severity.HIGH),
        "has_form": ("form_divergence", Severity.HIGH),
        "has_object_embed": ("xss_html_injection", Severity.HIGH),
        "has_foreign_ns": ("foreign_ns_divergence", Severity.MEDIUM),
        "has_base_meta": ("xss_html_injection", Severity.HIGH),
        "has_raw_html": ("raw_html_divergence", Severity.MEDIUM),
        "has_link": ("link_injection", Severity.MEDIUM),
        "has_image": ("image_injection", Severity.MEDIUM),
        "autolinks_found": ("autolink_divergence", Severity.MEDIUM),
        "html_blocks_preserved": ("html_block_divergence", Severity.LOW),
    },
    field_priority=(
        "has_script", "has_event_handler", "has_javascript_uri",
        "has_data_uri", "has_iframe", "has_form", "has_object_embed",
        "has_base_meta", "has_foreign_ns", "has_raw_html",
        "has_link", "has_image", "autolinks_found",
        "html_blocks_preserved", "empty_output",
    ),
))

register(DomainProfile(
    name="deser",
    comparison_keys=(
        "deserialized", "sink_reached", "sink_depth",
        "filter_decision", "filter_rejected_class",
        "chain_class_hash", "readObject_calls",
        "method_invocation_hash",
        "process_spawned", "jndi_lookup", "class_loaded",
        "file_accessed", "network_connected",
    ),
    categories=(
        "sink_reach_divergence",
        "filter_bypass",
        "chain_depth_divergence",
        "type_resolution_divergence",
        "exception_divergence",
        "partial_deserialization",
        "cross_library_chain",
    ),
    field_category_map={
        "sink_reached": ("sink_reach_divergence", Severity.CRITICAL),
        "filter_decision": ("filter_bypass", Severity.CRITICAL),
        "deserialized": ("exception_divergence", Severity.HIGH),
        "chain_class_hash": ("type_resolution_divergence", Severity.HIGH),
        "sink_depth": ("chain_depth_divergence", Severity.MEDIUM),
        "process_spawned": ("sink_reach_divergence", Severity.CRITICAL),
        "jndi_lookup": ("sink_reach_divergence", Severity.CRITICAL),
        "class_loaded": ("cross_library_chain", Severity.HIGH),
    },
    field_priority=(
        "sink_reached", "filter_decision", "process_spawned",
        "jndi_lookup", "deserialized", "chain_class_hash",
        "sink_depth", "class_loaded", "method_invocation_hash",
    ),
    danger_ladder=(
        DangerRung(1, (("deserialized", "eq", True),)),
        DangerRung(2, (("deserialized", "eq", True), ("sink_depth", "gt", 1))),
        DangerRung(3, (("class_loaded", "eq", True),)),
        DangerRung(4, (("", "any_truthy", ("file_accessed", "network_connected")),)),
        DangerRung(5, (("jndi_lookup", "eq", True),)),
        DangerRung(6, (("process_spawned", "eq", True),)),
    ),
))

# ── JDBC connection-level exploitation ────────────────────────
register(DomainProfile(
    name="jdbc",
    comparison_keys=(
        "connected", "driver_loaded", "driver_class",
        "pool_created", "pool_type",
        "lifecycle_hook_executed", "lifecycle_hook_type",
        "sql_executed", "sink_reached",
        "process_spawned", "file_write", "file_read",
        "network_connected", "class_loaded", "deser_triggered",
    ),
    categories=(
        "driver_exploit",
        "pool_lifecycle_abuse",
        "connection_property_deser",
        "sql_injection_rce",
        "auth_bypass",
        "file_access",
        "network_ssrf",
        "cross_driver_confusion",
    ),
    field_priority=(
        "sink_reached", "process_spawned", "deser_triggered",
        "lifecycle_hook_executed", "sql_executed", "connected",
        "file_write", "file_read", "network_connected",
        "class_loaded", "driver_loaded", "pool_created",
    ),
    danger_ladder=(
        DangerRung(1, (("driver_loaded", "eq", True),)),
        DangerRung(2, (("connected", "eq", True),)),
        DangerRung(3, (("pool_created", "eq", True), ("lifecycle_hook_executed", "eq", True))),
        DangerRung(4, (("sql_executed", "eq", True),)),
        DangerRung(4, (("deser_triggered", "eq", True),)),
        DangerRung(5, (("", "any_truthy", ("file_write", "file_read", "network_connected")),)),
        DangerRung(6, (("process_spawned", "eq", True),)),
    ),
))

# ── DOM Clobbering ────────────────────────────────────────────
register(DomainProfile(
    name="domclobber",
    comparison_keys=(
        "clobber_count", "clobber_chain_depth",
        "clobber_has_anchor_href", "clobber_has_form_children",
        "clobber_has_collection", "clobber_dangerous_targets",
        "sanitize_dom_active", "sanitize_named_props_active",
        "has_script", "has_event_handler", "has_javascript_uri",
        "has_form", "has_iframe", "empty_output",
    ),
    categories=(
        "clobber_vector_divergence",
        "clobber_chain_depth_divergence",
        "clobber_anchor_href_divergence",
        "clobber_builtin_shadow_divergence",
        "clobber_defense_divergence",
        "clobber_dangerous_target",
        "clobber_form_child_chain",
        "clobber_collection_chain",
    ),
    field_category_map={
        "clobber_dangerous_targets": ("clobber_dangerous_target", Severity.CRITICAL),
        "clobber_has_anchor_href": ("clobber_anchor_href_divergence", Severity.HIGH),
        "clobber_has_form_children": ("clobber_form_child_chain", Severity.HIGH),
        "clobber_has_collection": ("clobber_collection_chain", Severity.HIGH),
        "clobber_chain_depth": ("clobber_chain_depth_divergence", Severity.HIGH),
        "clobber_count": ("clobber_vector_divergence", Severity.MEDIUM),
        "sanitize_dom_active": ("clobber_defense_divergence", Severity.MEDIUM),
        "sanitize_named_props_active": ("clobber_defense_divergence", Severity.MEDIUM),
    },
    field_priority=(
        "clobber_dangerous_targets", "clobber_has_anchor_href",
        "clobber_has_form_children", "clobber_has_collection",
        "clobber_chain_depth", "clobber_count",
        "sanitize_dom_active", "sanitize_named_props_active",
        "has_script", "has_event_handler", "has_javascript_uri",
        "has_form", "has_iframe", "empty_output",
    ),
    danger_ladder=(
        # 1: Any clobbering vector present
        DangerRung(1, (("clobber_count", "gt", 0),)),
        # 2: Chain depth > 1 (form.child or collection access)
        DangerRung(2, (("clobber_chain_depth", "gt", 1),)),
        # 3: Anchor href clobbering (toString → attacker URL)
        DangerRung(3, (("clobber_has_anchor_href", "eq", True),)),
        # 4: Dangerous targets clobbered (currentScript, location, etc.)
        DangerRung(4, (("clobber_dangerous_targets", "truthy", None),)),
        # 5: Chain depth + anchor href + dangerous targets (full exploit chain)
        DangerRung(5, (
            ("clobber_chain_depth", "gt", 1),
            ("clobber_has_anchor_href", "eq", True),
            ("clobber_dangerous_targets", "truthy", None),
        )),
        # 6: Clobbering + active script execution (XSS via clobbering)
        DangerRung(6, (
            ("clobber_count", "gt", 0),
            ("", "any_truthy", ("has_script", "has_event_handler", "has_javascript_uri")),
        )),
    ),
))

# ── Class Pollution (Python prototype pollution analog) ────────
register(DomainProfile(
    name="class_pollution",
    comparison_keys=(
        "merged", "chain_depth", "dunder_traversed_count",
        "globals_polluted_count", "class_attrs_changed_count",
        "attrs_changed_count", "merge_impl", "exception_class",
        # Phase 2: execution-guided coverage features
        "access_path_hash", "globals_reachable_count", "sink_types_hash",
    ),
    categories=(
        "globals_write",
        "class_attr_pollution",
        "instance_attr_pollution",
        "dunder_reachability",
        "merge_accept_reject",
        "chain_depth_divergence",
        "filter_bypass",
        "globals_reachability",
        "sink_reachability",
    ),
    field_category_map={
        "globals_polluted_count": ("globals_write", Severity.CRITICAL),
        "class_attrs_changed_count": ("class_attr_pollution", Severity.HIGH),
        "attrs_changed_count": ("instance_attr_pollution", Severity.HIGH),
        "chain_depth": ("chain_depth_divergence", Severity.MEDIUM),
        "merged": ("merge_accept_reject", Severity.HIGH),
        "dunder_traversed_count": ("dunder_reachability", Severity.MEDIUM),
    },
    field_priority=(
        "globals_polluted_count", "class_attrs_changed_count",
        "attrs_changed_count", "chain_depth", "merged",
        "dunder_traversed_count", "merge_impl",
    ),
    danger_ladder=(
        # 1: Merge succeeded
        DangerRung(1, (("merged", "eq", True),)),
        # 2: Dunder traversal occurred
        DangerRung(2, (("merged", "eq", True), ("dunder_traversed_count", "gt", 0))),
        # 3: Deep chain (depth >= 2)
        DangerRung(3, (("merged", "eq", True), ("chain_depth", "gt", 1))),
        # 4: Class attributes modified
        DangerRung(4, (("class_attrs_changed_count", "gt", 0),)),
        # 5: Globals polluted (non-dangerous)
        DangerRung(5, (("globals_polluted_count", "gt", 0),)),
        # 6: Callable sinks reachable OR multiple globals polluted (RCE path)
        DangerRung(6, (("globals_reachable_count", "gt", 2),)),
        # 7: Multiple globals polluted (confirmed RCE)
        DangerRung(7, (("globals_polluted_count", "gt", 1),)),
    ),
))

# ── Apache Confusion (module interaction confusion) ────────────
register(DomainProfile(
    name="apache_confusion",
    comparison_keys=(
        # Per-phase URI snapshots (the core confusion signal)
        "uri_at_translate", "uri_at_access_check",
        "uri_at_fixup", "uri_at_handler",
        # Per-phase filename snapshots
        "filename_at_access_check", "filename_at_handler",
        # Handler tracking
        "handler_at_access_check", "handler_at_handler",
        # Status and outcome
        "status_code", "final_handler",
        # Derived confusion signals
        "uri_changed_post_access", "filename_changed_post_access",
        "handler_changed_post_access",
        "access_check_target_matches_handler_target",
        # Body content heuristic (exploitability)
        "served_protected_content", "body_marker",
    ),
    categories=(
        "filename_confusion",
        "handler_confusion",
        "path_confusion",
        "docroot_confusion",
        "access_bypass",
        "backend_confusion",
        "phase_desync",
        "encoding_confusion",
        "content_leak",
    ),
    field_category_map={
        "access_check_target_matches_handler_target": (
            "access_bypass", Severity.CRITICAL),
        "filename_changed_post_access": (
            "filename_confusion", Severity.CRITICAL),
        "handler_changed_post_access": (
            "handler_confusion", Severity.CRITICAL),
        "uri_changed_post_access": (
            "path_confusion", Severity.HIGH),
        "filename_at_handler": (
            "filename_confusion", Severity.HIGH),
        "uri_at_handler": (
            "path_confusion", Severity.HIGH),
        "handler_at_handler": (
            "handler_confusion", Severity.MEDIUM),
        "final_handler": (
            "backend_confusion", Severity.HIGH),
        "status_code": (
            "access_bypass", Severity.MEDIUM),
        "served_protected_content": (
            "content_leak", Severity.CRITICAL),
    },
    field_priority=(
        "access_check_target_matches_handler_target",
        "filename_changed_post_access",
        "handler_changed_post_access",
        "uri_changed_post_access",
        "filename_at_handler",
        "uri_at_handler",
        "handler_at_handler",
        "final_handler",
        "status_code",
    ),
    danger_ladder=(
        # 1: URI differs between phases (some normalization happening)
        DangerRung(1, (("uri_changed_post_access", "eq", True),)),
        # 2: Filename changes after access check
        DangerRung(2, (("filename_changed_post_access", "eq", True),)),
        # 3: Handler changes after access check
        DangerRung(3, (("handler_changed_post_access", "eq", True),)),
        # 4: Both filename AND handler change (strong confusion signal)
        DangerRung(4, (
            ("filename_changed_post_access", "eq", True),
            ("handler_changed_post_access", "eq", True),
        )),
        # 5: Access check target mismatches handler target
        DangerRung(5, (
            ("access_check_target_matches_handler_target", "eq", False),
        )),
        # 6: 200 OK AND access check saw different target than handler
        DangerRung(6, (
            ("status_code", "eq", 200),
            ("access_check_target_matches_handler_target", "eq", False),
        )),
        # 7: Protected content actually served (confirmed exploitable)
        DangerRung(7, (
            ("served_protected_content", "eq", True),
        )),
    ),
))

# ── JS Sandbox Escape ────────────────────────────────────────
register(DomainProfile(
    name="sandbox",
    comparison_keys=(
        "escaped", "type", "errorPattern", "retType",
        "reportCalled", "reportValType",
        "error", "returnValue", "validation",
    ),
    categories=(
        "sandbox_escape",
        "sandbox_behavioral_diff",
        "sandbox_accept_reject",
    ),
    field_category_map={
        "escaped": ("sandbox_escape", Severity.CRITICAL),
        "type": ("sandbox_behavioral_diff", Severity.HIGH),
        "error": ("sandbox_accept_reject", Severity.MEDIUM),
    },
    field_priority=(
        "escaped",
        "payload",
        "type",
        "error",
    ),
    danger_ladder=(
        # 1: Code produces an error (some execution happened)
        DangerRung(1, (("error", "truthy"),)),
        # 2: ReferenceError — looking for a name, close to escape
        DangerRung(2, (("type", "eq", "ReferenceError"),)),
        # 3: EvalError — eval blocked, very close
        DangerRung(3, (("type", "eq", "EvalError"),)),
        # 4: Escaped!
        DangerRung(4, (("escaped", "truthy"),)),
        # 5: Escaped with payload exfiltrated
        DangerRung(5, (
            ("escaped", "truthy"),
            ("payload", "truthy"),
        )),
    ),
))
