"""Built-in domain profiles extracted from domain.py."""

from __future__ import annotations

from ..domain_model import DangerRung, DomainProfile
from ..protocols import Severity

def register_profiles(register) -> None:
    """Register this module's built-in domain profiles."""

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
            # 2: Multiple assertions present ??wrapping attack surface
            DangerRung(2, (("assertion_count", "gt", 1),)),
            # 3: Multiple assertions AND subject extracted ??selection happened
            DangerRung(3, (("assertion_count", "gt", 1), ("subject", "truthy", None))),
            # 4: Multi-assertion AND reference scope doesn't cover selected assertion
            #    (falsy catches both False and None ??None means URI couldn't resolve)
            DangerRung(4, (("assertion_count", "gt", 1), ("reference_matches_selected_assertion", "falsy", None))),
            # 5: Weak signature algorithm accepted (short names + XML DSig URIs)
            DangerRung(5, (("signature_method", "in", (
                "sha1", "md5", "hmac-sha1", "rsa-sha1",
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                "http://www.w3.org/2000/09/xmldsig#sha1",
                "http://www.w3.org/2001/04/xmldsig-more#md5",
            )),)),
            # 6: Signature valid BUT assertion outside signed scope ??full bypass
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
            # 2: External key hint observed ??attack surface for key confusion
            DangerRung(2, (("", "any_truthy", ("jku_source", "resolved_kid")),)),
            # 3a: Nested JWT opened ??token confusion surface
            DangerRung(3, (("nested_jwt", "eq", True),)),
            # 3b: Token type mismatch ??observed != expected (e.g. JWE received when JWS expected)
            DangerRung(3, (("token_type_observed", "neq", "jws"),)),
            # 4a: External key accepted with valid signature ??key confusion succeeded
            DangerRung(4, (("", "any_truthy", ("jku_source", "resolved_kid")), ("signature_valid", "eq", True))),
            # 4b: Nested JWT with inner signature unchecked or failed
            DangerRung(4, (("nested_jwt", "eq", True), ("inner_signature_valid", "in", (False, None)))),
            # 5a: Signature valid but critical header present and ignored
            DangerRung(5, (("signature_valid", "eq", True), ("crit_processed", "eq", False))),
            # 5b: Signature valid but temporal validation failed
            DangerRung(5, (("signature_valid", "eq", True), ("time_valid", "eq", False))),
            # 6: alg=none bypass ??signature accepted with no algorithm
            DangerRung(6, (("signature_valid", "eq", True), ("effective_alg", "in", ("none", "None", "NONE")))),
        ),
    ))
    
