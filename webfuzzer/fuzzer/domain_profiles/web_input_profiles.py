"""Built-in domain profiles extracted from domain.py."""

from __future__ import annotations

from ..domain_model import DangerRung, DomainProfile
from ..protocols import Severity

def register_profiles(register) -> None:
    """Register this module's built-in domain profiles."""

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
            # 2a: Fragment present in redirect URI ??suspicious shape
            DangerRung(2, (("fragment_present", "eq", True),)),
            # 2b: Loopback detected ??suspicious shape
            DangerRung(2, (("loopback_detected", "eq", True),)),
            # 3a: Redirect accepted AND fragment present (RFC violation accepted)
            DangerRung(3, (("redirect_match", "eq", True), ("fragment_present", "eq", True))),
            # 3b: Redirect accepted AND loopback (internal redirect accepted)
            DangerRung(3, (("redirect_match", "eq", True), ("loopback_detected", "eq", True))),
            # 4: Scope expansion ??granted scopes don't match requested
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
    
