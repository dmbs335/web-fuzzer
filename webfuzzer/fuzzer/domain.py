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
    """

    name: str
    comparison_keys: tuple[str, ...]
    categories: tuple[str, ...]
    field_category_map: dict[str, tuple[str, Severity]] = field(
        default_factory=dict, hash=False,
    )
    field_priority: tuple[str, ...] = ()


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
        "assertion_count", "assertion_id",
    ),
    categories=(
        "signature_bypass",
        "subject_confusion",
        "attribute_confusion",
        "assertion_count_divergence",
        "assertion_selection_divergence",
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
    },
    field_priority=(
        "signature_valid", "subject", "assertion_id",
        "issuer", "audience", "assertion_count",
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
