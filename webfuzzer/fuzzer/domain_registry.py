"""Registry and derived views for domain profiles."""

from __future__ import annotations

from .domain_model import DomainProfile
from .protocols import Severity

_GENERIC_CATEGORIES = (
    "accept_reject",
    "accept_reject_host",
    "accept_reject_scheme",
    "output",
    "timing",
    "error_pattern",
    "no_finding",
)

_registry: dict[str, DomainProfile] = {}
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
    """Return all registered profiles in registration order."""
    return list(_registry.values())


def get_all_key_sets() -> list[tuple[str, ...]]:
    """Return all registered comparison key sets."""
    global _cached_key_sets
    if _cached_key_sets is None:
        _cached_key_sets = [profile.comparison_keys for profile in _registry.values()]
    return _cached_key_sets


def get_all_categories() -> list[str]:
    """Return registered categories plus shared generic categories."""
    global _cached_categories
    if _cached_categories is None:
        seen: set[str] = set()
        categories: list[str] = []
        for profile in _registry.values():
            for category in profile.categories:
                if category not in seen:
                    seen.add(category)
                    categories.append(category)
        for category in _GENERIC_CATEGORIES:
            if category not in seen:
                seen.add(category)
                categories.append(category)
        _cached_categories = categories
    return _cached_categories


def get_merged_field_category_map() -> dict[str, tuple[str, Severity]]:
    """Return the merged field-category map across all profiles."""
    global _cached_fcm
    if _cached_fcm is None:
        merged: dict[str, tuple[str, Severity]] = {}
        for profile in _registry.values():
            merged.update(profile.field_category_map)
        _cached_fcm = merged
    return _cached_fcm


def get_merged_field_priority() -> list[str]:
    """Return the merged field priority order across all profiles."""
    global _cached_fp
    if _cached_fp is None:
        seen: set[str] = set()
        result: list[str] = []
        for profile in _registry.values():
            for field_name in profile.field_priority:
                if field_name not in seen:
                    seen.add(field_name)
                    result.append(field_name)
        _cached_fp = result
    return _cached_fp
