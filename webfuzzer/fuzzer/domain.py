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

from .domain_model import DangerRung, DomainProfile, compute_danger
from .domain_profiles.exploit_profiles import register_profiles as register_exploit_profiles
from .domain_profiles.foundation_profiles import register_profiles as register_foundation_profiles
from .domain_profiles.web_input_profiles import register_profiles as register_web_input_profiles
from .domain_registry import (
    all_profiles,
    get_all_categories,
    get_all_key_sets,
    get_merged_field_category_map,
    get_merged_field_priority,
    get_profile,
    register,
)
from .protocols import Severity


# Built-in profiles
register_foundation_profiles(register)
register_web_input_profiles(register)
register_exploit_profiles(register)
