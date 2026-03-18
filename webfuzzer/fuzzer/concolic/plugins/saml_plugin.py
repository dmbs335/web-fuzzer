"""SAML domain plugin for property-learning concolic layer.

Extracts 48 structural XML/SAML properties and provides perturbation
operators for each.  Delegates to the existing PropertyExtractor and
perturbation functions.
"""

from __future__ import annotations

import random

from ..domain_plugin import DomainPlugin
from ..property_extractor import PROPERTY_NAMES, PropertyExtractor
from ..property_guided import _perturb_property
from ..property_vector import NUM_PROPERTIES, PropertyVector


class SamlPlugin(DomainPlugin):
    """SAML-specific property extraction and perturbation."""

    def __init__(self) -> None:
        self._extractor = PropertyExtractor()

    def extract(self, data: bytes) -> PropertyVector:
        return self._extractor.extract(data)

    @property
    def property_names(self) -> tuple[str, ...]:
        return PROPERTY_NAMES

    @property
    def num_properties(self) -> int:
        return NUM_PROPERTIES

    def perturb(self, data: bytes, prop_idx: int, rng: random.Random) -> list[bytes]:
        return _perturb_property(data, prop_idx, rng)

    @property
    def excluded_output_fields(self) -> frozenset[str]:
        return frozenset({
            "duration_ms",
            "digest_input_hash",
            "signed_info_hash",
            "canonical_assertion_hex",
            "signature_error",
        })

    @property
    def mutation_name_to_prop_index(self) -> dict[str, int]:
        return {
            "tag_count": 1, "ns_decl_count": 4, "empty_ns": 6,
            "relative_ns": 7, "depth": 9, "assertion_count": 10,
            "comment": 13, "pi": 14, "transform_count": 15,
            "xpath_transform": 17, "cdata": 20, "encoding_decl": 23,
            "id_attrs": 25, "duplicate_id": 26, "conditions": 34,
            "audience": 37, "nameid_format": 39, "issuer": 41,
            "keyinfo": 44, "duplicate_attrs": 46,
        }
