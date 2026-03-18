"""Domain plugin interface for property-learning concolic layer.

Each fuzzing domain (SAML, JWT, Cookie, OAuth, etc.) provides:
1. PropertyExtractor — structural properties from raw input bytes
2. Perturbation registry — property-index → mutation functions
3. Property names — human-readable names for reporting

The core framework (CorrelationTracker, CoverageExtractor, budget control,
weight feedback) is domain-agnostic and shared across all domains.
"""

from __future__ import annotations

import random
import re
from abc import ABC, abstractmethod
from typing import Sequence

from .property_vector import PropertyVector


class DomainPlugin(ABC):
    """Base class for domain-specific property extraction and perturbation.

    Subclasses must implement:
    - ``extract(data) -> PropertyVector``
    - ``property_names`` — tuple of human-readable names
    - ``num_properties`` — total property count
    - ``perturb(data, prop_idx, rng) -> list[bytes]``
    """

    @abstractmethod
    def extract(self, data: bytes) -> PropertyVector:
        """Extract structural properties from raw input bytes."""

    @property
    @abstractmethod
    def property_names(self) -> tuple[str, ...]:
        """Human-readable property names, indexed by position."""

    @property
    @abstractmethod
    def num_properties(self) -> int:
        """Total number of properties extracted."""

    @abstractmethod
    def perturb(self, data: bytes, prop_idx: int, rng: random.Random) -> list[bytes]:
        """Generate mutations targeting a specific property index."""

    @property
    def excluded_output_fields(self) -> frozenset[str]:
        """Output JSON fields to exclude from divergence tracking (too noisy)."""
        return frozenset({
            "duration_ms",
            "digest_input_hash",
            "signed_info_hash",
            "canonical_assertion_hex",
        })

    @property
    def mutation_name_to_prop_index(self) -> dict[str, int]:
        """Map AST analyzer mutation names → property indices for perturbation.

        The AST analyzer outputs shorthand names like "ns_decl_count", "comment".
        This maps them to the property index that the perturb() method uses.
        Override in subclass to provide domain-specific mappings.
        """
        return {}
