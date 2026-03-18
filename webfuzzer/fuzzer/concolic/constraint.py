"""Core data model for XML constraints extracted from differential results.

An XmlConstraint captures WHY two SAML libraries diverged on a given input,
encoding the structural XML property responsible for the behavioral difference.
The constraint solver uses these to generate targeted mutations that explore
the boundary of the divergence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class XmlConstraint:
    """A symbolic constraint extracted from a differential execution."""

    # Which XML processing stage the constraint belongs to.
    #   "c14n"      — canonicalization divergence (namespace scope, algorithm)
    #   "reference" — Reference URI / ID attribute resolution ambiguity
    #   "extraction"— text extraction divergence (.text vs itertext vs textContent)
    #   "scope"     — signature scope (unsigned-but-parsed elements)
    #   "transform" — transform chain processing divergence
    domain: str

    # Machine-readable predicate within the domain, e.g.:
    #   c14n:       "ns_in_scope_diverges", "c14n_algorithm_mismatch"
    #   reference:  "id_resolution_ambiguous", "uri_missing_target"
    #   extraction: "child_element_truncation", "comment_content_hidden"
    #   scope:      "unsigned_element_parsed", "transform_scope_mismatch"
    #   transform:  "enveloped_sig_handling", "transform_order_divergence"
    predicate: str

    # Which library pair exhibited this divergence.
    # (primary_idx, ref_idx) where primary rotates during fuzzing.
    library_pair: tuple[int, int]

    # How reliably the extractor identified the cause.
    # 0.0 = heuristic guess, 1.0 = high-confidence structural match.
    confidence: float

    # Domain-specific parameters that further specify the constraint.
    # Stored as tuple of (key, value) pairs for hashability.
    #   c14n:       (("ns_prefix", "saml"), ("parent_element", "Assertion"))
    #   reference:  (("uri", "#_123"), ("id_attrs", ("ID", "Id")))
    #   extraction: (("child_tag", "t"), ("full_text", "admin@evil.com"))
    #   scope:      (("element_tag", "NameID"), ("transform_type", "enveloped"))
    parameters: tuple[tuple[str, Any], ...] = ()

    # Strategy categories in SamlMutator that are relevant to this constraint.
    # Used by constraint-biased weight selection.
    relevant_categories: frozenset[str] = field(default_factory=frozenset)

    def params_dict(self) -> dict[str, Any]:
        """Return parameters as a regular dict for convenient access."""
        return dict(self.parameters)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict (for coverage metadata, reports)."""
        return {
            "domain": self.domain,
            "predicate": self.predicate,
            "pair": list(self.library_pair),
            "confidence": self.confidence,
            "parameters": dict(self.parameters),
            "relevant_categories": sorted(self.relevant_categories),
        }

    @staticmethod
    def make_params(**kwargs: Any) -> tuple[tuple[str, Any], ...]:
        """Helper to build the frozen parameters tuple from keyword args."""
        return tuple(sorted(kwargs.items()))
