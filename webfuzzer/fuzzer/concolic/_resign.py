"""Shared SAML re-signing utility.

Re-exports the re-signing functions from saml_mutator to avoid
duplicating the lazy-loaded singleton signer pattern.  Both the
SamlMutator and the concolic ConstraintSolver import from here
(or equivalently from saml_mutator directly).
"""

from __future__ import annotations

# Re-export from the authoritative implementation.
# This avoids duplicating _get_signer(), the global signer cache,
# and the 3-tier assertion finding strategy.
from ..mutators.saml_mutator import _resign_assertion_bytes as resign_saml

__all__ = ["resign_saml"]
