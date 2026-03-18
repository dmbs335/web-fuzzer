"""AST-based branch condition extractor for Python libraries.

Automatically analyzes Python source code to extract if-conditions,
classify what input properties they check, and map them to mutation
functions from the domain plugin.

This replaces the manually-curated branch_db.py with dynamic generation.
"""

from __future__ import annotations

import ast
import importlib
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ExtractedBranch:
    """One branch condition extracted from source AST."""

    library: str  # "signxml", "pyjwt", etc.
    file: str  # "verifier.py"
    file_path: str  # full path
    line_start: int
    line_end: int
    condition_source: str  # raw Python source of condition
    condition_ast: str  # ast.dump of condition node
    input_properties: frozenset[str]  # detected input properties
    category: str  # "validation", "parsing", "crypto", "type_check", "config", "unknown"
    negatable: bool  # can we generate input to flip this branch?


# ── Property detection patterns ──────────────────────────────────
# Maps AST patterns → input property names that the condition checks.
# These are domain-agnostic patterns that work across libraries.

# Name patterns in conditions that suggest input-dependent branches
_INPUT_PROPERTY_PATTERNS: dict[str, list[str]] = {
    # XML/SAML properties
    "tag": ["element_tag"],
    "attrib": ["element_attributes"],
    "text": ["element_text"],
    "find": ["element_search"],
    "findall": ["element_search"],
    "xpath": ["xpath_query"],
    "nsmap": ["namespace_map"],
    "namespace": ["namespace"],
    "xmlns": ["namespace"],
    "uri": ["reference_uri"],
    "URI": ["reference_uri"],
    "Reference": ["reference"],
    "Transform": ["transform"],
    "Algorithm": ["algorithm"],
    "Signature": ["signature"],
    "KeyInfo": ["key_info"],
    "KeyValue": ["key_value"],
    "X509": ["x509"],
    "c14n": ["canonicalization"],
    "digest": ["digest"],
    "Assertion": ["assertion"],
    "NameID": ["nameid"],
    "Issuer": ["issuer"],
    "Conditions": ["conditions"],
    "Audience": ["audience"],
    "Subject": ["subject"],
    # JWT properties
    "alg": ["algorithm"],
    "typ": ["token_type"],
    "kid": ["key_id"],
    "jku": ["key_url"],
    "jwk": ["embedded_key"],
    "x5u": ["cert_url"],
    "crit": ["critical_headers"],
    "iss": ["issuer"],
    "sub": ["subject"],
    "aud": ["audience"],
    "exp": ["expiration"],
    "nbf": ["not_before"],
    "iat": ["issued_at"],
    "payload": ["payload"],
    "header": ["header"],
    "signature": ["signature"],
    "decode": ["decoding"],
    "encode": ["encoding"],
    "verify": ["verification"],
    # Cookie properties
    "domain": ["domain"],
    "path": ["path"],
    "expires": ["expires"],
    "max-age": ["max_age"],
    "secure": ["secure_flag"],
    "httponly": ["httponly_flag"],
    "samesite": ["samesite"],
    # General patterns
    "len(": ["length_check"],
    "isinstance": ["type_check"],
    "is not None": ["presence_check"],
    "is None": ["absence_check"],
    "not ": ["negation"],
    "==": ["equality_check"],
    "!=": ["inequality_check"],
    "startswith": ["prefix_check"],
    "endswith": ["suffix_check"],
    "in ": ["membership_check"],
}

# Condition categories
_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "validation": ["valid", "verify", "check", "require", "must",
                    "schema", "assert", "ensure", "expect"],
    "parsing": ["parse", "decode", "find", "search", "get",
                "extract", "load", "read", "split"],
    "crypto": ["sign", "encrypt", "decrypt", "hash", "digest",
               "hmac", "rsa", "ecdsa", "key", "cert", "x509",
               "algorithm", "c14n", "canonical"],
    "type_check": ["isinstance", "type(", "hasattr"],
    "config": ["config", "option", "setting", "flag", "self.config",
               "self._", "deprecated"],
}


class AstBranchExtractor:
    """Extract branch conditions from Python source files.

    Usage:
        extractor = AstBranchExtractor()
        branches = extractor.analyze_library("signxml", ["verifier.py", "processor.py"])
    """

    def analyze_library(
        self,
        library_name: str,
        source_dir: str | None = None,
        key_files: list[str] | None = None,
    ) -> list[ExtractedBranch]:
        """Analyze a Python library's source code.

        If source_dir is None, tries to find it via importlib.
        If key_files is None, analyzes all .py files.
        """
        if source_dir is None:
            source_dir = self._find_library_source(library_name)
            if source_dir is None:
                logger.warning("Cannot find source for library: %s", library_name)
                return []

        branches: list[ExtractedBranch] = []

        if key_files:
            files = [os.path.join(source_dir, f) for f in key_files]
        else:
            files = self._find_python_files(source_dir)

        for filepath in files:
            if not os.path.exists(filepath):
                continue
            try:
                file_branches = self._analyze_file(library_name, filepath)
                branches.extend(file_branches)
            except Exception as e:
                logger.debug("Failed to analyze %s: %s", filepath, e)

        return branches

    def analyze_module(self, module_name: str) -> list[ExtractedBranch]:
        """Analyze a Python module by import name (e.g., 'signxml', 'jwt')."""
        try:
            mod = importlib.import_module(module_name)
        except ImportError:
            logger.warning("Cannot import module: %s", module_name)
            return []

        source_dir = os.path.dirname(mod.__file__)
        return self.analyze_library(module_name, source_dir)

    def _analyze_file(
        self, library_name: str, filepath: str
    ) -> list[ExtractedBranch]:
        """Extract all if-conditions from a single Python file."""
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()

        try:
            tree = ast.parse(source, filepath)
        except SyntaxError:
            return []

        filename = os.path.basename(filepath)
        branches: list[ExtractedBranch] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.If):
                continue

            try:
                cond_source = ast.unparse(node.test)
            except Exception:
                continue

            # Skip trivial conditions
            if self._is_trivial(cond_source):
                continue

            # Detect input properties
            properties = self._detect_properties(cond_source)

            # Categorize
            category = self._categorize(cond_source)

            # Skip pure config/type checks — they're not input-dependent
            if category in ("config", "type_check") and not properties:
                continue

            branches.append(
                ExtractedBranch(
                    library=library_name,
                    file=filename,
                    file_path=filepath,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    condition_source=cond_source[:200],
                    condition_ast=ast.dump(node.test)[:200],
                    input_properties=frozenset(properties),
                    category=category,
                    negatable=bool(properties),
                )
            )

        return branches

    def _detect_properties(self, condition: str) -> set[str]:
        """Detect which input properties a condition checks."""
        props: set[str] = set()
        condition_lower = condition.lower()

        for pattern, prop_names in _INPUT_PROPERTY_PATTERNS.items():
            if pattern.lower() in condition_lower:
                props.update(prop_names)

        return props

    def _categorize(self, condition: str) -> str:
        """Categorize a condition."""
        condition_lower = condition.lower()

        scores: dict[str, int] = {}
        for category, keywords in _CATEGORY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw.lower() in condition_lower)
            if score > 0:
                scores[category] = score

        if not scores:
            return "unknown"
        return max(scores, key=scores.get)

    @staticmethod
    def _is_trivial(condition: str) -> bool:
        """Skip conditions that are trivially not input-dependent."""
        trivial = [
            "TYPE_CHECKING",
            "__name__",
            "sys.version",
            "sys.platform",
            "os.environ",
        ]
        return any(t in condition for t in trivial)

    @staticmethod
    def _find_library_source(library_name: str) -> str | None:
        """Find source directory for a library."""
        # Common import name → module name mappings
        import_map = {
            "signxml": "signxml",
            "python3-saml": "onelogin.saml2",
            "pyjwt": "jwt",
            "python-jose": "jose",
            "jwcrypto": "jwcrypto",
            "authlib": "authlib",
        }
        module_name = import_map.get(library_name, library_name)
        try:
            mod = importlib.import_module(module_name)
            return os.path.dirname(mod.__file__)
        except ImportError:
            return None

    @staticmethod
    def _find_python_files(source_dir: str, max_files: int = 20) -> list[str]:
        """Find Python files in directory, excluding tests."""
        files: list[str] = []
        for root, _, filenames in os.walk(source_dir):
            if "test" in root.lower() or "__pycache__" in root:
                continue
            for fn in filenames:
                if fn.endswith(".py") and not fn.startswith("_test"):
                    files.append(os.path.join(root, fn))
                    if len(files) >= max_files:
                        return files
        return files


# ── Mutation mapping ────────────────────────────────────────────

# Maps detected input properties → generic mutation strategy names.
# The DomainPlugin provides the actual perturbation implementation.

PROPERTY_TO_MUTATION: dict[str, list[str]] = {
    # XML/SAML
    "element_tag": ["tag_count", "assertion_count"],
    "element_attributes": ["attr_count", "duplicate_attrs"],
    "element_text": ["cdata", "comment", "pi"],
    "element_search": ["depth", "assertion_count", "tag_count"],
    "namespace": ["ns_decl_count", "empty_ns", "relative_ns"],
    "namespace_map": ["ns_decl_count", "empty_ns", "relative_ns"],
    "reference_uri": ["duplicate_id", "id_attrs"],
    "reference": ["transform_count"],
    "transform": ["transform_count", "xpath_transform"],
    "algorithm": ["encoding_decl"],  # algorithm confusion
    "signature": ["assertion_count"],  # multi-sig
    "key_info": ["keyinfo"],
    "key_value": ["keyinfo"],
    "x509": ["keyinfo"],
    "canonicalization": ["ns_decl_count", "relative_ns", "comment"],
    "digest": ["cdata", "comment"],
    "assertion": ["assertion_count", "depth"],
    "nameid": ["nameid_format", "comment", "pi"],
    "issuer": ["issuer"],
    "conditions": ["conditions"],
    "audience": ["audience"],
    "subject": ["nameid_format"],
    # JWT
    "token_type": ["typ"],
    "key_id": ["kid"],
    "key_url": ["jku"],
    "embedded_key": ["jwk"],
    "cert_url": ["jku"],
    "critical_headers": ["crit"],
    "expiration": ["exp"],
    "not_before": ["nbf"],
    "issued_at": ["exp"],  # reuse time perturbation
    "payload": ["claim_count"],
    "header": ["alg_none", "alg_hmac"],
    "decoding": ["b64_padding"],
    "encoding": ["b64_padding"],
    "verification": ["signature"],
    # Cookie
    "domain": ["domain"],
    "path": ["path"],
    "expires": ["maxage"],
    "max_age": ["maxage"],
    "secure_flag": ["host_prefix", "secure_prefix"],
    "httponly_flag": ["host_prefix"],
    "samesite": ["samesite"],
    # General
    "length_check": ["tag_count", "assertion_count", "claim_count"],
    "presence_check": ["tag_count"],
    "absence_check": ["tag_count"],
}


def map_branches_to_mutations(
    branches: list[ExtractedBranch],
) -> list[tuple[ExtractedBranch, list[str]]]:
    """Map extracted branches to mutation strategy names.

    Returns (branch, [mutation_names]) pairs where mutation_names
    can be resolved by the DomainPlugin.
    """
    result: list[tuple[ExtractedBranch, list[str]]] = []
    for branch in branches:
        if not branch.negatable:
            continue
        mutations: set[str] = set()
        for prop in branch.input_properties:
            mutations.update(PROPERTY_TO_MUTATION.get(prop, []))
        if mutations:
            result.append((branch, sorted(mutations)))
    return result
