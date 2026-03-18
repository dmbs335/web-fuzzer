"""Constraint extraction from SAML differential execution results.

Inspects the already-parsed JSON outputs from target libraries (same data
that SamlDiffStrategy uses) and produces XmlConstraint objects describing
WHY divergences occurred.  Zero additional target execution required.

Five extraction heuristics:
  1. C14N Divergence — namespace/canonicalization keywords in signature_error
  2. Reference Resolution — assertion_count or reference_matches divergence
  3. Text Extraction — subject differs with both signatures valid
  4. Signature Scope — one accepts modified element, other rejects
  5. Transform Chain — transform processing keywords in error messages
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import OrderedDict
from typing import Any

from ..oracles._saml_parsing import parse_saml_output
from ..protocols import ExecutionResult, Input
from .constraint import XmlConstraint

logger = logging.getLogger(__name__)

# ── Regex patterns for heuristic classification ──────────────────

_C14N_KEYWORDS = re.compile(
    r"c14n|canonical|namespace|prefix|inclusive|exclusive|xmlns",
    re.IGNORECASE,
)
_TRANSFORM_KEYWORDS = re.compile(
    r"transform|enveloped|xpath|xslt|filter",
    re.IGNORECASE,
)
_REFERENCE_KEYWORDS = re.compile(
    r"reference|uri|id\b|wsu:id|xml:id",
    re.IGNORECASE,
)
_KEY_KEYWORDS = re.compile(
    r"certificate|key|x509|rsa|hmac|dsa",
    re.IGNORECASE,
)

# Regex for detecting namespace declarations in raw XML
_NS_DECL_RE = re.compile(rb'xmlns(?::(\w+))?="([^"]*)"')

# Regex for Reference URI
_REF_URI_RE = re.compile(rb'<(?:ds:)?Reference[^>]*URI="([^"]*)"')

# Regex for ID-like attributes
_ID_ATTR_RE = re.compile(rb'<(\w+:)?(\w+)\b[^>]*?\b(ID|Id|xml:id|wsu:Id)="([^"]*)"')

# Void c14n indicators (from saml_diff_strategy.py)
_VOID_NS_RE = re.compile(
    rb'xmlns:\w+="(?:'
    rb'[0-9]+|'
    rb'\.|'
    rb'[a-z]+/[a-z]+|'
    rb'#|'
    rb'//|'
    rb'\?[a-z]+|'
    rb'%00|'
    rb'data:,|'
    rb')"'
)
_EMPTY_NS_RE = re.compile(rb'xmlns:\w+=""')

# Known empty-string digest values
_EMPTY_SHA256 = b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
_EMPTY_SHA1 = b"2jmj7l5rSw0yVb/vlWAYkK/YBwk="

# ── Strategy category sets for constraint mapping ────────────────

_C14N_STRATEGIES = frozenset({
    "void_c14n_relative_ns", "c14n_superfluous_ns", "c14n_inherited_ns",
    "c14n_default_vs_prefixed_ns", "c14n_xml_inherited_attrs",
    "c14n_prefixlist_inject", "c14n_2_0_algorithm_swap",
    "c14n_qname_in_attrvalue", "c14n_xml_attr_ancestor",
    "c14n_default_ns_switch", "c14n_attr_value_normalization",
    "namespace_redeclaration", "namespace_undeclare",
    "namespace_prefix_remap", "void_c14n_enhanced",
    "void_c14n_precomputed_digest", "inclusive_ns_manipulate",
})

_C14N_ALGO_STRATEGIES = frozenset({
    "c14n_method_swap", "signedinfo_c14n_swap", "transform_remove_c14n",
    "c14n_2_0_algorithm_swap",
})

_REFERENCE_STRATEGIES = frozenset({
    "xsw1_pre_assertion_clone", "xsw2_post_assertion_clone",
    "xsw3_assertion_in_assertion", "xsw4_assertion_swap",
    "xsw5_post_signature_assertion", "xsw7_extensions_embed",
    "xsw8_object_embed", "xsw_first_assertion_extract",
    "xsw_signed_in_extensions", "reference_uri_empty",
    "reference_uri_xpointer", "reference_dual_target",
    "assertion_id_collision", "xsw_envelope_inversion",
    "duplicate_reference", "ns_prefixed_attr_dup",
    "reserved_ns_attr_inject",
})

_EXTRACTION_STRATEGIES = frozenset({
    "nameid_mixed_content", "nameid_spoof", "multi_nameid",
    "unicode_normalization", "null_byte_inject",
    "unicode_identity_confusion", "comment_inject_digest",
    "processing_instruction_inject", "attribute_injection",
})

_SCOPE_STRATEGIES = frozenset({
    "xpath_transform_exclude_subject", "xpath_filter2_subtract_conditions",
    "xpath_filter2_union_evil", "xpath_filter2_multi_step",
    "transform_chain_inject", "manifest_reference_inject",
    "xslt_pre_verification_transform",
})

_TRANSFORM_STRATEGIES = frozenset({
    "transform_chain_inject", "transform_remove_enveloped",
    "xslt_transform_inject", "xslt_pre_verification_transform",
    "xpointer_comment_preservation",
})

# Max constraints per input (prevent explosion)
_MAX_CONSTRAINTS_PER_INPUT = 10


class ConstraintExtractor:
    """Extract symbolic XML constraints from differential SAML results.

    Operates on already-parsed JSON output dicts — no additional target
    execution required.  Maintains a bounded cache to avoid redundant
    extraction on the same input.
    """

    def __init__(self, cache_size: int = 1000) -> None:
        self._cache: OrderedDict[str, list[XmlConstraint]] = OrderedDict()
        self._cache_size = cache_size
        self.stats = _ExtractorStats()

    def extract(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
    ) -> list[XmlConstraint]:
        """Extract constraints from a differential execution.

        Returns a list of XmlConstraint objects (possibly empty).
        Only triggers when at least one pair shows divergence.
        """
        p_data = parse_saml_output(primary_result.stdout)
        if p_data is None:
            return []

        all_constraints: list[XmlConstraint] = []

        for ref_idx, ref_result in enumerate(ref_results):
            r_data = parse_saml_output(ref_result.stdout)
            if r_data is None:
                continue

            # Check cache
            cache_key = self._cache_key(inp, ref_idx)
            if cache_key in self._cache:
                self._cache.move_to_end(cache_key)
                all_constraints.extend(self._cache[cache_key])
                continue

            pair_constraints = self._extract_pair(
                inp, p_data, r_data,
                primary_idx=0, ref_idx=ref_idx,
            )

            # Cache result
            self._cache[cache_key] = pair_constraints
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

            all_constraints.extend(pair_constraints)

        # Cap total constraints
        if len(all_constraints) > _MAX_CONSTRAINTS_PER_INPUT:
            # Keep highest confidence
            all_constraints.sort(key=lambda c: c.confidence, reverse=True)
            all_constraints = all_constraints[:_MAX_CONSTRAINTS_PER_INPUT]

        self.stats.total_extractions += 1
        self.stats.total_constraints += len(all_constraints)
        return all_constraints

    def _extract_pair(
        self,
        inp: Input,
        p_data: dict[str, Any],
        r_data: dict[str, Any],
        primary_idx: int,
        ref_idx: int,
    ) -> list[XmlConstraint]:
        """Extract constraints for a single (primary, reference) pair."""
        pair = (primary_idx, ref_idx)
        constraints: list[XmlConstraint] = []

        p_valid = p_data.get("signature_valid", False)
        r_valid = r_data.get("signature_valid", False)
        p_subject = (p_data.get("subject") or "").strip()
        r_subject = (r_data.get("subject") or "").strip()
        p_error = p_data.get("signature_error", "") or ""
        r_error = r_data.get("signature_error", "") or ""

        # Quick check: any divergence at all?
        sig_diverges = p_valid != r_valid
        subject_diverges = (
            p_subject and r_subject
            and p_subject != r_subject
        )
        assertion_count_diverges = (
            p_data.get("assertion_count", 1) != r_data.get("assertion_count", 1)
        )

        if not (sig_diverges or subject_diverges or assertion_count_diverges):
            return []

        raw = inp.data

        # ── Heuristic 1: C14N Divergence ──
        if sig_diverges:
            c14n_constraint = self._check_c14n_divergence(
                raw, p_data, r_data, p_error, r_error, pair,
            )
            if c14n_constraint:
                constraints.append(c14n_constraint)

        # ── Heuristic 2: Reference Resolution ──
        if assertion_count_diverges or sig_diverges:
            ref_constraint = self._check_reference_resolution(
                raw, p_data, r_data, pair,
            )
            if ref_constraint:
                constraints.append(ref_constraint)

        # ── Heuristic 3: Text Extraction ──
        if subject_diverges:
            ext_constraint = self._check_text_extraction(
                raw, p_data, r_data, p_subject, r_subject, pair,
            )
            if ext_constraint:
                constraints.append(ext_constraint)

        # ── Heuristic 4: Signature Scope ──
        if sig_diverges:
            scope_constraint = self._check_signature_scope(
                raw, p_data, r_data, p_valid, r_valid, pair,
            )
            if scope_constraint:
                constraints.append(scope_constraint)

        # ── Heuristic 5: Transform Chain ──
        if sig_diverges:
            transform_constraint = self._check_transform_chain(
                raw, p_error, r_error, pair,
            )
            if transform_constraint:
                constraints.append(transform_constraint)

        return constraints

    # ── Heuristic implementations ────────────────────────────────

    def _check_c14n_divergence(
        self,
        raw: bytes,
        p_data: dict, r_data: dict,
        p_error: str, r_error: str,
        pair: tuple[int, int],
    ) -> XmlConstraint | None:
        """Detect c14n/namespace-related divergence."""
        errors = f"{p_error} {r_error}"

        # Check if error messages mention c14n/namespace
        has_c14n_keywords = bool(_C14N_KEYWORDS.search(errors))

        # Check if input has void c14n indicators
        has_void_ns = bool(_VOID_NS_RE.search(raw) or _EMPTY_NS_RE.search(raw))
        has_empty_digest = _EMPTY_SHA256 in raw or _EMPTY_SHA1 in raw

        if not (has_c14n_keywords or has_void_ns):
            return None

        # Extract namespace context from input
        ns_decls = _NS_DECL_RE.findall(raw[:8000])
        ns_prefixes = [
            prefix.decode("utf-8", errors="replace")
            for prefix, _ in ns_decls if prefix
        ]

        # Determine specific predicate
        if has_void_ns and has_empty_digest:
            predicate = "void_c14n_precomputed"
            confidence = 0.9
        elif has_void_ns:
            predicate = "ns_in_scope_diverges"
            confidence = 0.8
        elif has_c14n_keywords and "algorithm" in errors.lower():
            predicate = "c14n_algorithm_mismatch"
            confidence = 0.7
            return XmlConstraint(
                domain="c14n",
                predicate=predicate,
                library_pair=pair,
                confidence=confidence,
                parameters=XmlConstraint.make_params(
                    ns_prefixes=tuple(ns_prefixes),
                    error_hint=errors[:200],
                ),
                relevant_categories=_C14N_ALGO_STRATEGIES,
            )
        else:
            predicate = "ns_in_scope_diverges"
            confidence = 0.6

        return XmlConstraint(
            domain="c14n",
            predicate=predicate,
            library_pair=pair,
            confidence=confidence,
            parameters=XmlConstraint.make_params(
                ns_prefixes=tuple(ns_prefixes),
                has_void_ns=has_void_ns,
                has_empty_digest=has_empty_digest,
            ),
            relevant_categories=_C14N_STRATEGIES,
        )

    def _check_reference_resolution(
        self,
        raw: bytes,
        p_data: dict, r_data: dict,
        pair: tuple[int, int],
    ) -> XmlConstraint | None:
        """Detect Reference URI / ID resolution ambiguity."""
        p_ac = p_data.get("assertion_count", 1)
        r_ac = r_data.get("assertion_count", 1)
        p_ref_match = p_data.get("reference_matches_selected_assertion")
        r_ref_match = r_data.get("reference_matches_selected_assertion")

        # Extract Reference URI from input
        ref_uri_match = _REF_URI_RE.search(raw[:8000])
        ref_uri = (
            ref_uri_match.group(1).decode("utf-8", errors="replace")
            if ref_uri_match else ""
        )

        # Extract ID-like attributes
        id_attrs = _ID_ATTR_RE.findall(raw[:8000])
        id_attr_names = sorted(set(
            name.decode("utf-8", errors="replace")
            for _, _, name, _ in id_attrs
        ))
        id_values = [
            val.decode("utf-8", errors="replace")
            for _, _, _, val in id_attrs
        ]

        # Count assertions in raw XML
        assertion_count = (
            raw.count(b"<saml:Assertion") + raw.count(b"<Assertion")
        )

        if assertion_count <= 1 and p_ac == r_ac:
            # No ambiguity in assertion count — check ref_match divergence
            if p_ref_match is not None and r_ref_match is not None:
                if p_ref_match != r_ref_match:
                    return XmlConstraint(
                        domain="reference",
                        predicate="ref_match_diverges",
                        library_pair=pair,
                        confidence=0.8,
                        parameters=XmlConstraint.make_params(
                            uri=ref_uri,
                            id_attrs=tuple(id_attr_names),
                            assertion_count=assertion_count,
                        ),
                        relevant_categories=_REFERENCE_STRATEGIES,
                    )
            return None

        # Multiple assertions or count divergence
        has_duplicate_ids = len(id_values) != len(set(id_values))

        if p_ac != r_ac:
            predicate = "assertion_count_diverges"
            confidence = 0.85
        elif has_duplicate_ids:
            predicate = "id_resolution_ambiguous"
            confidence = 0.8
        else:
            predicate = "id_resolution_ambiguous"
            confidence = 0.6

        return XmlConstraint(
            domain="reference",
            predicate=predicate,
            library_pair=pair,
            confidence=confidence,
            parameters=XmlConstraint.make_params(
                uri=ref_uri,
                id_attrs=tuple(id_attr_names),
                assertion_count=assertion_count,
                primary_count=p_ac,
                ref_count=r_ac,
                has_duplicate_ids=has_duplicate_ids,
            ),
            relevant_categories=_REFERENCE_STRATEGIES,
        )

    def _check_text_extraction(
        self,
        raw: bytes,
        p_data: dict, r_data: dict,
        p_subject: str, r_subject: str,
        pair: tuple[int, int],
    ) -> XmlConstraint | None:
        """Detect text extraction divergence (e.g., .text vs itertext)."""
        if not p_subject or not r_subject:
            return None

        # Determine extraction mechanism
        shorter, longer = sorted([p_subject, r_subject], key=len)

        # Check if shorter is a prefix of longer (truncation pattern)
        is_truncation = longer.startswith(shorter) and len(shorter) < len(longer)

        # Check for comment/PI artifacts
        has_comments = b"<!--" in raw
        has_pis = b"<?" in raw and b"<?xml" not in raw[:50]
        has_cdata = b"<![CDATA[" in raw
        # Detect actual child elements inside NameID (not comments/PIs/CDATA)
        has_child_in_nameid = bool(re.search(
            rb"<(?:saml:)?NameID[^>]*>[^<]*<(?!!|/|\?)",
            raw[:8000],
        ))

        if is_truncation and has_child_in_nameid:
            predicate = "child_element_truncation"
            confidence = 0.9
        elif is_truncation and has_comments:
            predicate = "comment_content_hidden"
            confidence = 0.8
        elif is_truncation and has_cdata:
            predicate = "cdata_extraction_diverges"
            confidence = 0.75
        elif is_truncation:
            predicate = "text_node_truncation"
            confidence = 0.7
        elif p_subject.lower() == r_subject.lower():
            predicate = "case_normalization"
            confidence = 0.5
        else:
            predicate = "extraction_divergence"
            confidence = 0.6

        return XmlConstraint(
            domain="extraction",
            predicate=predicate,
            library_pair=pair,
            confidence=confidence,
            parameters=XmlConstraint.make_params(
                primary_subject=p_subject,
                ref_subject=r_subject,
                has_child_in_nameid=has_child_in_nameid,
                has_comments=has_comments,
                has_pis=has_pis,
                has_cdata=has_cdata,
            ),
            relevant_categories=_EXTRACTION_STRATEGIES,
        )

    def _check_signature_scope(
        self,
        raw: bytes,
        p_data: dict, r_data: dict,
        p_valid: bool, r_valid: bool,
        pair: tuple[int, int],
    ) -> XmlConstraint | None:
        """Detect signature scope divergence (unsigned-but-parsed elements)."""
        # This fires when one library accepts and the other rejects,
        # and the accepting side extracted a subject/attribute that
        # appears to be outside the signed scope.
        acc_data = p_data if p_valid else r_data
        rej_data = r_data if p_valid else p_data

        acc_subject = (acc_data.get("subject") or "").strip()
        rej_error = (rej_data.get("signature_error") or "").lower()

        # Check for XPath transform exclusion in input
        has_xpath_transform = bool(re.search(
            rb"XPath|xpath|Filter|filter2",
            raw[:8000],
        ))

        # Check for elements outside signed scope
        has_multiple_assertions = (
            raw.count(b"<saml:Assertion") + raw.count(b"<Assertion") > 1
        )

        # Heuristic: if rejecting side mentions reference/scope/transform
        scope_related = bool(
            re.search(r"reference|scope|signed|digest", rej_error)
        )

        if not (has_xpath_transform or has_multiple_assertions or scope_related):
            return None

        if has_xpath_transform:
            predicate = "transform_scope_mismatch"
            confidence = 0.8
        elif has_multiple_assertions and acc_subject:
            predicate = "unsigned_element_parsed"
            confidence = 0.75
        elif scope_related:
            predicate = "digest_scope_diverges"
            confidence = 0.6
        else:
            predicate = "unsigned_element_parsed"
            confidence = 0.5

        return XmlConstraint(
            domain="scope",
            predicate=predicate,
            library_pair=pair,
            confidence=confidence,
            parameters=XmlConstraint.make_params(
                accepting_subject=acc_subject,
                has_xpath_transform=has_xpath_transform,
                has_multiple_assertions=has_multiple_assertions,
                rej_error_hint=rej_error[:200],
            ),
            relevant_categories=_SCOPE_STRATEGIES,
        )

    def _check_transform_chain(
        self,
        raw: bytes,
        p_error: str, r_error: str,
        pair: tuple[int, int],
    ) -> XmlConstraint | None:
        """Detect transform chain processing divergence."""
        errors = f"{p_error} {r_error}"

        if not _TRANSFORM_KEYWORDS.search(errors):
            return None

        # Avoid double-counting with c14n heuristic
        if _C14N_KEYWORDS.search(errors) and not re.search(
            r"enveloped|xslt|xpath\s*filter|transform.*order",
            errors, re.IGNORECASE,
        ):
            return None

        # Count transforms in input
        transform_count = raw.count(b"<ds:Transform") + raw.count(b"<Transform")
        has_enveloped = b"enveloped-signature" in raw
        has_xslt = b"xslt" in raw.lower()
        has_xpath_filter = b"xpath-filter" in raw.lower() or b"XPath" in raw

        if has_xslt:
            predicate = "xslt_transform_divergence"
            confidence = 0.8
        elif has_xpath_filter:
            predicate = "xpath_filter_divergence"
            confidence = 0.75
        elif has_enveloped and transform_count > 2:
            predicate = "transform_order_divergence"
            confidence = 0.7
        else:
            predicate = "enveloped_sig_handling"
            confidence = 0.6

        return XmlConstraint(
            domain="transform",
            predicate=predicate,
            library_pair=pair,
            confidence=confidence,
            parameters=XmlConstraint.make_params(
                transform_count=transform_count,
                has_enveloped=has_enveloped,
                has_xslt=has_xslt,
                has_xpath_filter=has_xpath_filter,
                error_hint=errors[:200],
            ),
            relevant_categories=_TRANSFORM_STRATEGIES,
        )

    # ── Utilities ────────────────────────────────────────────────

    @staticmethod
    def _cache_key(inp: Input, ref_idx: int) -> str:
        h = hashlib.sha256(inp.data[:4096]).hexdigest()[:16]
        return f"{h}:{ref_idx}"


class _ExtractorStats:
    """Lightweight counters for observability."""
    __slots__ = ("total_extractions", "total_constraints")

    def __init__(self) -> None:
        self.total_extractions = 0
        self.total_constraints = 0
