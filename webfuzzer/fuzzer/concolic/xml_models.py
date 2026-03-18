"""Symbolic XML models for SAML concolic execution.

Four lightweight pure-Python models that predict XML processing behavior
without executing targets.  All use regex-based parsing (same approach as
SamlMutator) for speed and robustness against malformed XML.

Models:
  1. C14NNamespaceModel   — namespace scope prediction, mutation generation
  2. ReferenceResolutionModel — Reference URI / ID attribute resolution
  3. TextExtractionModel   — .text vs itertext vs textContent prediction
  4. SignatureScopeModel   — signed vs unsigned element classification
"""

from __future__ import annotations

import re
import random
from dataclasses import dataclass, field
from typing import Any


# ── Shared regex patterns ────────────────────────────────────────

# Namespace declarations: xmlns:prefix="uri" or xmlns="uri"
_NS_DECL_RE = re.compile(rb'xmlns(?::(\w+))?="([^"]*)"')

# Opening tags (capturing prefix:localname or just localname)
_TAG_OPEN_RE = re.compile(rb'<((?:\w+:)?\w+)(\s[^>]*)?\s*/?>')

# ID-like attributes with values
_ID_ATTR_RE = re.compile(
    rb'<((?:\w+:)?\w+)\b([^>]*?)\b(ID|Id|xml:id|wsu:Id)="([^"]*)"'
)

# Reference URI in ds:Reference
_REF_URI_RE = re.compile(rb'<(?:ds:)?Reference[^>]*URI="([^"]*)"')

# Signature elements
_SIG_OPEN_RE = re.compile(rb'<(?:ds:)?Signature[\s>]')
_SIG_CLOSE_RE = re.compile(rb'</(?:ds:)?Signature\s*>')

# Transform elements
_TRANSFORM_RE = re.compile(rb'<(?:ds:)?Transform[^>]*Algorithm="([^"]*)"')

# Assertion elements
_ASSERTION_RE = re.compile(
    rb'<((?:\w+:)?Assertion)\b([^>]*?)>'
)

# NameID element content
_NAMEID_RE = re.compile(
    rb'<(?:saml:)?NameID[^>]*>(.*?)</(?:saml:)?NameID\s*>',
    re.DOTALL,
)

# CanonicalizationMethod algorithm
_C14N_METHOD_RE = re.compile(
    rb'<(?:ds:)?CanonicalizationMethod[^>]*Algorithm="([^"]*)"'
)

# InclusiveNamespaces PrefixList
_PREFIX_LIST_RE = re.compile(
    rb'<(?:ec:)?InclusiveNamespaces[^>]*PrefixList="([^"]*)"'
)


# ── Data structures ──────────────────────────────────────────────

@dataclass(frozen=True, slots=True)
class ElementInfo:
    """Lightweight element descriptor from regex parsing."""
    tag: str           # e.g. "saml:Assertion"
    id_value: str      # ID attribute value, empty if none
    id_attr: str       # which attribute name (ID, Id, xml:id, wsu:Id)
    offset: int        # byte offset in raw XML


@dataclass(slots=True)
class NsMutation:
    """A proposed namespace mutation."""
    kind: str          # "add" | "remove" | "redeclare" | "undeclare" | "reorder" | "void"
    prefix: str        # namespace prefix (empty for default ns)
    uri: str           # namespace URI (new value for add/redeclare)
    target_element: str  # where to apply (e.g. "saml:Assertion")
    description: str   # human-readable description


# ── Model 1: C14N Namespace Model ────────────────────────────────

class C14NNamespaceModel:
    """Predicts which namespaces are in-scope at each element under exc-c14n.

    Does NOT do full c14n — just tracks namespace declarations to predict
    whether adding/removing/reordering namespace declarations changes
    canonical output.
    """

    def namespaces_in_scope(
        self, xml_bytes: bytes, element_tag: str | None = None,
    ) -> dict[str, str]:
        """Return {prefix: uri} map of all namespace declarations.

        If element_tag is given, returns only namespaces declared on or
        above that element (approximation — regex-based, not DOM).
        """
        decls: dict[str, str] = {}
        search_region = xml_bytes[:16384]

        if element_tag:
            # Find the element and only consider declarations before it
            tag_match = re.search(
                rb'<' + element_tag.encode() + rb'[\s>]',
                search_region,
            )
            if tag_match:
                search_region = search_region[:tag_match.end() + 500]

        for match in _NS_DECL_RE.finditer(search_region):
            prefix = match.group(1)
            uri = match.group(2)
            key = prefix.decode("utf-8", errors="replace") if prefix else ""
            decls[key] = uri.decode("utf-8", errors="replace")

        return decls

    def get_c14n_algorithm(self, xml_bytes: bytes) -> str:
        """Extract the CanonicalizationMethod algorithm URI."""
        m = _C14N_METHOD_RE.search(xml_bytes[:8000])
        return m.group(1).decode("utf-8", errors="replace") if m else ""

    def get_prefix_list(self, xml_bytes: bytes) -> list[str]:
        """Extract InclusiveNamespaces PrefixList tokens."""
        m = _PREFIX_LIST_RE.search(xml_bytes[:8000])
        if not m:
            return []
        return m.group(1).decode("utf-8", errors="replace").split()

    def predict_c14n_difference(
        self, xml_bytes: bytes, mutation: NsMutation,
    ) -> float:
        """Return probability [0,1] that mutation changes canonical output.

        Higher = more likely to create divergence between exc-c14n
        implementations.
        """
        algo = self.get_c14n_algorithm(xml_bytes)
        is_exclusive = "exclusive" in algo.lower() or "exc" in algo.lower()
        prefix_list = self.get_prefix_list(xml_bytes)
        ns_map = self.namespaces_in_scope(xml_bytes)

        score = 0.0

        if mutation.kind == "void":
            # Void c14n (relative NS) — high impact on most implementations
            score = 0.9

        elif mutation.kind == "undeclare":
            # xmlns:prefix="" — behavior varies across c14n implementations
            score = 0.7 if is_exclusive else 0.5

        elif mutation.kind == "add":
            if is_exclusive:
                # In exc-c14n, unused NS declarations are not rendered
                # unless in PrefixList — adding one that IS in PrefixList
                # creates divergence
                if mutation.prefix in prefix_list:
                    score = 0.8
                else:
                    score = 0.3  # Unused, probably stripped
            else:
                # In inclusive c14n, all in-scope NS are rendered
                score = 0.6

        elif mutation.kind == "redeclare":
            # Changing a used NS URI always changes c14n output
            if mutation.prefix in ns_map:
                score = 0.85
            else:
                score = 0.4

        elif mutation.kind == "remove":
            if mutation.prefix in ns_map:
                score = 0.7
            else:
                score = 0.1

        elif mutation.kind == "reorder":
            # exc-c14n sorts by prefix; reordering shouldn't matter
            # BUT some implementations don't sort correctly
            score = 0.3 if is_exclusive else 0.5

        return min(score, 1.0)

    def generate_ns_mutations(
        self, xml_bytes: bytes, rng: random.Random | None = None,
    ) -> list[NsMutation]:
        """Generate namespace mutations that explore c14n divergence."""
        ns_map = self.namespaces_in_scope(xml_bytes)
        prefix_list = self.get_prefix_list(xml_bytes)
        mutations: list[NsMutation] = []

        # 1. Void c14n: add relative namespace URI
        for prefix_val in ("x", "evil", "void"):
            if prefix_val not in ns_map:
                mutations.append(NsMutation(
                    kind="void", prefix=prefix_val,
                    uri="1",  # numeric = relative URI
                    target_element="samlp:Response",
                    description=f'Add void xmlns:{prefix_val}="1"',
                ))
                break

        # 2. Undeclare existing prefixes
        for prefix in list(ns_map.keys())[:3]:
            if prefix:  # can't undeclare default ns in XML 1.0
                mutations.append(NsMutation(
                    kind="undeclare", prefix=prefix, uri="",
                    target_element="saml:Assertion",
                    description=f'Undeclare xmlns:{prefix}=""',
                ))

        # 3. Add unused namespace that's in PrefixList
        for pl_prefix in prefix_list:
            if pl_prefix not in ns_map:
                mutations.append(NsMutation(
                    kind="add", prefix=pl_prefix,
                    uri=f"urn:test:{pl_prefix}",
                    target_element="saml:Assertion",
                    description=f'Add unused NS in PrefixList: xmlns:{pl_prefix}',
                ))

        # 4. Redeclare SAML namespace with variant URI
        saml_variants = [
            ("saml", "urn:oasis:names:tc:SAML:2.0:assertion"),
            ("saml", "urn:oasis:names:tc:SAML:1.0:assertion"),
            ("samlp", "urn:oasis:names:tc:SAML:2.0:protocol"),
        ]
        for prefix, uri in saml_variants:
            if prefix in ns_map and ns_map[prefix] != uri:
                continue
            mutations.append(NsMutation(
                kind="redeclare", prefix=prefix, uri=uri,
                target_element="saml:Assertion",
                description=f'Redeclare {prefix} on Assertion',
            ))

        # 5. Add default namespace (xmlns="...")
        if "" not in ns_map:
            mutations.append(NsMutation(
                kind="add", prefix="", uri="urn:test:default",
                target_element="saml:Assertion",
                description='Add default namespace on Assertion',
            ))

        # 6. Reorder: swap first two NS declarations
        if len(ns_map) >= 2:
            prefixes = list(ns_map.keys())
            mutations.append(NsMutation(
                kind="reorder", prefix=prefixes[0], uri="",
                target_element="samlp:Response",
                description=f'Reorder NS: move {prefixes[0]} after {prefixes[1]}',
            ))

        return mutations


# ── Model 2: Reference Resolution Model ─────────────────────────

class ReferenceResolutionModel:
    """Predicts which element(s) a ds:Reference URI resolves to."""

    def resolve_reference(
        self, xml_bytes: bytes, uri: str | None = None,
    ) -> list[ElementInfo]:
        """Return elements matching the Reference URI.

        Multiple results = ambiguity (potential XSW target).
        If uri is None, extracts from the XML itself.
        """
        if uri is None:
            m = _REF_URI_RE.search(xml_bytes[:8000])
            uri = m.group(1).decode("utf-8", errors="replace") if m else ""

        if not uri or not uri.startswith("#"):
            # Empty/bare URI — implementations vary on what this resolves to
            return self._find_all_assertions(xml_bytes)

        target_id = uri[1:]  # strip #

        results: list[ElementInfo] = []
        for match in _ID_ATTR_RE.finditer(xml_bytes):
            tag = match.group(1).decode("utf-8", errors="replace")
            id_attr = match.group(3).decode("utf-8", errors="replace")
            id_val = match.group(4).decode("utf-8", errors="replace")
            if id_val == target_id:
                results.append(ElementInfo(
                    tag=tag, id_value=id_val,
                    id_attr=id_attr, offset=match.start(),
                ))

        return results

    def find_id_attributes(
        self, xml_bytes: bytes,
    ) -> dict[str, list[str]]:
        """Map element_tag -> [attr_name] for all ID-like attributes."""
        result: dict[str, list[str]] = {}
        for match in _ID_ATTR_RE.finditer(xml_bytes):
            tag = match.group(1).decode("utf-8", errors="replace")
            attr = match.group(3).decode("utf-8", errors="replace")
            result.setdefault(tag, []).append(attr)
        return result

    def predict_xsw_effectiveness(
        self, xml_bytes: bytes, xsw_variant: str,
    ) -> float:
        """Predict likelihood that this XSW variant creates reference ambiguity."""
        assertions = self._find_all_assertions(xml_bytes)
        ref_targets = self.resolve_reference(xml_bytes)

        # Already multiple assertions = higher chance of XSW success
        base = 0.3 if len(assertions) > 1 else 0.5

        # Check for duplicate IDs
        ids = [e.id_value for e in assertions if e.id_value]
        has_dup = len(ids) != len(set(ids))
        if has_dup:
            base += 0.2

        # XSW variants that insert before signed assertion are more effective
        # when the library uses first-match resolution
        if xsw_variant in ("xsw1_pre_assertion_clone", "xsw_first_assertion_extract"):
            base += 0.15

        # Empty Reference URI = library-dependent resolution
        m = _REF_URI_RE.search(xml_bytes[:8000])
        if not m or not m.group(1):
            base += 0.2

        return min(base, 1.0)

    def _find_all_assertions(self, xml_bytes: bytes) -> list[ElementInfo]:
        """Find all Assertion elements in the XML."""
        results: list[ElementInfo] = []
        for match in _ASSERTION_RE.finditer(xml_bytes):
            tag = match.group(1).decode("utf-8", errors="replace")
            attrs = match.group(2) or b""
            id_match = re.search(rb'\bID="([^"]*)"', attrs)
            id_val = id_match.group(1).decode("utf-8", errors="replace") if id_match else ""
            results.append(ElementInfo(
                tag=tag, id_value=id_val,
                id_attr="ID" if id_val else "",
                offset=match.start(),
            ))
        return results


# ── Model 3: Text Extraction Model ──────────────────────────────

class TextExtractionModel:
    """Predicts how different text extraction APIs handle mixed content.

    Known library extraction profiles:
      - "text_only":   lxml .text property — stops at first child element
      - "itertext":    lxml itertext() — all text nodes in subtree
      - "textContent": DOM textContent — all text including descendants
    """

    # Library → extraction behavior
    EXTRACTION_PROFILES: dict[str, str] = {
        "python3-saml": "text_only",
        "signxml": "itertext",
        "xmlcrypto": "textContent",
        "samlify": "textContent",
        "node-saml": "textContent",
        "crewjam": "textContent",
        "rubysaml": "textContent",
        "phpsaml": "textContent",
    }

    def predict_extracted_text(
        self, xml_bytes: bytes, element_tag: str, profile: str,
    ) -> str:
        """Predict what text a given extraction profile would return.

        This is an approximation — regex-based, not full DOM.
        """
        # Find element content
        pattern = re.compile(
            rb'<(?:\w+:)?' + element_tag.encode() + rb'[^>]*>(.*?)'
            rb'</(?:\w+:)?' + element_tag.encode() + rb'\s*>',
            re.DOTALL,
        )
        m = pattern.search(xml_bytes[:8000])
        if not m:
            return ""

        content = m.group(1)

        if profile == "text_only":
            # .text: returns text before first child element
            # Strip comments and PIs first
            content = re.sub(rb'<!--.*?-->', b'', content, flags=re.DOTALL)
            content = re.sub(rb'<\?.*?\?>', b'', content, flags=re.DOTALL)
            # Text before first child element
            child_match = re.search(rb'<(?!!|\?)', content)
            if child_match:
                content = content[:child_match.start()]
            return content.decode("utf-8", errors="replace").strip()

        elif profile == "itertext":
            # itertext: all text nodes including after child elements
            # Strip tags but keep text content
            text = re.sub(rb'<!--.*?-->', b'', content, flags=re.DOTALL)
            text = re.sub(rb'<\?.*?\?>', b'', text, flags=re.DOTALL)
            text = re.sub(rb'<!\[CDATA\[(.*?)\]\]>', rb'\1', text, flags=re.DOTALL)
            text = re.sub(rb'<[^>]+>', b'', text)
            return text.decode("utf-8", errors="replace").strip()

        elif profile == "textContent":
            # textContent: like itertext but also includes comment/PI text
            # in some implementations. Standard DOM: excludes comments.
            text = re.sub(rb'<!--.*?-->', b'', content, flags=re.DOTALL)
            text = re.sub(rb'<\?.*?\?>', b'', text, flags=re.DOTALL)
            text = re.sub(rb'<!\[CDATA\[(.*?)\]\]>', rb'\1', text, flags=re.DOTALL)
            text = re.sub(rb'<[^>]+>', b'', text)
            return text.decode("utf-8", errors="replace").strip()

        return ""

    def generate_confusion_payloads(
        self, target_text: str, rng: random.Random | None = None,
    ) -> list[bytes]:
        """Generate NameID content that produces different text across profiles.

        Returns list of NameID inner content (not the full element).
        """
        if not target_text:
            target_text = "admin@evil.com"

        # Split target into prefix + suffix for injection point
        if "@" in target_text:
            prefix, suffix = target_text.split("@", 1)
            suffix = "@" + suffix
        elif len(target_text) > 3:
            mid = len(target_text) // 2
            prefix = target_text[:mid]
            suffix = target_text[mid:]
        else:
            prefix = target_text
            suffix = ""

        payloads: list[bytes] = []

        # 1. Child element injection (truncation in text_only)
        payloads.append(
            f"{prefix}<t/>{suffix}".encode()
        )

        # 2. Comment injection (hidden in some profiles)
        payloads.append(
            f"{prefix}<!--HIDDEN-->{suffix}".encode()
        )

        # 3. CDATA section
        payloads.append(
            f"{prefix}<![CDATA[{suffix}]]>".encode()
        )

        # 4. Processing instruction
        payloads.append(
            f"{prefix}<?pi data?>{suffix}".encode()
        )

        # 5. Nested element with text
        payloads.append(
            f"{prefix}<evil>{suffix}</evil>".encode()
        )

        # 6. Multiple child elements
        payloads.append(
            f"<a>{prefix}</a><b>{suffix}</b>".encode()
        )

        # 7. Empty child element splitting text
        payloads.append(
            f"{prefix}<x:t xmlns:x='urn:evil'/>{suffix}".encode()
        )

        # 8. Comment before any text (empty .text)
        payloads.append(
            f"<!--start-->{target_text}".encode()
        )

        return payloads

    def profiles_that_diverge(
        self, xml_bytes: bytes, element_tag: str = "NameID",
    ) -> list[tuple[str, str, str, str]]:
        """Return pairs of (lib_a, text_a, lib_b, text_b) that would diverge."""
        divergences = []
        results: dict[str, str] = {}
        for lib, profile in self.EXTRACTION_PROFILES.items():
            text = self.predict_extracted_text(xml_bytes, element_tag, profile)
            results[lib] = text

        libs = list(results.keys())
        for i, lib_a in enumerate(libs):
            for lib_b in libs[i + 1:]:
                if results[lib_a] != results[lib_b]:
                    divergences.append((
                        lib_a, results[lib_a],
                        lib_b, results[lib_b],
                    ))

        return divergences


# ── Model 4: Signature Scope Model ──────────────────────────────

class SignatureScopeModel:
    """Predicts which elements fall within/outside the signed digest scope."""

    def signed_elements(self, xml_bytes: bytes) -> list[ElementInfo]:
        """Return elements within the digest computation scope.

        Identifies which elements are referenced by ds:Reference URIs
        and thus covered by the signature.
        """
        ref_model = ReferenceResolutionModel()
        return ref_model.resolve_reference(xml_bytes)

    def unsigned_parsed_elements(
        self, xml_bytes: bytes,
    ) -> list[ElementInfo]:
        """Return elements that are parsed for security decisions but not signed.

        These are the attack surface: content that libraries extract
        and use for authentication decisions, but that falls outside
        the signature scope.
        """
        signed = set()
        for elem in self.signed_elements(xml_bytes):
            signed.add(elem.id_value)

        # Find all assertions and check which are NOT signed
        unsigned: list[ElementInfo] = []
        for match in _ASSERTION_RE.finditer(xml_bytes):
            tag = match.group(1).decode("utf-8", errors="replace")
            attrs = match.group(2) or b""
            id_match = re.search(rb'\bID="([^"]*)"', attrs)
            id_val = id_match.group(1).decode("utf-8", errors="replace") if id_match else ""
            if id_val and id_val not in signed:
                unsigned.append(ElementInfo(
                    tag=tag, id_value=id_val,
                    id_attr="ID", offset=match.start(),
                ))
            elif not id_val:
                # No ID = can't be referenced by URI = unsigned
                unsigned.append(ElementInfo(
                    tag=tag, id_value="",
                    id_attr="", offset=match.start(),
                ))

        return unsigned

    def get_transforms(self, xml_bytes: bytes) -> list[str]:
        """Extract transform algorithm URIs from the signature."""
        return [
            m.group(1).decode("utf-8", errors="replace")
            for m in _TRANSFORM_RE.finditer(xml_bytes[:8000])
        ]

    def has_enveloped_transform(self, xml_bytes: bytes) -> bool:
        """Check if enveloped-signature transform is present."""
        return b"enveloped-signature" in xml_bytes[:8000]

    def predict_transform_effect(
        self, xml_bytes: bytes, new_transform_uri: str,
    ) -> dict[str, str]:
        """Predict impact of adding/modifying a transform.

        Returns dict mapping element_id -> "in_scope" | "out_of_scope" | "uncertain"
        """
        existing = self.get_transforms(xml_bytes)
        result: dict[str, str] = {}

        for elem in self.signed_elements(xml_bytes):
            eid = elem.id_value or f"offset_{elem.offset}"
            uri_lower = new_transform_uri.lower()
            if "xpath" in uri_lower or "filter" in uri_lower:
                result[eid] = "uncertain"  # XPath/Filter can include/exclude anything
            elif "xslt" in uri_lower:
                result[eid] = "uncertain"  # XSLT can transform arbitrarily
            else:
                result[eid] = "in_scope"  # Most transforms preserve scope

        # Elements not currently signed stay out of scope
        for elem in self.unsigned_parsed_elements(xml_bytes):
            eid = elem.id_value or f"offset_{elem.offset}"
            result[eid] = "out_of_scope"

        return result

    def find_signature_boundaries(
        self, xml_bytes: bytes,
    ) -> list[tuple[int, int]]:
        """Return (start, end) byte offsets of all Signature elements."""
        boundaries: list[tuple[int, int]] = []
        for open_match in _SIG_OPEN_RE.finditer(xml_bytes):
            # Find matching close
            close_match = _SIG_CLOSE_RE.search(xml_bytes, open_match.end())
            if close_match:
                boundaries.append((open_match.start(), close_match.end()))
        return boundaries
