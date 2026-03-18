"""Domain-agnostic structural property extraction from raw XML bytes.

Measures ~48 structural properties using only byte-level operations
(regex and counting).  No XML parsing, no domain knowledge.
Cost: <0.2ms per call on inputs up to 50KB.

Property indices are stable — property 0 is always ``total_bytes``,
property 1 is always ``tag_count``, etc.  This is critical because
CorrelationTracker's contingency tables are indexed by property position.
"""

from __future__ import annotations

import math
import re
from typing import Sequence

from .property_vector import NUM_PROPERTIES, PropertyVector

# ── Compiled regexes (module-level for performance) ────────────────

_TAG_OPEN_RE = re.compile(rb"<(?!!|/|\?)[^>]+>")
_ATTR_RE = re.compile(rb"""\s(\w[\w.\-]*)=["']""")
_NS_DECL_RE = re.compile(rb'xmlns(?::(\w+))?="([^"]*)"')
_EMPTY_NS_RE = re.compile(rb'xmlns:\w+=""')
_RELATIVE_NS_RE = re.compile(
    rb'xmlns:\w+="('
    rb"[0-9]"  # single digit
    rb"|[.]"  # dot
    rb"|[a-z]/[a-z]"  # relative path
    rb"|#"  # fragment only
    rb"|//"  # protocol-relative
    rb"|[?]"  # query only
    rb"|%00"  # null
    rb"|data:,"  # data URI
    rb'|)"'  # empty string (captured via closing quote)
)
_DEFAULT_NS_RE = re.compile(rb'xmlns="[^"]*"')
_COMMENT_RE = re.compile(rb"<!--")
_PI_RE = re.compile(rb"<\?(?!xml\b)")  # exclude XML declaration
_CDATA_RE = re.compile(rb"<!\[CDATA\[")
_DOCTYPE_RE = re.compile(rb"<!DOCTYPE", re.IGNORECASE)
_SIGNATURE_RE = re.compile(rb"<(?:\w+:)?Signature[\s>]")
_REFERENCE_RE = re.compile(rb"<(?:\w+:)?Reference[\s>]")
_TRANSFORM_RE = re.compile(rb"<(?:\w+:)?Transform[\s>]")
_ENVELOPED_RE = re.compile(rb"enveloped-signature")
_XPATH_RE = re.compile(rb"xpath|filter2|XPath", re.IGNORECASE)
_XSLT_RE = re.compile(rb"xslt", re.IGNORECASE)
_PREFIXLIST_RE = re.compile(rb"PrefixList", re.IGNORECASE)
_ID_ATTR_RE = re.compile(rb'\b(ID|Id|xml:id|wsu:Id)="([^"]*)"')
_ASSERTION_LIKE_RE = re.compile(rb"<(?:\w+:)?Assertion[\s>]")
_BOM = b"\xef\xbb\xbf"
_ENCODING_DECL_RE = re.compile(rb'encoding=["\']([^"\']*)["\']')

# ── New regexes for 10-gap coverage ──────────────────────────────

# Parser level
_ENTITY_REF_RE = re.compile(rb"&(?!amp;|lt;|gt;|quot;|apos;)(\w+);")
_DTD_ENTITY_RE = re.compile(rb"<!ENTITY\s", re.IGNORECASE)
_XML_VERSION_RE = re.compile(rb'version=["\']([^"\']*)["\']')
_XML_DECL_RE = re.compile(rb"<\?xml\s")

# Time/conditions
_CONDITIONS_RE = re.compile(rb"<(?:\w+:)?Conditions[\s>]")
_NOTBEFORE_RE = re.compile(rb'NotBefore=', re.IGNORECASE)
_NOTONORAFTER_RE = re.compile(rb'NotOnOrAfter=', re.IGNORECASE)

# Audience
_AUDIENCE_RESTRICTION_RE = re.compile(rb"<(?:\w+:)?AudienceRestriction[\s>]")
_AUDIENCE_RE = re.compile(rb"<(?:\w+:)?Audience[\s>]")

# NameID
_NAMEID_FORMAT_RE = re.compile(rb'<(?:\w+:)?NameID[^>]*Format=["\']([^"\']*)["\']')

# Issuer
_ISSUER_RE = re.compile(rb"<(?:\w+:)?Issuer[\s>]")

# Key material
_KEYINFO_RE = re.compile(rb"<(?:\w+:)?KeyInfo[\s>]")
_X509CERT_RE = re.compile(rb"<(?:\w+:)?X509Certificate[\s>]")
_KEYVALUE_RE = re.compile(rb"<(?:\w+:)?KeyValue[\s>]")

# Duplicate attributes (same attr name twice on one tag)
_DUP_ATTR_RE = re.compile(rb"<[^>]+?\s(\w[\w.\-]*)=['\"][^'\"]*['\"][^>]*\s\1=['\"]")

# ── Property names (order matches extraction) ─────────────────────

PROPERTY_NAMES: tuple[str, ...] = (
    # Size (4)
    "total_bytes",  # 0
    "tag_count",  # 1
    "attr_count",  # 2
    "text_ratio",  # 3
    # Namespace (5)
    "ns_decl_count",  # 4
    "unique_ns_uri_count",  # 5
    "has_empty_ns",  # 6
    "has_relative_ns",  # 7
    "default_ns_present",  # 8
    # Structure (6)
    "depth_estimate",  # 9
    "assertion_count",  # 10
    "signature_count",  # 11
    "reference_count",  # 12
    "comment_count",  # 13
    "pi_count",  # 14
    # Signature (5)
    "transform_count",  # 15
    "has_enveloped",  # 16
    "has_xpath_transform",  # 17
    "has_xslt_transform",  # 18
    "prefix_list_present",  # 19
    # Content (5)
    "cdata_count",  # 20
    "doctype_present",  # 21
    "has_bom",  # 22
    "has_encoding_decl",  # 23
    "non_ascii_ratio",  # 24
    # ID (3)
    "id_attr_count",  # 25
    "duplicate_id_present",  # 26
    "mixed_id_case",  # 27
    # Entropy (2)
    "byte_entropy",  # 28
    "tag_name_diversity",  # 29
    # ── NEW: 10-gap coverage (18 properties) ─────────────────
    # Parser level (4)
    "entity_ref_count",  # 30 — custom entity references
    "has_dtd_entities",  # 31 — <!ENTITY declarations
    "xml_version_11",  # 32 — xml version="1.1"
    "has_xml_decl",  # 33 — <?xml present
    # Time/conditions (3)
    "has_conditions",  # 34 — <Conditions present
    "has_notbefore",  # 35 — NotBefore= attribute
    "has_notonorafter",  # 36 — NotOnOrAfter= attribute
    # Audience (2)
    "has_audience_restriction",  # 37
    "audience_count",  # 38
    # NameID (2)
    "has_nameid_format",  # 39 — Format= on NameID
    "nameid_format_count",  # 40 — distinct Format values
    # Issuer (2)
    "issuer_count",  # 41 — count of <Issuer> elements
    "issuer_nesting_diversity",  # 42 — issuers at different depths
    # Multi-signature (1)
    "sig_nesting_diversity",  # 43 — signatures at different depths
    # Key material (2)
    "has_keyinfo",  # 44
    "has_x509_cert",  # 45
    # Duplicate attributes (1)
    "has_duplicate_attrs",  # 46
    # Comment inside assertion (1)
    "comment_inside_assertion",  # 47
)

assert len(PROPERTY_NAMES) == NUM_PROPERTIES


class PropertyExtractor:
    """Extract structural properties from raw bytes.

    All properties are measured via regex/byte scanning over the first
    ``_MAX_SCAN`` bytes of input.  Each property is a float, typically
    normalized or naturally bounded.

    Thread-safe: no mutable state.
    """

    _MAX_SCAN = 8192  # 8KB scan window (balance accuracy vs speed)

    def extract(self, data: bytes) -> PropertyVector:
        """Extract all properties.  O(n) single pass over first 16KB."""
        buf = data[: self._MAX_SCAN]
        v = [0.0] * NUM_PROPERTIES

        # ── Size ──────────────────────────────────────────────
        v[0] = min(len(data) / 50000.0, 1.0)  # normalized, cap at 50KB
        tags = _TAG_OPEN_RE.findall(buf)
        v[1] = min(len(tags) / 200.0, 1.0)  # tag count, normalized
        attr_count = sum(len(_ATTR_RE.findall(t)) for t in tags)
        v[2] = min(attr_count / 200.0, 1.0)  # attr count, normalized
        non_tag_bytes = len(buf) - sum(len(t) for t in tags)
        v[3] = non_tag_bytes / max(len(buf), 1)  # text ratio

        # ── Namespace ─────────────────────────────────────────
        ns_decls = _NS_DECL_RE.findall(buf)
        v[4] = min(len(ns_decls) / 20.0, 1.0)  # ns declaration count
        unique_uris = {uri for _, uri in ns_decls}
        v[5] = min(len(unique_uris) / 10.0, 1.0)  # unique URI count
        v[6] = 1.0 if _EMPTY_NS_RE.search(buf) else 0.0
        v[7] = 1.0 if _RELATIVE_NS_RE.search(buf) else 0.0
        v[8] = 1.0 if _DEFAULT_NS_RE.search(buf) else 0.0

        # ── Precompute depth map (shared by depth, issuer, sig) ─
        depth_map = self._build_depth_map(buf)

        # ── Structure ─────────────────────────────────────────
        v[9] = min(depth_map[0] / 20.0, 1.0) if depth_map else 0.0
        v[10] = min(len(_ASSERTION_LIKE_RE.findall(buf)) / 5.0, 1.0)
        v[11] = min(len(_SIGNATURE_RE.findall(buf)) / 3.0, 1.0)
        v[12] = min(len(_REFERENCE_RE.findall(buf)) / 5.0, 1.0)
        v[13] = min(len(_COMMENT_RE.findall(buf)) / 10.0, 1.0)
        v[14] = min(len(_PI_RE.findall(buf)) / 5.0, 1.0)

        # ── Signature ────────────────────────────────────────
        v[15] = min(len(_TRANSFORM_RE.findall(buf)) / 10.0, 1.0)
        v[16] = 1.0 if _ENVELOPED_RE.search(buf) else 0.0
        v[17] = 1.0 if _XPATH_RE.search(buf) else 0.0
        v[18] = 1.0 if _XSLT_RE.search(buf) else 0.0
        v[19] = 1.0 if _PREFIXLIST_RE.search(buf) else 0.0

        # ── Content ──────────────────────────────────────────
        v[20] = min(len(_CDATA_RE.findall(buf)) / 5.0, 1.0)
        v[21] = 1.0 if _DOCTYPE_RE.search(buf) else 0.0
        v[22] = 1.0 if data[:3] == _BOM else 0.0
        v[23] = 1.0 if _ENCODING_DECL_RE.search(buf[:200]) else 0.0
        sample = buf[:4096]
        # C-speed: remove all non-ASCII bytes, count what was removed
        ascii_only = sample.translate(None, bytes(range(128, 256)))
        v[24] = (len(sample) - len(ascii_only)) / max(len(sample), 1) if sample else 0.0

        # ── ID ────────────────────────────────────────────────
        id_matches = _ID_ATTR_RE.findall(buf)
        v[25] = min(len(id_matches) / 10.0, 1.0)
        id_values = [val for _, val in id_matches]
        v[26] = 1.0 if len(id_values) != len(set(id_values)) else 0.0
        id_attr_names = {name for name, _ in id_matches}
        v[27] = 1.0 if len(id_attr_names) > 1 else 0.0

        # ── Entropy ──────────────────────────────────────────
        v[28] = self._byte_entropy(buf[:4096])
        v[29] = self._tag_name_diversity(tags)

        # ── Parser level ────────────────────────────────────
        v[30] = min(len(_ENTITY_REF_RE.findall(buf)) / 5.0, 1.0)
        v[31] = 1.0 if _DTD_ENTITY_RE.search(buf) else 0.0
        xml_ver = _XML_VERSION_RE.search(buf[:200])
        v[32] = 1.0 if xml_ver and b"1.1" in xml_ver.group(1) else 0.0
        v[33] = 1.0 if _XML_DECL_RE.search(buf[:100]) else 0.0

        # ── Time/conditions ─────────────────────────────────
        v[34] = 1.0 if _CONDITIONS_RE.search(buf) else 0.0
        v[35] = 1.0 if _NOTBEFORE_RE.search(buf) else 0.0
        v[36] = 1.0 if _NOTONORAFTER_RE.search(buf) else 0.0

        # ── Audience ────────────────────────────────────────
        v[37] = 1.0 if _AUDIENCE_RESTRICTION_RE.search(buf) else 0.0
        v[38] = min(len(_AUDIENCE_RE.findall(buf)) / 3.0, 1.0)

        # ── NameID ──────────────────────────────────────────
        nameid_formats = _NAMEID_FORMAT_RE.findall(buf)
        v[39] = 1.0 if nameid_formats else 0.0
        v[40] = min(len(set(nameid_formats)) / 3.0, 1.0)

        # ── Issuer ──────────────────────────────────────────
        issuer_matches = list(_ISSUER_RE.finditer(buf))
        v[41] = min(len(issuer_matches) / 3.0, 1.0)
        if issuer_matches and len(depth_map) > 1:
            issuer_depths = {self._depth_lookup(depth_map, m.start()) for m in issuer_matches}
            v[42] = min(len(issuer_depths) / 2.0, 1.0)

        # ── Multi-signature ─────────────────────────────────
        sig_matches = list(_SIGNATURE_RE.finditer(buf))
        if sig_matches and len(depth_map) > 1:
            sig_depths = {self._depth_lookup(depth_map, m.start()) for m in sig_matches}
            v[43] = min(len(sig_depths) / 2.0, 1.0)

        # ── Key material ────────────────────────────────────
        v[44] = 1.0 if _KEYINFO_RE.search(buf) else 0.0
        v[45] = 1.0 if _X509CERT_RE.search(buf) else 0.0

        # ── Duplicate attributes ────────────────────────────
        v[46] = 1.0 if _DUP_ATTR_RE.search(buf[:8192]) else 0.0

        # ── Comment inside assertion ────────────────────────
        assertion_m = _ASSERTION_LIKE_RE.search(buf)
        if assertion_m:
            assertion_region = buf[assertion_m.start():]
            v[47] = 1.0 if _COMMENT_RE.search(assertion_region) else 0.0

        return PropertyVector(tuple(v))

    @property
    def property_names(self) -> tuple[str, ...]:
        return PROPERTY_NAMES

    # ── Helpers ──────────────────────────────────────────────

    @staticmethod
    def _build_depth_map(buf: bytes) -> list[int]:
        """Build sparse depth map: list of (position, depth) at each '<'.

        Returns list where [0] = max_depth, then alternating
        (lt_position, depth_at_that_position) pairs packed flat:
        [max_depth, pos0, depth0, pos1, depth1, ...]
        """
        n = len(buf)
        if n == 0:
            return [0]
        depth = 0
        max_depth = 0
        result = [0]  # placeholder for max_depth
        pos = 0
        try:
            while True:
                pos = buf.index(b"<", pos)
                if pos + 1 < n:
                    nxt = buf[pos + 1:pos + 2]
                    if nxt == b"/":
                        depth = max(depth - 1, 0)
                    elif nxt not in (b"!", b"?"):
                        depth += 1
                        if depth > max_depth:
                            max_depth = depth
                result.append(pos)
                result.append(depth)
                pos += 1
        except ValueError:
            pass
        result[0] = max_depth
        return result

    @staticmethod
    def _depth_lookup(depth_map: list[int], target_pos: int) -> int:
        """O(log n) depth lookup via binary search on sparse map."""
        if len(depth_map) < 3:
            return 0
        # Entries are at indices 1,3,5,... (positions) and 2,4,6,... (depths)
        lo, hi = 0, (len(depth_map) - 1) // 2 - 1
        depth = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            entry_pos = depth_map[1 + mid * 2]
            if entry_pos <= target_pos:
                depth = depth_map[2 + mid * 2]
                lo = mid + 1
            else:
                hi = mid - 1
        return depth

    @staticmethod
    def _byte_entropy(buf: bytes) -> float:
        """Shannon entropy of byte distribution, normalized to [0, 1]."""
        if not buf:
            return 0.0
        # Use collections.Counter for C-speed counting
        from collections import Counter
        counts = Counter(buf)
        n = len(buf)
        entropy = 0.0
        log2 = math.log2
        for f in counts.values():
            p = f / n
            entropy -= p * log2(p)
        return entropy / 8.0  # max entropy is 8 bits

    @staticmethod
    def _tag_name_diversity(tags: Sequence[bytes]) -> float:
        """Fraction of unique tag names over total tags."""
        if not tags:
            return 0.0
        names: set[bytes] = set()
        tag_name_re = re.compile(rb"<(\w[\w:.\-]*)")
        for t in tags:
            m = tag_name_re.match(t)
            if m:
                names.add(m.group(1))
        return len(names) / len(tags)
