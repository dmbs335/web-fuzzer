#!/usr/bin/env python3
"""Generate round-trip seed variants for SAML differential fuzzing.

Round-trip = parse → re-serialize divergence.  When XML goes through
parse/serialize/parse, implementation differences can alter the canonical
form, breaking or faking signature verification.

Seed categories:
1. Namespace undeclaration (xmlns:x="") — forbidden in XML 1.0, allowed in 1.1
2. Namespace prefix rebinding (same prefix, different URI on child)
3. Default namespace override on assertion sub-elements
4. Attribute value entity encoding variants (&amp; vs &#38; vs &#x26;)
5. CDATA in NameID and attribute values
6. Whitespace in attribute values and between elements
7. XML declaration variants (encoding, standalone)
8. Empty elements self-closing vs explicit close tag
9. Comment/PI between signed elements
10. Numeric character references in element names (edge case)
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from lxml import etree
from signxml import XMLSigner
from signxml.algorithms import SignatureConstructionMethod, CanonicalizationMethod

KEY_PATH = Path("targets/saml_fixtures/idp_key.pem")
CERT_PATH = Path("targets/saml_fixtures/idp_cert.pem")
OUT_DIR = Path("targets/saml_seeds_round_trip")

NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def make_base_response(assert_id="_assert_rt"):
    """Build a minimal valid SAML response with assertion."""
    resp = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        nsmap={"samlp": NSMAP["samlp"], "saml": NSMAP["saml"]},
    )
    resp.set("ID", "_resp_rt")
    resp.set("Version", "2.0")
    resp.set("IssueInstant", "2026-03-14T10:00:00Z")
    resp.set("Destination", "https://sp.example.com/acs")

    issuer = etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer.text = "https://idp.example.com"

    status = etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
    sc = etree.SubElement(status, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
    sc.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    assertion = etree.SubElement(
        resp, "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
    )
    assertion.set("Version", "2.0")
    assertion.set("ID", assert_id)
    assertion.set("IssueInstant", "2026-03-14T10:00:00Z")

    a_issuer = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
    )
    a_issuer.text = "https://idp.example.com"

    subject = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject"
    )
    nameid = etree.SubElement(
        subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID"
    )
    nameid.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    nameid.text = "user@example.com"

    subj_conf = etree.SubElement(
        subject, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation"
    )
    subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    scd = etree.SubElement(
        subj_conf,
        "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData",
    )
    scd.set("NotOnOrAfter", "2026-03-14T11:00:00Z")
    scd.set("Recipient", "https://sp.example.com/acs")

    conditions = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions"
    )
    conditions.set("NotBefore", "2026-03-14T10:00:00Z")
    conditions.set("NotOnOrAfter", "2026-03-14T11:00:00Z")
    ar = etree.SubElement(
        conditions,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction",
    )
    aud = etree.SubElement(
        ar, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
    )
    aud.text = "https://sp.example.com"

    authn = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement"
    )
    authn.set("AuthnInstant", "2026-03-14T10:00:00Z")
    authn.set("SessionIndex", "_session_rt")
    ac = etree.SubElement(
        authn, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext"
    )
    accr = etree.SubElement(
        ac,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef",
    )
    accr.text = (
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    )

    attr_stmt = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
    )
    attr = etree.SubElement(
        attr_stmt, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
    )
    attr.set("Name", "role")
    attr.set(
        "NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
    )
    av = etree.SubElement(
        attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
    )
    av.text = "user"

    return resp, assertion


def sign_assertion(resp, assertion):
    """Sign the assertion with the test IdP key."""
    key = KEY_PATH.read_bytes()
    cert = CERT_PATH.read_bytes()
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    signed = signer.sign(
        assertion,
        key=key,
        cert=cert,
        reference_uri=f"#{assertion.get('ID')}",
    )
    return etree.tostring(resp, xml_declaration=True, encoding="UTF-8")


def sign_and_serialize(resp, assertion):
    """Sign assertion and return serialized XML bytes."""
    key = KEY_PATH.read_bytes()
    cert = CERT_PATH.read_bytes()
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    signer.sign(
        assertion,
        key=key,
        cert=cert,
        reference_uri=f"#{assertion.get('ID')}",
    )
    return etree.tostring(resp, xml_declaration=True, encoding="UTF-8")


def write_seed(name, xml_bytes):
    """Write seed file."""
    path = OUT_DIR / f"{name}.xml"
    path.write_bytes(xml_bytes)
    print(f"  {name}.xml ({len(xml_bytes)} bytes)")


def post_sign_inject(xml_bytes, old, new):
    """Replace bytes in serialized XML after signing (corrupts digest intentionally)."""
    return xml_bytes.replace(old, new, 1)


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

def gen_ns_undeclaration():
    """Category 1: xmlns:x="" namespace undeclaration on child elements."""
    seeds = []

    # 1a: undeclare saml prefix on Subject
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<saml:Subject xmlns:saml="">',
    )
    seeds.append(("01_ns_undecl_subject", xml))

    # 1b: undeclare saml on NameID
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:NameID",
        b'<saml:NameID xmlns:saml=""',
    )
    seeds.append(("02_ns_undecl_nameid", xml))

    # 1c: undeclare then redeclare
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<saml:Subject xmlns:saml="" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">',
    )
    seeds.append(("03_ns_undecl_redecl", xml))

    return seeds


def gen_prefix_rebinding():
    """Category 2: rebind prefix to different URI on child."""
    seeds = []

    # 2a: rebind saml to SAML 1.1 namespace on Subject
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">',
    )
    seeds.append(("04_prefix_rebind_saml11", xml))

    # 2b: rebind saml to custom URI
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<saml:Subject xmlns:saml="urn:custom:saml:fake">',
    )
    seeds.append(("05_prefix_rebind_custom", xml))

    # 2c: rebind ds prefix on Signature child
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<ds:SignedInfo>",
        b'<ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig-fake#">',
    )
    seeds.append(("06_prefix_rebind_ds", xml))

    return seeds


def gen_default_ns_override():
    """Category 3: default namespace override on assertion elements."""
    seeds = []

    # 3a: set default NS on assertion to SAML assertion NS
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Assertion",
        b'<saml:Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"',
    )
    seeds.append(("07_default_ns_saml", xml))

    # 3b: set default NS on NameID to empty
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:NameID",
        b'<saml:NameID xmlns=""',
    )
    seeds.append(("08_default_ns_empty_nameid", xml))

    # 3c: set default NS to xhtml on Subject
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<saml:Subject xmlns="http://www.w3.org/1999/xhtml">',
    )
    seeds.append(("09_default_ns_xhtml", xml))

    return seeds


def gen_entity_encoding():
    """Category 4: entity encoding variants in attribute values and text."""
    seeds = []

    # 4a: entity-encode @ in NameID
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(xml, b"user@example.com", b"user&#64;example.com")
    seeds.append(("10_entity_at_decimal", xml))

    # 4b: hex entity
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(xml, b"user@example.com", b"user&#x40;example.com")
    seeds.append(("11_entity_at_hex", xml))

    # 4c: entity-encode dot
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(xml, b"user@example.com", b"user@example&#46;com")
    seeds.append(("12_entity_dot_decimal", xml))

    # 4d: double-encode ampersand in NameID (inject raw &)
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b"user@example.com", b"user&amp;admin@example.com"
    )
    seeds.append(("13_entity_amp_nameid", xml))

    # 4e: overlong UTF-8 representation (2-byte encoding of ASCII)
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    # Replace 'u' (0x75) with overlong 2-byte: 0xC1 0xB5
    xml = post_sign_inject(xml, b"user@example.com", b"\xc1\xb5ser@example.com")
    seeds.append(("14_overlong_utf8", xml))

    return seeds


def gen_cdata():
    """Category 5: CDATA sections in text content."""
    seeds = []

    # 5a: CDATA wrapping NameID value
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b">user@example.com</", b"><![CDATA[user@example.com]]></"
    )
    seeds.append(("15_cdata_nameid", xml))

    # 5b: split CDATA
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b">user@example.com</",
        b"><![CDATA[user]]>@<![CDATA[example.com]]></",
    )
    seeds.append(("16_cdata_split_nameid", xml))

    # 5c: CDATA in attribute value (role)
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b">user</saml:AttributeValue>",
        b"><![CDATA[admin]]></saml:AttributeValue>",
    )
    seeds.append(("17_cdata_role", xml))

    # 5d: mixed text + CDATA
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b">user@example.com</",
        b">user<![CDATA[@admin]]>.example.com</",
    )
    seeds.append(("18_cdata_mixed", xml))

    return seeds


def gen_whitespace():
    """Category 6: whitespace variants."""
    seeds = []

    # 6a: tab in NameID
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(xml, b"user@example.com", b"user@example.com\t")
    seeds.append(("19_ws_trailing_tab", xml))

    # 6b: newline in NameID
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(xml, b"user@example.com", b"user@example.com\n")
    seeds.append(("20_ws_trailing_newline", xml))

    # 6c: leading whitespace in NameID
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(xml, b">user@example.com", b"> user@example.com")
    seeds.append(("21_ws_leading_space", xml))

    # 6d: whitespace between attributes
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b'Version="2.0" ID="_assert_rt"',
        b'Version="2.0"  \t\n  ID="_assert_rt"',
    )
    seeds.append(("22_ws_between_attrs", xml))

    # 6e: CRLF line endings
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = xml.replace(b"\n", b"\r\n")
    seeds.append(("23_crlf_line_endings", xml))

    # 6f: zero-width spaces in NameID
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b"user@example.com", "user\u200b@example.com".encode("utf-8")
    )
    seeds.append(("24_zwsp_nameid", xml))

    # 6g: BOM prefix
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = b"\xef\xbb\xbf" + xml
    seeds.append(("25_bom_prefix", xml))

    return seeds


def gen_xml_declaration():
    """Category 7: XML declaration variants."""
    seeds = []

    # 7a: no XML declaration
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = xml.split(b"?>", 1)[1].lstrip()
    seeds.append(("26_no_xml_decl", xml))

    # 7b: XML 1.1 declaration
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = xml.replace(b'version=\'1.0\'', b'version="1.1"')
    seeds.append(("27_xml_11_decl", xml))

    # 7c: standalone="yes"
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = xml.replace(b"encoding='UTF-8'?>", b'encoding="UTF-8" standalone="yes"?>')
    seeds.append(("28_standalone_yes", xml))

    # 7d: different encoding declaration
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = xml.replace(b"encoding='UTF-8'", b'encoding="utf-8"')
    seeds.append(("29_encoding_lowercase", xml))

    # 7e: UTF-16 encoding declaration (but UTF-8 content)
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = xml.replace(b"encoding='UTF-8'", b'encoding="UTF-16"')
    seeds.append(("30_encoding_mismatch", xml))

    return seeds


def gen_element_form():
    """Category 8: element serialization form variants."""
    seeds = []

    # 8a: expand self-closing SubjectConfirmationData
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"/>",  # first self-closing tag (StatusCode)
        b"></samlp:StatusCode>",
    )
    seeds.append(("31_expand_selfclose", xml))

    return seeds


def gen_comment_pi():
    """Category 9: comments and PIs inside signed content."""
    seeds = []

    # 9a: comment inside NameID text
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b"user@example.com", b"user<!--comment-->@example.com"
    )
    seeds.append(("32_comment_in_nameid", xml))

    # 9b: PI inside assertion
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<?xml-stylesheet type="text/xsl" href="evil.xsl"?><saml:Subject>',
    )
    seeds.append(("33_pi_before_subject", xml))

    # 9c: comment splitting element name (well-formedness violation)
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b"<saml:NameID", b"<saml:Name<!-- -->ID"
    )
    seeds.append(("34_comment_split_tag", xml))

    # 9d: comment between NameID tag and text
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b">user@example.com</saml:NameID>",
        b"><!--injected-->user@example.com</saml:NameID>",
    )
    seeds.append(("35_comment_before_text", xml))

    # 9e: multi-line comment wrapping subject
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"user@example.com",
        b"admin@evil.com<!--user@example.com-->",
    )
    seeds.append(("36_comment_hide_real_email", xml))

    return seeds


def gen_ns_stacking():
    """Category 10: complex namespace stacking."""
    seeds = []

    # 10a: multiple unused NS on assertion
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Assertion",
        b'<saml:Assertion xmlns:x1="urn:x1" xmlns:x2="urn:x2" xmlns:x3="urn:x3"',
    )
    seeds.append(("37_ns_stacking_unused", xml))

    # 10b: redeclare saml with slightly different URI
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Assertion",
        b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion "',  # trailing space
    )
    seeds.append(("38_ns_uri_trailing_space", xml))

    # 10c: case-different NS URI
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion">',  # capital A
    )
    seeds.append(("39_ns_uri_case_diff", xml))

    # 10d: percent-encoded NS URI
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Subject>",
        b'<saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:%61ssertion">',
    )
    seeds.append(("40_ns_uri_pct_encoded", xml))

    # 10e: duplicate NS declaration (same prefix, same URI)
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml,
        b"<saml:Assertion",
        b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
    )
    seeds.append(("41_ns_duplicate_decl", xml))

    return seeds


def gen_signature_reference():
    """Category 11: signature reference URI variants."""
    seeds = []

    # 11a: empty reference URI (whole document)
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b'URI="#_assert_rt"', b'URI=""'
    )
    seeds.append(("42_ref_uri_empty", xml))

    # 11b: reference with extra whitespace
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b'URI="#_assert_rt"', b'URI=" #_assert_rt "'
    )
    seeds.append(("43_ref_uri_ws", xml))

    # 11c: reference with URL encoding
    resp, assertion = make_base_response()
    xml = sign_and_serialize(resp, assertion)
    xml = post_sign_inject(
        xml, b'URI="#_assert_rt"', b'URI="#_assert%5Frt"'
    )
    seeds.append(("44_ref_uri_pct", xml))

    return seeds


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    count = 0

    generators = [
        gen_ns_undeclaration,
        gen_prefix_rebinding,
        gen_default_ns_override,
        gen_entity_encoding,
        gen_cdata,
        gen_whitespace,
        gen_xml_declaration,
        gen_element_form,
        gen_comment_pi,
        gen_ns_stacking,
        gen_signature_reference,
    ]

    for gen in generators:
        print(f"\n{gen.__doc__.strip().splitlines()[0]}")
        for name, xml_bytes in gen():
            write_seed(name, xml_bytes)
            count += 1

    print(f"\nTotal: {count} round-trip seeds in {OUT_DIR}")


if __name__ == "__main__":
    main()
