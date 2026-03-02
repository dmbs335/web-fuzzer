"""SAML target -- signxml (Python XML-DSig verifier).

Verifies XML digital signatures and extracts SAML assertion fields.
signxml is a low-level XML-DSig library; we manually extract SAML
semantics from the verified document.

Output: standardized JSON for differential comparison.
Exit 0 = processed (even if signature invalid), Exit 1 = parse failure.
"""

import json
import os
import sys

from lxml import etree

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml_fixtures")

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

NSMAP = {
    "saml": SAML_NS,
    "samlp": SAMLP_NS,
    "ds": DS_NS,
}


def _text(elem):
    """Get full text content of an element, including text after comments/PIs."""
    if elem is None:
        return None
    return "".join(elem.itertext()).strip() or None


def _normalize_sig_algo(algo):
    a = algo.lower()
    if "hmac" in a:
        return algo.split("#")[-1] if "#" in algo else algo
    if "sha256" in a:
        return "rsa-sha256"
    if "sha384" in a:
        return "rsa-sha384"
    if "sha512" in a:
        return "rsa-sha512"
    if "sha1" in a:
        return "rsa-sha1"
    return algo


def _normalize_digest_algo(algo):
    a = algo.lower()
    if "sha256" in a:
        return "sha256"
    if "sha384" in a:
        return "sha384"
    if "sha512" in a:
        return "sha512"
    if "sha1" in a:
        return "sha1"
    if "md5" in a:
        return "md5"
    return algo


def _extract_algorithms(root):
    """Extract signature and digest algorithm URIs."""
    result = {}
    sig_method = root.find(".//ds:SignatureMethod", NSMAP)
    if sig_method is not None:
        result["signature"] = _normalize_sig_algo(sig_method.get("Algorithm", ""))

    digest_method = root.find(".//ds:DigestMethod", NSMAP)
    if digest_method is not None:
        result["digest"] = _normalize_digest_algo(digest_method.get("Algorithm", ""))

    return result


def _find_signed_assertion(doc, assertions):
    """Find the assertion targeted by the signature's Reference URI."""
    for ref in doc.iter("{%s}Reference" % DS_NS):
        uri = ref.get("URI", "")
        if uri.startswith("#"):
            target_id = uri[1:]
            for assertion in assertions:
                if assertion.get("ID") == target_id:
                    return assertion
    return assertions[0] if assertions else None


def verify_saml(xml_input: str) -> str:
    """Verify SAML Response and return structured JSON."""
    try:
        root = etree.fromstring(xml_input.encode("utf-8") if isinstance(xml_input, str) else xml_input)
    except etree.XMLSyntaxError as e:
        raise ValueError(f"XML parse error: {e}")

    # Load IdP certificate
    cert_path = os.path.join(FIXTURES, "idp_cert.pem")
    with open(cert_path, "rb") as f:
        idp_cert = f.read()

    # Attempt signature verification
    signature_valid = False
    signature_error = None
    verified_root = None

    try:
        from signxml import XMLVerifier
        verified_data = XMLVerifier().verify(
            root, x509_cert=idp_cert
        )
        signature_valid = True
        verified_root = verified_data.signed_xml
    except Exception as e:
        signature_error = str(e)[:500]
        verified_root = root

    # Extract SAML fields from the document (verified or original)
    doc = verified_root if verified_root is not None else root

    # Assertions — check if doc itself is an Assertion (signxml returns signed element)
    assertions = doc.findall(".//{%s}Assertion" % SAML_NS)
    doc_tag = doc.tag if hasattr(doc, 'tag') else ""
    if doc_tag == "{%s}Assertion" % SAML_NS or doc_tag == "Assertion":
        if doc not in assertions:
            assertions.insert(0, doc)
    assertion_count = len(assertions)

    # Find the assertion targeted by the signature's Reference URI
    signed_assertion = _find_signed_assertion(doc, assertions)

    subject = None
    subject_format = None
    issuer = None
    audience = None
    attributes = {}
    assertion_id = None

    if signed_assertion is not None:
        assertion_id = signed_assertion.get("ID")
        # Extract from signed assertion only
        name_id_elem = signed_assertion.find("{%s}Subject/{%s}NameID" % (SAML_NS, SAML_NS))
        if name_id_elem is None:
            name_id_elem = signed_assertion.find(".//{%s}NameID" % SAML_NS)
        subject = _text(name_id_elem)
        subject_format = name_id_elem.get("Format") if name_id_elem is not None else None

        issuer_elem = signed_assertion.find("{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)

        audience_elem = signed_assertion.find(".//{%s}Audience" % SAML_NS)
        audience = _text(audience_elem)

        for attr_elem in signed_assertion.findall(".//{%s}Attribute" % SAML_NS):
            attr_name = attr_elem.get("Name", "")
            values = []
            for val in attr_elem.findall("{%s}AttributeValue" % SAML_NS):
                if val.text:
                    values.append(val.text.strip())
            if attr_name and values:
                attributes[attr_name] = values[0] if len(values) == 1 else values

    # Response-level issuer as fallback
    if not issuer:
        issuer_elem = doc.find("{%s}Issuer" % SAML_NS)
        if issuer_elem is None:
            issuer_elem = doc.find(".//{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)

    # Algorithms
    algorithms = _extract_algorithms(doc)

    result = {
        "signature_valid": signature_valid,
        "signature_error": signature_error,
        "subject": subject,
        "subject_format": subject_format,
        "issuer": issuer,
        "audience": audience,
        "attributes": attributes,
        "assertion_count": assertion_count,
        "assertion_id": assertion_id,
        "algorithms": algorithms,
    }
    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main():
    if len(sys.argv) < 2:
        print("Usage: saml_signxml.py <input_file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = verify_saml(data)
        print(result)
        sys.exit(0)
    except (ValueError, TypeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
