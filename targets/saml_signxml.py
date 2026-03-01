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
    """Get text content of an element, or None."""
    if elem is None:
        return None
    return (elem.text or "").strip() or None


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

    # Assertions
    assertions = doc.findall(".//saml:Assertion", NSMAP)
    if not assertions:
        # Try without namespace (some docs use default ns)
        assertions = doc.findall(".//{%s}Assertion" % SAML_NS)

    assertion_count = len(assertions)

    # Subject / NameID
    name_id_elem = doc.find(".//saml:NameID", NSMAP)
    if name_id_elem is None:
        name_id_elem = doc.find(".//{%s}NameID" % SAML_NS)
    subject = _text(name_id_elem)
    subject_format = name_id_elem.get("Format") if name_id_elem is not None else None

    # Issuer
    issuer_elem = doc.find(".//saml:Issuer", NSMAP)
    if issuer_elem is None:
        issuer_elem = doc.find(".//{%s}Issuer" % SAML_NS)
    issuer = _text(issuer_elem)

    # Audience
    audience_elem = doc.find(".//saml:Audience", NSMAP)
    if audience_elem is None:
        audience_elem = doc.find(".//{%s}Audience" % SAML_NS)
    audience = _text(audience_elem)

    # Attributes
    attributes = {}
    for attr_elem in doc.findall(".//saml:Attribute", NSMAP):
        attr_name = attr_elem.get("Name", "")
        values = []
        for val in attr_elem.findall("saml:AttributeValue", NSMAP):
            if val.text:
                values.append(val.text.strip())
        if attr_name and values:
            attributes[attr_name] = values[0] if len(values) == 1 else values

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
