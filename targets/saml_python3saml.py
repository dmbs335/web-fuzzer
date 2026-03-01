"""SAML target -- python3-saml (OneLogin).

Full SAML 2.0 Response verification including signature, conditions,
audience, and assertion extraction.

Output: standardized JSON for differential comparison.
Exit 0 = processed (even if signature invalid), Exit 1 = parse failure.
"""

import base64
import json
import os
import sys
import traceback

from lxml import etree

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml_fixtures")

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
NSMAP = {"saml": SAML_NS, "ds": DS_NS}


def _text(elem):
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
    result = {}
    sig_method = root.find(".//ds:SignatureMethod", NSMAP)
    if sig_method is not None:
        result["signature"] = _normalize_sig_algo(sig_method.get("Algorithm", ""))

    digest_method = root.find(".//ds:DigestMethod", NSMAP)
    if digest_method is not None:
        result["digest"] = _normalize_digest_algo(digest_method.get("Algorithm", ""))
    return result


def _find_signed_assertion(root, assertions):
    """Find the assertion targeted by the signature's Reference URI."""
    for ref in root.iter("{%s}Reference" % DS_NS):
        uri = ref.get("URI", "")
        if uri.startswith("#"):
            target_id = uri[1:]
            for assertion in assertions:
                if assertion.get("ID") == target_id:
                    return assertion
    return assertions[0] if assertions else None


def verify_saml(xml_input: str) -> str:
    """Verify SAML Response using python3-saml and return structured JSON."""
    xml_bytes = xml_input.encode("utf-8") if isinstance(xml_input, str) else xml_input

    try:
        root = etree.fromstring(xml_bytes)
    except etree.XMLSyntaxError as e:
        raise ValueError(f"XML parse error: {e}")

    # Load IdP cert (strip PEM headers for python3-saml)
    cert_path = os.path.join(FIXTURES, "idp_cert.pem")
    with open(cert_path, "r", encoding="utf-8") as f:
        raw_cert = f.read()
    cert_clean = (
        raw_cert
        .replace("-----BEGIN CERTIFICATE-----", "")
        .replace("-----END CERTIFICATE-----", "")
        .replace("\n", "")
        .strip()
    )

    signature_valid = False
    signature_error = None

    try:
        from onelogin.saml2.response import OneLogin_Saml2_Response
        from onelogin.saml2.settings import OneLogin_Saml2_Settings

        settings_data = {
            "strict": False,
            "sp": {
                "entityId": "https://sp.example.com",
                "assertionConsumerService": {
                    "url": "https://sp.example.com/acs",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                },
            },
            "idp": {
                "entityId": "https://idp.example.com",
                "singleSignOnService": {
                    "url": "https://idp.example.com/sso",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                },
                "x509cert": cert_clean,
            },
        }

        settings = OneLogin_Saml2_Settings(settings_data, custom_base_path=".")
        b64_response = base64.b64encode(xml_bytes).decode("ascii")
        response = OneLogin_Saml2_Response(settings, b64_response)

        request_data = {
            "http_host": "sp.example.com",
            "script_name": "/acs",
            "server_port": "443",
            "https": "on",
        }
        if response.is_valid(request_data, raise_exceptions=False):
            signature_valid = True
        else:
            signature_error = response.get_error() or "Validation failed"

    except ImportError:
        # python3-saml not installed; fall back to signxml
        try:
            from signxml import XMLVerifier
            idp_cert_bytes = open(cert_path, "rb").read()
            XMLVerifier().verify(root, x509_cert=idp_cert_bytes)
            signature_valid = True
        except Exception as e:
            signature_error = str(e)[:500]
    except Exception as e:
        signature_error = str(e)[:500]

    # Extract fields from the signed assertion (not full document)
    assertions = root.findall(".//{%s}Assertion" % SAML_NS)
    signed_assertion = _find_signed_assertion(root, assertions)

    subject = None
    subject_format = None
    issuer = None
    audience = None
    attributes = {}

    if signed_assertion is not None:
        name_id = signed_assertion.find("{%s}Subject/{%s}NameID" % (SAML_NS, SAML_NS))
        if name_id is None:
            name_id = signed_assertion.find(".//{%s}NameID" % SAML_NS)
        subject = _text(name_id)
        subject_format = name_id.get("Format") if name_id is not None else None

        issuer_elem = signed_assertion.find("{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)

        audience_elem = signed_assertion.find(".//{%s}Audience" % SAML_NS)
        audience = _text(audience_elem)

        for attr in signed_assertion.findall(".//{%s}Attribute" % SAML_NS):
            name = attr.get("Name", "")
            vals = []
            for v in attr.findall("{%s}AttributeValue" % SAML_NS):
                if v.text:
                    vals.append(v.text.strip())
            if name and vals:
                attributes[name] = vals[0] if len(vals) == 1 else vals

    # Response-level issuer as fallback
    if not issuer:
        issuer_elem = root.find("{%s}Issuer" % SAML_NS)
        if issuer_elem is None:
            issuer_elem = root.find(".//{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)

    result = {
        "signature_valid": signature_valid,
        "signature_error": signature_error,
        "subject": subject,
        "subject_format": subject_format,
        "issuer": issuer,
        "audience": audience,
        "attributes": attributes,
        "assertion_count": len(assertions),
        "algorithms": _extract_algorithms(root),
    }
    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main():
    if len(sys.argv) < 2:
        print("Usage: saml_python3saml.py <input_file>", file=sys.stderr)
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
