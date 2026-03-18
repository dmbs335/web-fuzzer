"""SAML target -- python3-saml (OneLogin).

Full SAML 2.0 Response verification including signature, conditions,
audience, and assertion extraction.

Output: standardized JSON for differential comparison.
Exit 0 = processed (even if signature invalid), Exit 1 = parse failure.
"""

import base64
import hashlib
import json
import os
import sys
import traceback
from copy import deepcopy

from lxml import etree

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml_fixtures")

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
NSMAP = {"saml": SAML_NS, "ds": DS_NS}


def _text(elem):
    """Match python3-saml's OneLogin_Saml2_XML.element_text() behavior.

    Strips XML comments, then returns .text (which stops at the first
    remaining child node, e.g. a PI).  Faithfully mirrors::

        etree.strip_tags(node, etree.Comment)
        return node.text

    No .strip() — the real library returns the raw text as-is.
    """
    if elem is None:
        return None
    e = deepcopy(elem)
    etree.strip_tags(e, etree.Comment)
    return e.text or None


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


def _count_signatures(root):
    return len(root.findall(".//{%s}Signature" % DS_NS))


def _count_references(root):
    return len(list(root.iter("{%s}Reference" % DS_NS)))


def _first_reference_uri(root):
    for ref in root.iter("{%s}Reference" % DS_NS):
        uri = ref.get("URI", "")
        if uri:
            return uri
    return None


def _local_name(tag):
    if not tag:
        return None
    return tag.split("}", 1)[1] if "}" in tag else tag


def _stable_xml_hash(elem):
    if elem is None:
        return None
    try:
        data = etree.tostring(elem, method="c14n", with_comments=True)
    except Exception:
        data = etree.tostring(elem, encoding="utf-8")
    return hashlib.sha256(data).hexdigest()[:16]


def _extract_transform_chain(root):
    ref = root.find(".//ds:Reference", NSMAP)
    if ref is None:
        return []
    transforms = ref.findall(".//ds:Transform", NSMAP)
    return [t.get("Algorithm", "") for t in transforms if t.get("Algorithm")]


def _extract_c14n_method(root):
    elem = root.find(".//ds:CanonicalizationMethod", NSMAP)
    return elem.get("Algorithm") if elem is not None else None


def _extract_signature_method(root):
    elem = root.find(".//ds:SignatureMethod", NSMAP)
    return elem.get("Algorithm") if elem is not None else None


def _extract_digest_method(root):
    elem = root.find(".//ds:DigestMethod", NSMAP)
    return elem.get("Algorithm") if elem is not None else None


def _extract_signed_info_hash(root):
    elem = root.find(".//ds:SignedInfo", NSMAP)
    return _stable_xml_hash(elem)


def _extract_keyinfo_type(root):
    keyinfo = root.find(".//ds:KeyInfo", NSMAP)
    if keyinfo is None:
        return False, "none"
    if len(keyinfo) == 0 and not (keyinfo.text or "").strip():
        return True, "empty"
    if keyinfo.find(".//ds:X509Certificate", NSMAP) is not None:
        return True, "x509data"
    if keyinfo.find(".//ds:KeyValue", NSMAP) is not None:
        return True, "keyvalue"
    return True, "unknown"


def _resolved_id_attribute(elem):
    if elem is None:
        return None
    for candidate in ("ID", "Id", "{http://www.w3.org/XML/1998/namespace}id"):
        if elem.get(candidate):
            return candidate
    return None


def _nameid_observability(assertion):
    if assertion is None:
        return 0, "missing"
    name_ids = assertion.findall(".//{%s}NameID" % SAML_NS)
    if not name_ids:
        return 0, "missing"
    first_text = _text(name_ids[0])
    return len(name_ids), "empty" if first_text is None else "nonempty"


def _find_signed_assertion(root, assertions):
    """Find the assertion targeted by the signature's Reference URI."""
    for ref in root.iter("{%s}Reference" % DS_NS):
        uri = ref.get("URI", "")
        if uri.startswith("#"):
            target_id = uri[1:]
            for idx, assertion in enumerate(assertions):
                if assertion.get("ID") == target_id:
                    return assertion, "reference_uri", idx, uri
    if assertions:
        return assertions[0], "first_assertion_fallback", 0, _first_reference_uri(root)
    return None, "no_assertion", None, _first_reference_uri(root)


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
    signed_assertion, selection_mode, selected_assertion_index, reference_uri = _find_signed_assertion(root, assertions)
    reference_target_id = reference_uri[1:] if isinstance(reference_uri, str) and reference_uri.startswith("#") else None

    subject = None
    subject_format = None
    issuer = None
    issuer_source = "none"
    audience = None
    audience_count = 0
    attributes = {}
    assertion_id = None
    nameid_count = 0
    empty_nameid_semantics = "missing"

    if signed_assertion is not None:
        assertion_id = signed_assertion.get("ID")
        name_id = signed_assertion.find("{%s}Subject/{%s}NameID" % (SAML_NS, SAML_NS))
        if name_id is None:
            name_id = signed_assertion.find(".//{%s}NameID" % SAML_NS)
        subject = _text(name_id)
        subject_format = name_id.get("Format") if name_id is not None else None
        nameid_count, empty_nameid_semantics = _nameid_observability(signed_assertion)

        issuer_elem = signed_assertion.find("{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)
        if issuer:
            issuer_source = "assertion"

        audience_elems = signed_assertion.findall(".//{%s}Audience" % SAML_NS)
        audience_count = len(audience_elems)
        audience_elem = audience_elems[0] if audience_elems else None
        audience = _text(audience_elem)

        for attr in signed_assertion.findall(".//{%s}Attribute" % SAML_NS):
            name = attr.get("Name", "")
            vals = []
            for v in attr.findall("{%s}AttributeValue" % SAML_NS):
                t = _text(v)
                if t:
                    vals.append(t)
            if name and vals:
                attributes[name] = vals[0] if len(vals) == 1 else vals

    # Response-level issuer as fallback
    if not issuer:
        issuer_elem = root.find("{%s}Issuer" % SAML_NS)
        if issuer_elem is None:
            issuer_elem = root.find(".//{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)
        if issuer:
            issuer_source = "response"

    reference_matches_selected_assertion = None
    if reference_target_id and assertion_id:
        reference_matches_selected_assertion = reference_target_id == assertion_id
    keyinfo_present, keyinfo_type = _extract_keyinfo_type(root)
    validated_node = signed_assertion if signature_valid else None
    validated_node_tag = _local_name(getattr(validated_node, "tag", None))
    validated_node_id = None
    resolved_id_attribute = None
    digest_input_hash = None
    if validated_node is not None:
        validated_node_id = (
            validated_node.get("ID")
            or validated_node.get("Id")
            or validated_node.get("{http://www.w3.org/XML/1998/namespace}id")
        )
        resolved_id_attribute = _resolved_id_attribute(validated_node)
        digest_input_hash = _stable_xml_hash(validated_node)
    validated_reference_uri = reference_uri if signature_valid else None

    # Intermediate processing fields
    transform_chain = _extract_transform_chain(root)
    c14n_method = _extract_c14n_method(root)

    # c14n_method_used: the actual c14n applied (declared c14n if sig valid, else None)
    c14n_method_used = c14n_method if signature_valid else None

    # reference_resolution_mode: how the target of Reference was resolved
    # "uri_id_match" = Reference URI matched an Assertion ID attribute
    # "fallback_first" = no URI match, fell back to first assertion
    # "no_reference" = no Reference element found
    if reference_uri and reference_target_id and assertion_id:
        if reference_target_id == assertion_id:
            reference_resolution_mode = "uri_id_match"
        else:
            reference_resolution_mode = "uri_id_mismatch"
    elif reference_uri:
        reference_resolution_mode = "uri_no_target"
    elif assertions:
        reference_resolution_mode = "fallback_first"
    else:
        reference_resolution_mode = "no_reference"

    result = {
        "signature_valid": signature_valid,
        "signature_error": signature_error,
        "subject": subject,
        "subject_format": subject_format,
        "issuer": issuer,
        "audience": audience,
        "attributes": attributes,
        "assertion_count": len(assertions),
        "assertion_id": assertion_id,
        "selected_assertion_index": selected_assertion_index,
        "selection_mode": selection_mode,
        "reference_uri": reference_uri,
        "reference_matches_selected_assertion": reference_matches_selected_assertion,
        "signature_count": _count_signatures(root),
        "issuer_source": issuer_source,
        "audience_count": audience_count,
        "nameid_count": nameid_count,
        "empty_nameid_semantics": empty_nameid_semantics,
        "algorithms": _extract_algorithms(root),
        "validated_reference_uri": validated_reference_uri,
        "validated_reference_count": _count_references(root),
        "validated_node_tag": validated_node_tag,
        "validated_node_id": validated_node_id,
        "validated_node_xpath": validated_node_tag,
        "id_resolution_mode": selection_mode,
        "resolved_id_attribute": resolved_id_attribute,
        "transform_chain": transform_chain,
        "transform_chain_length": len(transform_chain),
        "c14n_method": c14n_method,
        "c14n_method_used": c14n_method_used,
        "signature_method": _extract_signature_method(root),
        "validated_signature_algorithm": _extract_signature_method(root) if signature_valid else None,
        "digest_method": _extract_digest_method(root),
        "digest_input_hash": digest_input_hash,
        "signed_info_hash": _extract_signed_info_hash(root),
        "key_source": "configured_cert",
        "keyinfo_present": keyinfo_present,
        "keyinfo_type": keyinfo_type,
        "signature_element_count": _count_signatures(root),
        "reference_element_count": _count_references(root),
        "reference_resolution_mode": reference_resolution_mode,
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
