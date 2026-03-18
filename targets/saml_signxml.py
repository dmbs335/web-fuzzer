"""SAML target -- signxml (Python XML-DSig verifier).

Verifies XML digital signatures and extracts SAML assertion fields.
signxml is a low-level XML-DSig library; we manually extract SAML
semantics from the verified document.

Output: standardized JSON for differential comparison.
Exit 0 = processed (even if signature invalid), Exit 1 = parse failure.
"""

import hashlib
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
    return "".join(elem.itertext()) or None


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


def _count_signatures(doc):
    return len(doc.findall(".//{%s}Signature" % DS_NS))


def _count_references(doc):
    return len(list(doc.iter("{%s}Reference" % DS_NS)))


def _first_reference_uri(doc):
    for ref in doc.iter("{%s}Reference" % DS_NS):
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


def _canonical_assertion_hex(elem):
    """Return first 32 bytes (hex) of exc-c14n output for an element."""
    if elem is None:
        return None
    try:
        data = etree.tostring(elem, method="c14n2", with_comments=False)
    except Exception:
        try:
            data = etree.tostring(elem, method="c14n", with_comments=False)
        except Exception:
            return None
    return data[:32].hex() if data else None


def _extract_transform_chain(doc):
    ref = doc.find(".//ds:Reference", NSMAP)
    if ref is None:
        return []
    transforms = ref.findall(".//ds:Transform", NSMAP)
    return [t.get("Algorithm", "") for t in transforms if t.get("Algorithm")]


def _extract_c14n_method(doc):
    elem = doc.find(".//ds:CanonicalizationMethod", NSMAP)
    return elem.get("Algorithm") if elem is not None else None


def _extract_signature_method(doc):
    elem = doc.find(".//ds:SignatureMethod", NSMAP)
    return elem.get("Algorithm") if elem is not None else None


def _extract_digest_method(doc):
    elem = doc.find(".//ds:DigestMethod", NSMAP)
    return elem.get("Algorithm") if elem is not None else None


def _extract_signed_info_hash(doc):
    elem = doc.find(".//ds:SignedInfo", NSMAP)
    return _stable_xml_hash(elem)


def _extract_keyinfo_type(doc):
    keyinfo = doc.find(".//ds:KeyInfo", NSMAP)
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


def _find_signed_assertion(doc, assertions):
    """Find the assertion targeted by the signature's Reference URI."""
    for ref in doc.iter("{%s}Reference" % DS_NS):
        uri = ref.get("URI", "")
        if uri.startswith("#"):
            target_id = uri[1:]
            for idx, assertion in enumerate(assertions):
                if assertion.get("ID") == target_id:
                    return assertion, "reference_uri", idx, uri
    if assertions:
        return assertions[0], "first_assertion_fallback", 0, _first_reference_uri(doc)
    return None, "no_assertion", None, _first_reference_uri(doc)


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

    # Count assertions from original root (for consistent cross-harness comparison)
    original_assertions = root.findall(".//{%s}Assertion" % SAML_NS)
    assertion_count = len(original_assertions)

    # Extract SAML fields from the verified document
    doc = verified_root if verified_root is not None else root

    # Assertions within verified context
    assertions = doc.findall(".//{%s}Assertion" % SAML_NS)
    doc_tag = doc.tag if hasattr(doc, 'tag') else ""
    if doc_tag == "{%s}Assertion" % SAML_NS or doc_tag == "Assertion":
        if doc not in assertions:
            assertions.insert(0, doc)

    # Find the assertion targeted by the signature's Reference URI
    signed_assertion, selection_mode, selected_assertion_index, reference_uri = _find_signed_assertion(doc, assertions)
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
        # Extract from signed assertion only
        name_id_elem = signed_assertion.find("{%s}Subject/{%s}NameID" % (SAML_NS, SAML_NS))
        if name_id_elem is None:
            name_id_elem = signed_assertion.find(".//{%s}NameID" % SAML_NS)
        subject = _text(name_id_elem)
        subject_format = name_id_elem.get("Format") if name_id_elem is not None else None
        nameid_count, empty_nameid_semantics = _nameid_observability(signed_assertion)

        issuer_elem = signed_assertion.find("{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)
        if issuer:
            issuer_source = "assertion"

        audience_elems = signed_assertion.findall(".//{%s}Audience" % SAML_NS)
        audience_count = len(audience_elems)
        audience_elem = audience_elems[0] if audience_elems else None
        audience = _text(audience_elem)

        for attr_elem in signed_assertion.findall(".//{%s}Attribute" % SAML_NS):
            attr_name = attr_elem.get("Name", "")
            values = []
            for val in attr_elem.findall("{%s}AttributeValue" % SAML_NS):
                v = _text(val)
                if v:
                    values.append(v)
            if attr_name and values:
                attributes[attr_name] = values[0] if len(values) == 1 else values

    # Response-level issuer as fallback
    if not issuer:
        issuer_elem = doc.find("{%s}Issuer" % SAML_NS)
        if issuer_elem is None:
            issuer_elem = doc.find(".//{%s}Issuer" % SAML_NS)
        issuer = _text(issuer_elem)
        if issuer:
            issuer_source = "response"

    # Algorithms
    algorithms = _extract_algorithms(doc)
    reference_matches_selected_assertion = None
    if reference_target_id and assertion_id:
        reference_matches_selected_assertion = reference_target_id == assertion_id
    keyinfo_present, keyinfo_type = _extract_keyinfo_type(doc)
    validated_node = verified_root if signature_valid and verified_root is not None else signed_assertion
    validated_node_id = None
    validated_node_tag = None
    validated_reference_uri = None
    resolved_id_attribute = None
    id_resolution_mode = selection_mode
    digest_input_hash = None
    if validated_node is not None:
        validated_node_tag = _local_name(getattr(validated_node, "tag", None))
        validated_node_id = (
            validated_node.get("ID")
            or validated_node.get("Id")
            or validated_node.get("{http://www.w3.org/XML/1998/namespace}id")
        )
        resolved_id_attribute = _resolved_id_attribute(validated_node)
        digest_input_hash = _stable_xml_hash(validated_node)
    if signature_valid:
        if reference_uri:
            validated_reference_uri = reference_uri
        elif validated_node_id:
            validated_reference_uri = f"#{validated_node_id}"

    # Intermediate processing fields
    transform_chain = _extract_transform_chain(doc)
    c14n_method = _extract_c14n_method(doc)
    c14n_method_used = c14n_method if signature_valid else None

    if reference_target_id and assertion_id:
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
        "assertion_count": assertion_count,
        "assertion_id": assertion_id,
        "selected_assertion_index": selected_assertion_index,
        "selection_mode": selection_mode,
        "reference_uri": reference_uri,
        "reference_matches_selected_assertion": reference_matches_selected_assertion,
        "signature_count": _count_signatures(doc),
        "issuer_source": issuer_source,
        "audience_count": audience_count,
        "nameid_count": nameid_count,
        "empty_nameid_semantics": empty_nameid_semantics,
        "algorithms": algorithms,
        "validated_reference_uri": validated_reference_uri,
        "validated_reference_count": _count_references(doc),
        "validated_node_tag": validated_node_tag,
        "validated_node_id": validated_node_id,
        "validated_node_xpath": validated_node_tag,
        "id_resolution_mode": id_resolution_mode,
        "resolved_id_attribute": resolved_id_attribute,
        "transform_chain": transform_chain,
        "transform_chain_length": len(transform_chain),
        "c14n_method": c14n_method,
        "c14n_method_used": c14n_method_used,
        "signature_method": _extract_signature_method(doc),
        "validated_signature_algorithm": _extract_signature_method(doc) if signature_valid else None,
        "digest_method": _extract_digest_method(doc),
        "digest_input_hash": digest_input_hash,
        "signed_info_hash": _extract_signed_info_hash(doc),
        "key_source": "configured_cert",
        "keyinfo_present": keyinfo_present,
        "keyinfo_type": keyinfo_type,
        "signature_element_count": _count_signatures(doc),
        "reference_element_count": _count_references(doc),
        "canonical_assertion_hex": _canonical_assertion_hex(signed_assertion),
        "reference_resolution_mode": reference_resolution_mode,
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
