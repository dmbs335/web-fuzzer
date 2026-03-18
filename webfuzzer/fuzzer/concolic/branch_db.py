"""Branch condition database for SAML library concolic execution.

Maps (library, file, line_range) → XML structural mutation that
flips the branch.  Built from static analysis of signxml and
python3-saml source code.

Each entry describes:
- Which source file and line range the branch lives at
- What XML structural property the condition checks
- How to mutate the input to take the other path
"""

from __future__ import annotations

import re
import random
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True, slots=True)
class BranchCondition:
    """One source-level branch condition mapped to XML mutation."""

    library: str  # "signxml" or "python3-saml"
    file: str  # e.g. "processor.py"
    line_start: int
    line_end: int
    condition: str  # human-readable description
    xml_property: str  # what XML property it checks
    mutation_fn: str  # name of mutation function to call


# ── Mutation functions ──────────────────────────────────────────
# Each takes (data: bytes, rng: Random) -> bytes | None
# Returns None if mutation not applicable


def _add_dtd(data: bytes, rng: random.Random) -> bytes | None:
    """Add DTD declaration to trigger S1/P2-P4."""
    if b"<!DOCTYPE" in data:
        return None
    xml_decl = re.search(rb"<\?xml[^?]*\?>", data[:200])
    pos = xml_decl.end() if xml_decl else 0
    dtds = [
        b'<!DOCTYPE Response [<!ENTITY xxe "test">]>',
        b"<!DOCTYPE Response SYSTEM 'http://evil.com/dtd'>",
    ]
    return data[:pos] + rng.choice(dtds) + data[pos:]


def _remove_dtd(data: bytes, rng: random.Random) -> bytes | None:
    """Remove DTD to bypass S1/P2-P4."""
    m = re.search(rb"<!DOCTYPE[^>]*>", data)
    if not m:
        return None
    return data[: m.start()] + data[m.end() :]


def _set_reference_uri_empty(data: bytes, rng: random.Random) -> bytes | None:
    """Set Reference URI="" to trigger S12 (whole-document reference)."""
    m = re.search(rb'(<(?:\w+:)?Reference\s[^>]*?)URI="[^"]*"', data)
    if not m:
        return None
    return data[: m.start()] + m.group(1) + b'URI=""' + data[m.end() :]


def _remove_reference_uri(data: bytes, rng: random.Random) -> bytes | None:
    """Remove Reference URI attribute to trigger S11."""
    m = re.search(rb'(<(?:\w+:)?Reference\s[^>]*?)\s*URI="[^"]*"', data)
    if not m:
        return None
    return data[: m.start()] + m.group(1) + data[m.end() :]


def _add_xpointer_uri(data: bytes, rng: random.Random) -> bytes | None:
    """Set Reference URI to xpointer to trigger S13."""
    m = re.search(rb'(<(?:\w+:)?Reference\s[^>]*?)URI="[^"]*"', data)
    if not m:
        return None
    return data[: m.start()] + m.group(1) + b'URI="#xpointer(/)"' + data[m.end() :]


def _add_duplicate_id(data: bytes, rng: random.Random) -> bytes | None:
    """Create duplicate ID to trigger S15 (ambiguous reference)."""
    id_m = re.search(rb'\bID="([^"]*)"', data)
    if not id_m:
        return None
    clone = b'<DuplicateElement ID="' + id_m.group(1) + b'"/>'
    return data[: id_m.start()] + clone + data[id_m.start() :]


def _set_enveloping_signature(data: bytes, rng: random.Random) -> bytes | None:
    """Wrap so root is ds:Signature to trigger S19."""
    if data.strip().startswith(b"<ds:Signature") or data.strip().startswith(b"<Signature"):
        return None
    return (
        b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        b"<ds:SignedInfo/><ds:SignatureValue/>"
        b"<ds:Object>" + data + b"</ds:Object></ds:Signature>"
    )


def _add_with_comments_c14n(data: bytes, rng: random.Random) -> bytes | None:
    """Change c14n to WithComments variant to trigger S8."""
    old = b"http://www.w3.org/2001/10/xml-exc-c14n#"
    new = b"http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
    if old not in data or new in data:
        return None
    return data.replace(old, new, 1)


def _switch_c14n_inclusive(data: bytes, rng: random.Random) -> bytes | None:
    """Switch from exc-c14n to inclusive to trigger S7."""
    old = b"http://www.w3.org/2001/10/xml-exc-c14n#"
    new = b"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    if old not in data:
        return None
    return data.replace(old, new, 1)


def _add_base64_transform(data: bytes, rng: random.Random) -> bytes | None:
    """Add base64 transform to trigger S37."""
    m = re.search(rb"</(?:\w+:)?Transforms\s*>", data)
    if not m:
        return None
    inject = b'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/>'
    return data[: m.start()] + inject + data[m.start() :]


def _remove_enveloped_transform(data: bytes, rng: random.Random) -> bytes | None:
    """Remove enveloped-signature transform to trigger different S36 path."""
    m = re.search(
        rb"<(?:\w+:)?Transform\s+Algorithm=\"[^\"]*enveloped-signature[^\"]*\"\s*/?>",
        data,
    )
    if not m:
        return None
    return data[: m.start()] + data[m.end() :]


def _add_keyvalue(data: bytes, rng: random.Random) -> bytes | None:
    """Add KeyValue element to trigger S20-S31/S41/S65."""
    if b"KeyValue" in data:
        return None
    m = re.search(rb"</(?:\w+:)?SignedInfo\s*>", data)
    if not m:
        return None
    kv = (
        b"<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue>"
        b"<ds:Modulus>AAAA</ds:Modulus><ds:Exponent>AQAB</ds:Exponent>"
        b"</ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>"
    )
    return data[: m.end()] + kv + data[m.end() :]


def _add_x509cert(data: bytes, rng: random.Random) -> bytes | None:
    """Add X509Certificate to trigger S53-S56."""
    if b"X509Certificate" in data:
        return None
    m = re.search(rb"</(?:\w+:)?SignedInfo\s*>", data)
    if not m:
        return None
    cert = (
        b"<ds:KeyInfo><ds:X509Data>"
        b"<ds:X509Certificate>MIIBkTCB+wIJAL...</ds:X509Certificate>"
        b"</ds:X509Data></ds:KeyInfo>"
    )
    return data[: m.end()] + cert + data[m.end() :]


def _set_version_wrong(data: bytes, rng: random.Random) -> bytes | None:
    """Set Version != 2.0 to trigger P7."""
    m = re.search(rb'(<(?:\w+:)?Response\b[^>]*?)Version="2\.0"', data)
    if not m:
        return None
    return data[: m.start()] + m.group(1) + b'Version="1.1"' + data[m.end() :]


def _remove_response_id(data: bytes, rng: random.Random) -> bytes | None:
    """Remove Response ID to trigger P8."""
    m = re.search(rb'(<(?:\w+:)?Response\b[^>]*?)\s+ID="[^"]*"', data)
    if not m:
        return None
    return data[: m.start()] + m.group(1) + data[m.end() :]


def _add_extra_assertion(data: bytes, rng: random.Random) -> bytes | None:
    """Add extra Assertion to trigger P9/P54/P60 (count != 1)."""
    m = re.search(rb"(<(?:\w+:)?Assertion\b[^>]*>)", data)
    if not m:
        return None
    clone = (
        b'<saml:Assertion Version="2.0" ID="_extra_'
        + str(rng.randint(1000, 9999)).encode()
        + b'"><saml:Issuer>https://idp.example.com</saml:Issuer>'
        + b"<saml:Subject><saml:NameID>evil@example.com</saml:NameID>"
        + b"</saml:Subject></saml:Assertion>"
    )
    return data[: m.start()] + clone + data[m.start() :]


def _remove_conditions(data: bytes, rng: random.Random) -> bytes | None:
    """Remove Conditions to trigger P18."""
    m = re.search(
        rb"<(?:\w+:)?Conditions\b[^>]*>.*?</(?:\w+:)?Conditions\s*>",
        data,
        re.DOTALL,
    )
    if not m:
        return None
    return data[: m.start()] + data[m.end() :]


def _remove_authnstatement(data: bytes, rng: random.Random) -> bytes | None:
    """Remove AuthnStatement to trigger P19."""
    m = re.search(
        rb"<(?:\w+:)?AuthnStatement\b[^>]*>.*?</(?:\w+:)?AuthnStatement\s*>",
        data,
        re.DOTALL,
    )
    if not m:
        # Try self-closing
        m = re.search(rb"<(?:\w+:)?AuthnStatement\b[^/]*/\s*>", data)
    if not m:
        return None
    return data[: m.start()] + data[m.end() :]


def _set_wrong_destination(data: bytes, rng: random.Random) -> bytes | None:
    """Set wrong Destination to trigger P24-P25."""
    m = re.search(rb'(<(?:\w+:)?Response\b[^>]*?)Destination="[^"]*"', data)
    if not m:
        return data[: m.end()] if m else None
    return data[: m.start()] + m.group(1) + b'Destination="https://evil.sp/"' + data[m.end() :]


def _set_wrong_audience(data: bytes, rng: random.Random) -> bytes | None:
    """Set wrong Audience to trigger P27."""
    m = re.search(rb"(<(?:\w+:)?Audience\b[^>]*>)[^<]*(</)", data)
    if not m:
        return None
    return data[: m.start(1)] + m.group(1) + b"https://wrong-sp.example.com" + m.group(2) + data[m.end() :]


def _set_wrong_issuer(data: bytes, rng: random.Random) -> bytes | None:
    """Set wrong Issuer to trigger P28."""
    m = re.search(rb"(<(?:\w+:)?Issuer\b[^>]*>)[^<]*(</)", data)
    if not m:
        return None
    return data[: m.start(1)] + m.group(1) + b"https://evil-idp.example.com" + m.group(2) + data[m.end() :]


def _inject_child_in_nameid(data: bytes, rng: random.Random) -> bytes | None:
    """Inject child element in NameID to exploit P5 (element_text truncation)."""
    m = re.search(rb"(<(?:\w+:)?NameID\b[^>]*>)([^<]+)(</)", data)
    if not m:
        return None
    text = m.group(2)
    # Split text and inject child element
    if len(text) > 3:
        split = len(text) // 2
        children = [b"<t/>", b"<x/>", b"<child/>"]
        child = rng.choice(children)
        return (
            data[: m.start(2)]
            + text[:split]
            + child
            + text[split:]
            + data[m.end(2) :]
        )
    return None


def _set_wrong_subject_method(data: bytes, rng: random.Random) -> bytes | None:
    """Set SubjectConfirmation Method != bearer to trigger P30."""
    m = re.search(
        rb'(<(?:\w+:)?SubjectConfirmation\b[^>]*?)Method="[^"]*"', data
    )
    if not m:
        return None
    return (
        data[: m.start()]
        + m.group(1)
        + b'Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"'
        + data[m.end() :]
    )


def _add_expired_notonorafter(data: bytes, rng: random.Random) -> bytes | None:
    """Set expired NotOnOrAfter to trigger P34/P59."""
    m = re.search(rb'NotOnOrAfter="[^"]*"', data)
    if not m:
        return None
    return (
        data[: m.start()]
        + b'NotOnOrAfter="2000-01-01T00:00:00Z"'
        + data[m.end() :]
    )


def _add_future_notbefore(data: bytes, rng: random.Random) -> bytes | None:
    """Set future NotBefore to trigger P35/P58."""
    m = re.search(rb'NotBefore="[^"]*"', data)
    if not m:
        return None
    return (
        data[: m.start()] + b'NotBefore="2099-01-01T00:00:00Z"' + data[m.end() :]
    )


def _remove_signature(data: bytes, rng: random.Random) -> bytes | None:
    """Remove Signature to trigger P39/P86."""
    m = re.search(
        rb"<(?:\w+:)?Signature\b[^>]*>.*?</(?:\w+:)?Signature\s*>",
        data,
        re.DOTALL,
    )
    if not m:
        return None
    return data[: m.start()] + data[m.end() :]


def _set_deprecated_algorithm(data: bytes, rng: random.Random) -> bytes | None:
    """Set deprecated SignatureMethod to trigger P52."""
    m = re.search(rb'(<(?:\w+:)?SignatureMethod\b[^>]*?)Algorithm="[^"]*"', data)
    if not m:
        return None
    return (
        data[: m.start()]
        + m.group(1)
        + b'Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"'
        + data[m.end() :]
    )


def _add_multiple_issuers(data: bytes, rng: random.Random) -> bytes | None:
    """Add extra Issuer at Response level to trigger P70."""
    m = re.search(rb"(<(?:\w+:)?Response\b[^>]*>)", data)
    if not m:
        return None
    extra = b"<saml:Issuer>https://extra.idp</saml:Issuer>"
    existing = data.count(b"<saml:Issuer>") + data.count(b"<Issuer>")
    if existing < 2:
        return data[: m.end()] + extra + data[m.end() :]
    return None


def _mismatch_reference_uri(data: bytes, rng: random.Random) -> bytes | None:
    """Make Reference URI not match signed element ID to trigger P49."""
    m = re.search(rb'(<(?:\w+:)?Reference\b[^>]*?)URI="#([^"]*)"', data)
    if not m:
        return None
    return (
        data[: m.start()]
        + m.group(1)
        + b'URI="#_nonexistent_id_'
        + str(rng.randint(1000, 9999)).encode()
        + b'"'
        + data[m.end() :]
    )


def _set_status_failure(data: bytes, rng: random.Random) -> bytes | None:
    """Set StatusCode to non-success to trigger P95."""
    m = re.search(rb'(<(?:\w+:)?StatusCode\b[^>]*?)Value="[^"]*"', data)
    if not m:
        return None
    return (
        data[: m.start()]
        + m.group(1)
        + b'Value="urn:oasis:names:tc:SAML:2.0:status:Requester"'
        + data[m.end() :]
    )


def _add_prefixlist(data: bytes, rng: random.Random) -> bytes | None:
    """Add InclusiveNamespaces PrefixList to trigger S34."""
    if b"PrefixList" in data:
        return None
    m = re.search(
        rb'(<(?:\w+:)?Transform\s+Algorithm="[^"]*exc-c14n[^"]*")\s*/?>',
        data,
    )
    if not m:
        return None
    return (
        data[: m.start()]
        + m.group(1)
        + b">"
        + b'<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" '
        + b'PrefixList="ds saml"/>'
        + b"</ds:Transform>"
        + data[m.end() :]
    )


# ── Mutation function registry ──────────────────────────────────

MUTATION_FUNCTIONS: dict[str, Callable] = {
    "add_dtd": _add_dtd,
    "remove_dtd": _remove_dtd,
    "set_reference_uri_empty": _set_reference_uri_empty,
    "remove_reference_uri": _remove_reference_uri,
    "add_xpointer_uri": _add_xpointer_uri,
    "add_duplicate_id": _add_duplicate_id,
    "set_enveloping_signature": _set_enveloping_signature,
    "add_with_comments_c14n": _add_with_comments_c14n,
    "switch_c14n_inclusive": _switch_c14n_inclusive,
    "add_base64_transform": _add_base64_transform,
    "remove_enveloped_transform": _remove_enveloped_transform,
    "add_keyvalue": _add_keyvalue,
    "add_x509cert": _add_x509cert,
    "set_version_wrong": _set_version_wrong,
    "remove_response_id": _remove_response_id,
    "add_extra_assertion": _add_extra_assertion,
    "remove_conditions": _remove_conditions,
    "remove_authnstatement": _remove_authnstatement,
    "set_wrong_destination": _set_wrong_destination,
    "set_wrong_audience": _set_wrong_audience,
    "set_wrong_issuer": _set_wrong_issuer,
    "inject_child_in_nameid": _inject_child_in_nameid,
    "set_wrong_subject_method": _set_wrong_subject_method,
    "add_expired_notonorafter": _add_expired_notonorafter,
    "add_future_notbefore": _add_future_notbefore,
    "remove_signature": _remove_signature,
    "set_deprecated_algorithm": _set_deprecated_algorithm,
    "add_multiple_issuers": _add_multiple_issuers,
    "mismatch_reference_uri": _mismatch_reference_uri,
    "set_status_failure": _set_status_failure,
    "add_prefixlist": _add_prefixlist,
}


# ── Branch condition database ──────────────────────────────────
# Built from static analysis of signxml + python3-saml source.
# Line ranges are approximate (±5 lines) for fuzzy matching with coverage traces.

BRANCH_DB: list[BranchCondition] = [
    # ── signxml/processor.py ──
    BranchCondition("signxml", "processor.py", 50, 55, "DTD rejection", "dtd_presence", "add_dtd"),
    BranchCondition("signxml", "processor.py", 50, 55, "DTD bypass", "dtd_presence", "remove_dtd"),
    BranchCondition("signxml", "processor.py", 108, 115, "namespace prefix in tag", "ns_prefix", "add_prefixlist"),
    BranchCondition("signxml", "processor.py", 124, 130, "exc-c14n vs inclusive", "c14n_algorithm", "switch_c14n_inclusive"),
    BranchCondition("signxml", "processor.py", 126, 130, "c14n WithComments", "c14n_algorithm", "add_with_comments_c14n"),
    BranchCondition("signxml", "processor.py", 152, 156, "Reference URI absent", "reference_uri", "remove_reference_uri"),
    BranchCondition("signxml", "processor.py", 154, 158, "Reference URI empty", "reference_uri", "set_reference_uri_empty"),
    BranchCondition("signxml", "processor.py", 156, 160, "Reference URI xpointer", "reference_uri", "add_xpointer_uri"),
    BranchCondition("signxml", "processor.py", 163, 170, "duplicate ID ambiguity", "id_uniqueness", "add_duplicate_id"),

    # ── signxml/verifier.py ──
    BranchCondition("signxml", "verifier.py", 127, 132, "enveloping signature", "sig_structure", "set_enveloping_signature"),
    BranchCondition("signxml", "verifier.py", 210, 215, "InclusiveNamespaces PrefixList", "prefixlist", "add_prefixlist"),
    BranchCondition("signxml", "verifier.py", 227, 235, "enveloped transform", "transform_type", "remove_enveloped_transform"),
    BranchCondition("signxml", "verifier.py", 231, 236, "base64 transform", "transform_type", "add_base64_transform"),
    BranchCondition("signxml", "verifier.py", 262, 270, "KeyValue vs X509 mismatch", "key_material", "add_keyvalue"),
    BranchCondition("signxml", "verifier.py", 289, 297, "forbidden digest algorithm", "algorithm", "set_deprecated_algorithm"),
    BranchCondition("signxml", "verifier.py", 293, 297, "forbidden signature method", "algorithm", "set_deprecated_algorithm"),
    BranchCondition("signxml", "verifier.py", 445, 455, "X509 vs KeyValue path", "key_material", "add_x509cert"),
    BranchCondition("signxml", "verifier.py", 513, 520, "KeyValue/DER absence", "key_material", "add_keyvalue"),
    BranchCondition("signxml", "verifier.py", 532, 540, "reference count mismatch", "reference_count", "add_extra_assertion"),

    # ── python3-saml/response.py ──
    BranchCondition("python3-saml", "response.py", 66, 70, "Version != 2.0", "version", "set_version_wrong"),
    BranchCondition("python3-saml", "response.py", 73, 78, "missing Response ID", "response_id", "remove_response_id"),
    BranchCondition("python3-saml", "response.py", 83, 88, "wrong assertion count", "assertion_count", "add_extra_assertion"),
    BranchCondition("python3-saml", "response.py", 144, 148, "missing Conditions", "conditions_presence", "remove_conditions"),
    BranchCondition("python3-saml", "response.py", 154, 158, "wrong AuthnStatement count", "authnstatement_count", "remove_authnstatement"),
    BranchCondition("python3-saml", "response.py", 189, 204, "wrong Destination", "destination", "set_wrong_destination"),
    BranchCondition("python3-saml", "response.py", 206, 210, "wrong Audience", "audience", "set_wrong_audience"),
    BranchCondition("python3-saml", "response.py", 215, 220, "wrong Issuer", "issuer", "set_wrong_issuer"),
    BranchCondition("python3-saml", "response.py", 227, 232, "expired session", "timestamp", "add_expired_notonorafter"),
    BranchCondition("python3-saml", "response.py", 239, 244, "wrong SubjectConfirmation method", "subject_method", "set_wrong_subject_method"),
    BranchCondition("python3-saml", "response.py", 252, 258, "expired NotOnOrAfter", "timestamp", "add_expired_notonorafter"),
    BranchCondition("python3-saml", "response.py", 256, 262, "future NotBefore", "timestamp", "add_future_notbefore"),
    BranchCondition("python3-saml", "response.py", 274, 280, "assertion signature required", "signature_presence", "remove_signature"),
    BranchCondition("python3-saml", "response.py", 286, 292, "no signature at all", "signature_presence", "remove_signature"),
    BranchCondition("python3-saml", "response.py", 700, 706, "deprecated signature algorithm", "algorithm", "set_deprecated_algorithm"),
    BranchCondition("python3-saml", "response.py", 657, 662, "wrong signed element tag", "sig_structure", "set_enveloping_signature"),
    BranchCondition("python3-saml", "response.py", 681, 688, "Reference URI mismatch", "reference_uri", "mismatch_reference_uri"),
    BranchCondition("python3-saml", "response.py", 404, 412, "multiple Response Issuers", "issuer_count", "add_multiple_issuers"),
    BranchCondition("python3-saml", "response.py", 624, 634, "assertion count validation", "assertion_count", "add_extra_assertion"),

    # ── python3-saml/xml_utils.py (THE VULN) ──
    BranchCondition("python3-saml", "xml_utils.py", 172, 176, "element_text child truncation", "nameid_children", "inject_child_in_nameid"),

    # ── python3-saml/utils.py ──
    BranchCondition("python3-saml", "utils.py", 634, 640, "missing Status", "status_presence", "set_status_failure"),
    BranchCondition("python3-saml", "utils.py", 646, 650, "StatusCode not success", "status_code", "set_status_failure"),
]


def get_mutations_for_uncovered_lines(
    library: str,
    file: str,
    covered_lines: set[int],
    all_lines: set[int] | None = None,
) -> list[BranchCondition]:
    """Find branch conditions whose line ranges overlap uncovered regions.

    Returns conditions where at least one line in [line_start, line_end]
    is NOT in covered_lines.
    """
    results: list[BranchCondition] = []
    for bc in BRANCH_DB:
        if bc.library != library:
            continue
        if bc.file != file:
            continue
        branch_lines = set(range(bc.line_start, bc.line_end + 1))
        if not branch_lines.issubset(covered_lines):
            results.append(bc)
    return results


def get_all_mutations_for_library(library: str) -> list[BranchCondition]:
    """Get all branch conditions for a library."""
    return [bc for bc in BRANCH_DB if bc.library == library]
