"""Test lxml DTD ATTLIST namespace override behavior."""
from lxml import etree

# Test 1: parent has wrong NS, child inherits, DTD provides correct
test1 = (
    b'<!DOCTYPE root ['
    b'<!ATTLIST ns:child xmlns:ns CDATA "http://correct.com">'
    b']>'
    b'<root xmlns:ns="http://wrong.com">'
    b'<ns:child>test</ns:child>'
    b'</root>'
)
parsed1 = etree.fromstring(test1)
child1 = parsed1[0]
print(f"Test 1 (inherit wrong, DTD correct):")
print(f"  child tag: {child1.tag}")
print(f"  child nsmap: {child1.nsmap}")

# Test 2: child has explicit wrong NS, DTD has correct
test2 = (
    b'<!DOCTYPE root ['
    b'<!ATTLIST ns:child xmlns:ns CDATA "http://correct.com">'
    b']>'
    b'<root xmlns:ns="http://wrong.com">'
    b'<ns:child xmlns:ns="http://also-wrong.com">test</ns:child>'
    b'</root>'
)
parsed2 = etree.fromstring(test2)
child2 = parsed2[0]
print(f"\nTest 2 (explicit wrong on child, DTD correct):")
print(f"  child tag: {child2.tag}")
print(f"  child nsmap: {child2.nsmap}")

# Test 3: No NS on parent, DTD provides default for child
test3 = (
    b'<!DOCTYPE root ['
    b'<!ATTLIST ns:child xmlns:ns CDATA "http://correct.com">'
    b']>'
    b'<root>'
    b'<ns:child>test</ns:child>'
    b'</root>'
)
try:
    parsed3 = etree.fromstring(test3)
    child3 = parsed3[0]
    print(f"\nTest 3 (no parent NS, DTD provides):")
    print(f"  child tag: {child3.tag}")
    print(f"  child nsmap: {child3.nsmap}")
except Exception as e:
    print(f"\nTest 3: ERROR {e}")

# Test 4: c14n comparison with DTD override
# This simulates the attack: c14n produces different output with DTD
print("\n=== C14N comparison ===")

# Without DTD
xml_nodtd = b'<root xmlns:ns="http://wrong.com"><ns:child>test</ns:child></root>'
tree_nodtd = etree.fromstring(xml_nodtd)
c14n_nodtd = etree.tostring(tree_nodtd, method="c14n2")
print(f"Without DTD c14n: {c14n_nodtd}")

# With DTD override
xml_dtd = (
    b'<!DOCTYPE root ['
    b'<!ATTLIST ns:child xmlns:ns CDATA "http://correct.com">'
    b']>'
    b'<root xmlns:ns="http://wrong.com"><ns:child>test</ns:child></root>'
)
tree_dtd = etree.fromstring(xml_dtd)
c14n_dtd = etree.tostring(tree_dtd, method="c14n2")
print(f"With DTD c14n:    {c14n_dtd}")
print(f"Tags match: nodtd={tree_nodtd[0].tag} vs dtd={tree_dtd[0].tag}")

# Test 5: exc-c14n specifically
from io import BytesIO

# Exclusive c14n
ec14n_nodtd = tree_nodtd.getroottree().getroot()
ec14n_dtd = tree_dtd.getroottree().getroot()

# Serialize with exclusive c14n
nodtd_bytes = etree.tostring(ec14n_nodtd[0], method="c14n", exclusive=True)
dtd_bytes = etree.tostring(ec14n_dtd[0], method="c14n", exclusive=True)
print(f"\nExc-c14n child (no DTD): {nodtd_bytes}")
print(f"Exc-c14n child (DTD):    {dtd_bytes}")
print(f"Same? {nodtd_bytes == dtd_bytes}")

# Test 6: What happens with assertion-like structure
print("\n=== SAML-like structure ===")
saml_nodtd = (
    b'<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion">'
    b'<saml:Assertion Version="2.0">'
    b'<saml:NameID>test</saml:NameID>'
    b'</saml:Assertion>'
    b'</Response>'
)
saml_dtd = (
    b'<!DOCTYPE Response ['
    b'<!ATTLIST saml:Assertion xmlns:saml CDATA "urn:oasis:names:tc:SAML:2.0:assertion">'
    b']>'
    b'<Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:Assertion">'
    b'<saml:Assertion Version="2.0">'
    b'<saml:NameID>test</saml:NameID>'
    b'</saml:Assertion>'
    b'</Response>'
)

t_nodtd = etree.fromstring(saml_nodtd)
t_dtd = etree.fromstring(saml_dtd)

# Check what namespace the Assertion element is in
print(f"No DTD - Assertion tag: {t_nodtd[0].tag}")
print(f"No DTD - NameID tag: {t_nodtd[0][0].tag}")
print(f"DTD    - Assertion tag: {t_dtd[0].tag}")
print(f"DTD    - NameID tag: {t_dtd[0][0].tag}")

# exc-c14n of the Assertion element
ec14n_saml_nodtd = etree.tostring(t_nodtd[0], method="c14n", exclusive=True)
ec14n_saml_dtd = etree.tostring(t_dtd[0], method="c14n", exclusive=True)
print(f"\nExc-c14n Assertion (no DTD): {ec14n_saml_nodtd[:150]}")
print(f"Exc-c14n Assertion (DTD):    {ec14n_saml_dtd[:150]}")
