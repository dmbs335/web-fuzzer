/**
 * SAML target -- samlify (Node.js SAML 2.0 library).
 *
 * Uses samlify's ServiceProvider to validate SAML Responses.
 * Known vulnerabilities: CVE-2025-47949 (XPath scope failure).
 *
 * Usage: node saml_samlify.js <input_file>
 */

"use strict";

const fs = require("fs");
const path = require("path");

const FIXTURES = path.join(__dirname, "saml_fixtures");
const IDP_CERT = fs.readFileSync(path.join(FIXTURES, "idp_cert.pem"), "utf8");

const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

function getText(elem) {
  if (!elem) return null;
  const t = (elem.textContent || "").trim();
  return t || null;
}

/**
 * Find the assertion targeted by the signature's Reference URI.
 * Falls back to the first assertion if no matching reference found.
 */
function findSignedAssertion(doc) {
  const refs = doc.getElementsByTagNameNS(DS_NS, "Reference");
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
  for (let i = 0; i < refs.length; i++) {
    const uri = refs[i].getAttribute("URI") || "";
    if (uri.startsWith("#")) {
      const targetId = uri.substring(1);
      for (let j = 0; j < assertions.length; j++) {
        if (assertions[j].getAttribute("ID") === targetId) {
          return assertions[j];
        }
      }
    }
  }
  return assertions.length > 0 ? assertions[0] : null;
}

function verifySaml(xmlInput) {
  const { DOMParser } = require("@xmldom/xmldom");
  const doc = new DOMParser().parseFromString(xmlInput, "text/xml");

  let signatureValid = false;
  let signatureError = null;

  try {
    const samlify = require("samlify");
    samlify.setSchemaValidator({
      validate: () => Promise.resolve("skipped"),
    });

    const { verifySignature } = require("samlify/build/src/libsaml");

    try {
      signatureValid = verifySignature(xmlInput, { cert: IDP_CERT });
    } catch (e) {
      signatureError = e.message;
    }
  } catch (e) {
    signatureError = "samlify unavailable: " + e.message;
    try {
      const { SignedXml } = require("xml-crypto");
      const sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
      if (sigs.length > 0) {
        const sig = new SignedXml();
        sig.keyInfoProvider = {
          getKey: () => IDP_CERT,
          getKeyInfo: () => "",
        };
        sig.loadSignature(sigs[0]);
        signatureValid = sig.checkSignature(xmlInput);
        if (!signatureValid)
          signatureError = (sig.validationErrors || []).join("; ");
        else signatureError = null;
      }
    } catch (e2) {
      signatureError = e2.message;
    }
  }

  // Extract SAML fields from the signed assertion (not from full document)
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
  const signedAssertion = findSignedAssertion(doc);

  let subject = null, subjectFormat = null, issuer = null, audience = null;
  const attributes = {};

  if (signedAssertion) {
    const nameIDs = signedAssertion.getElementsByTagNameNS(SAML_NS, "NameID");
    if (nameIDs.length > 0) {
      subject = getText(nameIDs[0]);
      subjectFormat = nameIDs[0].getAttribute("Format");
    }

    const issuers = signedAssertion.getElementsByTagNameNS(SAML_NS, "Issuer");
    issuer = issuers.length > 0 ? getText(issuers[0]) : null;

    const audiences = signedAssertion.getElementsByTagNameNS(SAML_NS, "Audience");
    audience = audiences.length > 0 ? getText(audiences[0]) : null;

    const attrElems = signedAssertion.getElementsByTagNameNS(SAML_NS, "Attribute");
    for (let i = 0; i < attrElems.length; i++) {
      const name = attrElems[i].getAttribute("Name");
      const vals = attrElems[i].getElementsByTagNameNS(SAML_NS, "AttributeValue");
      if (name && vals.length > 0) {
        attributes[name] =
          vals.length === 1
            ? getText(vals[0])
            : Array.from({ length: vals.length }, (_, j) => getText(vals[j]));
      }
    }
  }

  // Response-level issuer as fallback
  if (!issuer) {
    const respIssuers = doc.getElementsByTagNameNS(SAML_NS, "Issuer");
    if (respIssuers.length > 0) issuer = getText(respIssuers[0]);
  }

  const sigMethods = doc.getElementsByTagNameNS(DS_NS, "SignatureMethod");
  const digestMethods = doc.getElementsByTagNameNS(DS_NS, "DigestMethod");
  const algorithms = {};
  function normSig(a) { const l=a.toLowerCase(); if(l.includes("hmac"))return a.split("#").pop(); if(l.includes("sha256"))return "rsa-sha256"; if(l.includes("sha384"))return "rsa-sha384"; if(l.includes("sha512"))return "rsa-sha512"; if(l.includes("sha1"))return "rsa-sha1"; return a; }
  function normDig(a) { const l=a.toLowerCase(); if(l.includes("sha256"))return "sha256"; if(l.includes("sha384"))return "sha384"; if(l.includes("sha512"))return "sha512"; if(l.includes("sha1"))return "sha1"; if(l.includes("md5"))return "md5"; return a; }
  if (sigMethods.length > 0)
    algorithms.signature = normSig(sigMethods[0].getAttribute("Algorithm") || "");
  if (digestMethods.length > 0)
    algorithms.digest = normDig(digestMethods[0].getAttribute("Algorithm") || "");

  return JSON.stringify({
    signature_valid: signatureValid,
    signature_error: signatureError,
    subject: subject,
    subject_format: subjectFormat || null,
    issuer: issuer,
    audience: audience,
    attributes,
    assertion_count: assertions.length,
    algorithms,
  });
}

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node saml_samlify.js <input_file>\n");
  process.exit(2);
}

try {
  const input = fs.readFileSync(inputPath, "utf8");
  process.stdout.write(verifySaml(input) + "\n");
  process.exit(0);
} catch (err) {
  process.stderr.write("REJECT: " + err.message + "\n");
  process.exit(1);
}
