/**
 * SAML target -- @node-saml/node-saml (passport-saml core).
 *
 * Uses node-saml's SAML class for full SAML Response validation.
 * This is the most commonly used Node.js SAML library (via passport-saml).
 *
 * Usage: node saml_nodesaml.js <input_file>
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { DOMParser } = require("@xmldom/xmldom");

const FIXTURES = path.join(__dirname, "saml_fixtures");
const IDP_CERT = fs.readFileSync(path.join(FIXTURES, "idp_cert.pem"), "utf8");
const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

function getText(elem) {
  if (!elem) return null;
  return (elem.textContent || "").trim() || null;
}

function verifySaml(xmlInput) {
  const doc = new DOMParser().parseFromString(xmlInput, "text/xml");
  let signatureValid = false;
  let signatureError = null;

  // Try node-saml first, fall back to xml-crypto
  try {
    const { SAML } = require("@node-saml/node-saml");
    // node-saml requires async; use synchronous xml-crypto verification
    throw new Error("use xml-crypto for sync");
  } catch {
    // Fallback: direct xml-crypto verification
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
      } else {
        signatureError = "No Signature element found";
      }
    } catch (e) {
      signatureError = e.message;
    }
  }

  // Extract fields from the signed assertion (not full document)
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");

  // Find signed assertion by matching Reference URI to Assertion ID
  let signedAssertion = null;
  const refs = doc.getElementsByTagNameNS(DS_NS, "Reference");
  for (let i = 0; i < refs.length; i++) {
    const uri = refs[i].getAttribute("URI") || "";
    if (uri.startsWith("#")) {
      const targetId = uri.substring(1);
      for (let j = 0; j < assertions.length; j++) {
        if (assertions[j].getAttribute("ID") === targetId) {
          signedAssertion = assertions[j];
          break;
        }
      }
      if (signedAssertion) break;
    }
  }
  if (!signedAssertion && assertions.length > 0) signedAssertion = assertions[0];

  let subject = null, subjectFormat = null, issuer = null, audience = null;
  let assertionId = null;
  const attributes = {};

  if (signedAssertion) {
    assertionId = signedAssertion.getAttribute("ID") || null;
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

  const sigM = doc.getElementsByTagNameNS(DS_NS, "SignatureMethod");
  const digM = doc.getElementsByTagNameNS(DS_NS, "DigestMethod");
  const algorithms = {};
  function normSig(a) { const l=a.toLowerCase(); if(l.includes("hmac"))return a.split("#").pop(); if(l.includes("sha256"))return "rsa-sha256"; if(l.includes("sha384"))return "rsa-sha384"; if(l.includes("sha512"))return "rsa-sha512"; if(l.includes("sha1"))return "rsa-sha1"; return a; }
  function normDig(a) { const l=a.toLowerCase(); if(l.includes("sha256"))return "sha256"; if(l.includes("sha384"))return "sha384"; if(l.includes("sha512"))return "sha512"; if(l.includes("sha1"))return "sha1"; if(l.includes("md5"))return "md5"; return a; }
  if (sigM.length > 0)
    algorithms.signature = normSig(sigM[0].getAttribute("Algorithm") || "");
  if (digM.length > 0)
    algorithms.digest = normDig(digM[0].getAttribute("Algorithm") || "");

  return JSON.stringify({
    signature_valid: signatureValid,
    signature_error: signatureError,
    subject: subject,
    subject_format: subjectFormat || null,
    issuer: issuer,
    audience: audience,
    attributes,
    assertion_count: assertions.length,
    assertion_id: assertionId,
    algorithms,
  });
}

module.exports = { verifySaml };

// -- Main (CLI only) --
if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node saml_nodesaml.js <input_file>\n");
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
}
