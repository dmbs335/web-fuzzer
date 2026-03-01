/**
 * SAML target -- xml-crypto (Node.js XML-DSig library).
 *
 * Verifies XML digital signatures using xml-crypto's SignedXml class
 * and extracts SAML assertion fields.
 *
 * Known vulnerabilities: SAMLStorm (CVE-2025-29775/29774) firstChild bug,
 * XPath scope issues.
 *
 * Usage: node saml_xmlcrypto.js <input_file>
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { SignedXml } = require("xml-crypto");
const { DOMParser } = require("@xmldom/xmldom");

const FIXTURES = path.join(__dirname, "saml_fixtures");
const IDP_CERT = fs.readFileSync(path.join(FIXTURES, "idp_cert.pem"), "utf8");

const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

function getText(elem) {
  if (!elem) return null;
  const t = (elem.textContent || "").trim();
  return t || null;
}

function normSigAlgo(a) {
  const l = a.toLowerCase();
  if (l.includes("hmac")) return a.split("#").pop();
  if (l.includes("sha256")) return "rsa-sha256";
  if (l.includes("sha384")) return "rsa-sha384";
  if (l.includes("sha512")) return "rsa-sha512";
  if (l.includes("sha1")) return "rsa-sha1";
  return a;
}
function normDigestAlgo(a) {
  const l = a.toLowerCase();
  if (l.includes("sha256")) return "sha256";
  if (l.includes("sha384")) return "sha384";
  if (l.includes("sha512")) return "sha512";
  if (l.includes("sha1")) return "sha1";
  if (l.includes("md5")) return "md5";
  return a;
}
function extractAlgorithms(doc) {
  const result = {};
  const sigMethods = doc.getElementsByTagNameNS(DS_NS, "SignatureMethod");
  if (sigMethods.length > 0)
    result.signature = normSigAlgo(sigMethods[0].getAttribute("Algorithm") || "");
  const digestMethods = doc.getElementsByTagNameNS(DS_NS, "DigestMethod");
  if (digestMethods.length > 0)
    result.digest = normDigestAlgo(digestMethods[0].getAttribute("Algorithm") || "");
  return result;
}

function verifySaml(xmlInput) {
  const doc = new DOMParser().parseFromString(xmlInput, "text/xml");

  const signatures = doc.getElementsByTagNameNS(DS_NS, "Signature");
  let signatureValid = false;
  let signatureError = null;

  if (signatures.length > 0) {
    try {
      const sig = new SignedXml();
      sig.keyInfoProvider = {
        getKey: function () {
          return IDP_CERT;
        },
        getKeyInfo: function () {
          return "<X509Data></X509Data>";
        },
      };
      sig.loadSignature(signatures[0]);
      signatureValid = sig.checkSignature(xmlInput);
      if (!signatureValid) {
        signatureError = (sig.validationErrors || []).join("; ");
      }
    } catch (e) {
      signatureError = e.message;
    }
  } else {
    signatureError = "No Signature element found";
  }

  // Extract SAML fields
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
  const nameIDs = doc.getElementsByTagNameNS(SAML_NS, "NameID");
  const issuers = doc.getElementsByTagNameNS(SAML_NS, "Issuer");
  const audiences = doc.getElementsByTagNameNS(SAML_NS, "Audience");

  // Attributes
  const attributes = {};
  const attrElems = doc.getElementsByTagNameNS(SAML_NS, "Attribute");
  for (let i = 0; i < attrElems.length; i++) {
    const name = attrElems[i].getAttribute("Name");
    const vals = attrElems[i].getElementsByTagNameNS(
      SAML_NS,
      "AttributeValue"
    );
    if (name && vals.length > 0) {
      if (vals.length === 1) {
        attributes[name] = getText(vals[0]);
      } else {
        const arr = [];
        for (let j = 0; j < vals.length; j++) arr.push(getText(vals[j]));
        attributes[name] = arr;
      }
    }
  }

  const result = {
    signature_valid: signatureValid,
    signature_error: signatureError,
    subject: nameIDs.length > 0 ? getText(nameIDs[0]) : null,
    subject_format:
      nameIDs.length > 0 ? nameIDs[0].getAttribute("Format") : null,
    issuer: issuers.length > 0 ? getText(issuers[0]) : null,
    audience: audiences.length > 0 ? getText(audiences[0]) : null,
    attributes: attributes,
    assertion_count: assertions.length,
    algorithms: extractAlgorithms(doc),
  };
  return JSON.stringify(result);
}

// -- Main --
const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node saml_xmlcrypto.js <input_file>\n");
  process.exit(2);
}

try {
  const input = fs.readFileSync(inputPath, "utf8");
  const result = verifySaml(input);
  process.stdout.write(result + "\n");
  process.exit(0);
} catch (err) {
  process.stderr.write("REJECT: " + err.message + "\n");
  process.exit(1);
}
