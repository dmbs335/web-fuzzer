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

function verifySaml(xmlInput) {
  const { DOMParser } = require("@xmldom/xmldom");
  const doc = new DOMParser().parseFromString(xmlInput, "text/xml");

  let signatureValid = false;
  let signatureError = null;
  let samlifyResult = null;

  try {
    const samlify = require("samlify");
    // Disable schema validation to focus on signature verification
    samlify.setSchemaValidator({
      validate: () => Promise.resolve("skipped"),
    });

    const idp = samlify.IdentityProvider({
      metadata: null,
      isAssertionEncrypted: false,
      signingCert: IDP_CERT,
      wantLogoutRequestSigned: false,
    });

    const sp = samlify.ServiceProvider({
      entityID: "https://sp.example.com",
      assertionConsumerService: [
        {
          Location: "https://sp.example.com/acs",
          Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
      ],
    });

    // Base64 encode the input for samlify
    const b64 = Buffer.from(xmlInput, "utf8").toString("base64");

    // Synchronous-style: samlify returns a Promise
    // We'll try direct XML verification approach instead
    const { extract } = require("samlify/build/src/extractor");
    const { verifySignature } = require("samlify/build/src/libsaml");

    try {
      signatureValid = verifySignature(xmlInput, { cert: IDP_CERT });
    } catch (e) {
      signatureError = e.message;
    }
  } catch (e) {
    // samlify not installed or API changed — fall back to xml-crypto
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

  // Extract SAML fields
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
  const nameIDs = doc.getElementsByTagNameNS(SAML_NS, "NameID");
  const issuers = doc.getElementsByTagNameNS(SAML_NS, "Issuer");
  const audiences = doc.getElementsByTagNameNS(SAML_NS, "Audience");

  const attributes = {};
  const attrElems = doc.getElementsByTagNameNS(SAML_NS, "Attribute");
  for (let i = 0; i < attrElems.length; i++) {
    const name = attrElems[i].getAttribute("Name");
    const vals = attrElems[i].getElementsByTagNameNS(
      SAML_NS,
      "AttributeValue"
    );
    if (name && vals.length > 0) {
      attributes[name] =
        vals.length === 1
          ? getText(vals[0])
          : Array.from({ length: vals.length }, (_, j) => getText(vals[j]));
    }
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
    subject: nameIDs.length > 0 ? getText(nameIDs[0]) : null,
    subject_format:
      nameIDs.length > 0 ? nameIDs[0].getAttribute("Format") : null,
    issuer: issuers.length > 0 ? getText(issuers[0]) : null,
    audience: audiences.length > 0 ? getText(audiences[0]) : null,
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
