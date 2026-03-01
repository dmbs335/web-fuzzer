/**
 * samlify persistent module for SAML verification.
 * Exports process(input) for use with persistent_wrapper.js.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const { DOMParser } = require("@xmldom/xmldom");

const FIXTURES = path.join(__dirname, "saml_fixtures");
const IDP_CERT = fs.readFileSync(path.join(FIXTURES, "idp_cert.pem"), "utf8");
const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

let verifySig;
try {
  const { verifySignature } = require("samlify/build/src/libsaml");
  verifySig = (xml) => verifySignature(xml, { cert: IDP_CERT });
} catch {
  const { SignedXml } = require("xml-crypto");
  verifySig = (xml) => {
    const doc = new DOMParser().parseFromString(xml, "text/xml");
    const sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
    if (sigs.length === 0) return false;
    const sig = new SignedXml();
    sig.keyInfoProvider = { getKey: () => IDP_CERT, getKeyInfo: () => "" };
    sig.loadSignature(sigs[0]);
    return sig.checkSignature(xml);
  };
}

function getText(elem) {
  if (!elem) return null;
  return (elem.textContent || "").trim() || null;
}

module.exports.process = function (input) {
  try {
    const doc = new DOMParser().parseFromString(input, "text/xml");
    let signatureValid = false;
    let signatureError = null;

    try {
      signatureValid = verifySig(input);
      if (!signatureValid) signatureError = "Signature verification failed";
    } catch (e) {
      signatureError = e.message;
    }

    const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
    const nameIDs = doc.getElementsByTagNameNS(SAML_NS, "NameID");
    const issuers = doc.getElementsByTagNameNS(SAML_NS, "Issuer");
    const audiences = doc.getElementsByTagNameNS(SAML_NS, "Audience");
    const attributes = {};
    const attrElems = doc.getElementsByTagNameNS(SAML_NS, "Attribute");
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

    const sigM = doc.getElementsByTagNameNS(DS_NS, "SignatureMethod");
    const digM = doc.getElementsByTagNameNS(DS_NS, "DigestMethod");
    const algorithms = {};
    function normSig(a) { const l=a.toLowerCase(); if(l.includes("hmac"))return a.split("#").pop(); if(l.includes("sha256"))return "rsa-sha256"; if(l.includes("sha384"))return "rsa-sha384"; if(l.includes("sha512"))return "rsa-sha512"; if(l.includes("sha1"))return "rsa-sha1"; return a; }
    function normDig(a) { const l=a.toLowerCase(); if(l.includes("sha256"))return "sha256"; if(l.includes("sha384"))return "sha384"; if(l.includes("sha512"))return "sha512"; if(l.includes("sha1"))return "sha1"; if(l.includes("md5"))return "md5"; return a; }
    if (sigM.length > 0)
      algorithms.signature = normSig(sigM[0].getAttribute("Algorithm") || "");
    if (digM.length > 0)
      algorithms.digest = normDig(digM[0].getAttribute("Algorithm") || "");

    return {
      output: JSON.stringify({
        signature_valid: signatureValid,
        signature_error: signatureError,
        subject: nameIDs.length > 0 ? getText(nameIDs[0]) : null,
        subject_format: nameIDs.length > 0 ? nameIDs[0].getAttribute("Format") : null,
        issuer: issuers.length > 0 ? getText(issuers[0]) : null,
        audience: audiences.length > 0 ? getText(audiences[0]) : null,
        attributes,
        assertion_count: assertions.length,
        algorithms,
      }),
      exitCode: 0,
    };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
