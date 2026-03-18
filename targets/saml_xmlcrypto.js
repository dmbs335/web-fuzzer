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
const crypto = require("crypto");
const { SignedXml } = require("xml-crypto");
const { DOMParser, XMLSerializer } = require("@xmldom/xmldom");

const FIXTURES = path.join(__dirname, "saml_fixtures");
const IDP_CERT = fs.readFileSync(path.join(FIXTURES, "idp_cert.pem"), "utf8");

const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

function getText(elem) {
  if (!elem) return null;
  const t = elem.textContent || "";
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

function countReferences(doc) {
  return doc.getElementsByTagNameNS(DS_NS, "Reference").length;
}

function firstReferenceUri(doc) {
  const refs = doc.getElementsByTagNameNS(DS_NS, "Reference");
  for (let i = 0; i < refs.length; i++) {
    const uri = refs[i].getAttribute("URI") || "";
    if (uri) return uri;
  }
  return null;
}

function stableXmlHash(node) {
  if (!node) return null;
  const serialized = new XMLSerializer().serializeToString(node);
  return crypto.createHash("sha256").update(serialized).digest("hex").slice(0, 16);
}

function canonicalAssertionHex(node) {
  if (!node) return null;
  try {
    const serialized = new XMLSerializer().serializeToString(node);
    const buf = Buffer.from(serialized, "utf8");
    return buf.slice(0, 32).toString("hex");
  } catch {
    return null;
  }
}

function extractTransformChain(doc) {
  const refs = doc.getElementsByTagNameNS(DS_NS, "Reference");
  if (refs.length === 0) return [];
  const transforms = refs[0].getElementsByTagNameNS(DS_NS, "Transform");
  const chain = [];
  for (let i = 0; i < transforms.length; i++) {
    const algo = transforms[i].getAttribute("Algorithm") || "";
    if (algo) chain.push(algo);
  }
  return chain;
}

function firstAlgorithmAttr(doc, localName) {
  const elems = doc.getElementsByTagNameNS(DS_NS, localName);
  return elems.length > 0 ? elems[0].getAttribute("Algorithm") || null : null;
}

function signedInfoHash(doc) {
  const elems = doc.getElementsByTagNameNS(DS_NS, "SignedInfo");
  return elems.length > 0 ? stableXmlHash(elems[0]) : null;
}

function keyInfoType(doc) {
  const keyInfos = doc.getElementsByTagNameNS(DS_NS, "KeyInfo");
  if (keyInfos.length === 0) return { present: false, type: "none" };
  const keyInfo = keyInfos[0];
  const childCount = keyInfo.childNodes ? keyInfo.childNodes.length : 0;
  if (childCount === 0 && !String(keyInfo.textContent || "").trim()) {
    return { present: true, type: "empty" };
  }
  if (keyInfo.getElementsByTagNameNS(DS_NS, "X509Certificate").length > 0) {
    return { present: true, type: "x509data" };
  }
  if (keyInfo.getElementsByTagNameNS(DS_NS, "KeyValue").length > 0) {
    return { present: true, type: "keyvalue" };
  }
  return { present: true, type: "unknown" };
}

function resolvedIdAttribute(elem) {
  if (!elem) return null;
  if (elem.getAttribute("ID")) return "ID";
  if (elem.getAttribute("Id")) return "Id";
  if (elem.getAttribute("xml:id")) return "xml:id";
  return null;
}

function nameIdObservability(assertion) {
  if (!assertion) return { count: 0, semantics: "missing" };
  const nameIDs = assertion.getElementsByTagNameNS(SAML_NS, "NameID");
  if (nameIDs.length === 0) return { count: 0, semantics: "missing" };
  return {
    count: nameIDs.length,
    semantics: getText(nameIDs[0]) === null ? "empty" : "nonempty",
  };
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
          return {
            assertion: assertions[j],
            selectionMode: "reference_uri",
            selectedAssertionIndex: j,
            referenceUri: uri,
          };
        }
      }
    }
  }
  return assertions.length > 0
    ? {
        assertion: assertions[0],
        selectionMode: "first_assertion_fallback",
        selectedAssertionIndex: 0,
        referenceUri: firstReferenceUri(doc),
      }
    : {
        assertion: null,
        selectionMode: "no_assertion",
        selectedAssertionIndex: null,
        referenceUri: firstReferenceUri(doc),
      };
}

function verifySaml(xmlInput) {
  const doc = new DOMParser().parseFromString(xmlInput, "text/xml");

  const signatures = doc.getElementsByTagNameNS(DS_NS, "Signature");
  let signatureValid = false;
  let signatureError = null;
  let validatedSignatureIndex = -1;

  if (signatures.length > 0) {
    try {
      const sig = new SignedXml({ publicCert: IDP_CERT });
      sig.loadSignature(signatures[0]);
      signatureValid = sig.checkSignature(xmlInput);
      if (!signatureValid) {
        signatureError = (sig.validationErrors || []).join("; ");
      } else {
        validatedSignatureIndex = 0;
      }
    } catch (e) {
      signatureError = e.message;
    }
  } else {
    signatureError = "No Signature element found";
  }

  // Extract SAML fields from the signed assertion (not from full document)
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
  const selection = findSignedAssertion(doc);
  const signedAssertion = selection.assertion;
  const referenceTargetId =
    selection.referenceUri && selection.referenceUri.startsWith("#")
      ? selection.referenceUri.substring(1)
      : null;

  // Verify that the signature's Reference URI covers the selected assertion
  if (signatureValid && signedAssertion) {
    const refs = doc.getElementsByTagNameNS(DS_NS, "Reference");
    if (refs.length > 0) {
      const refUri = (refs[0].getAttribute("URI") || "").replace(/^#/, "");
      const assertId = signedAssertion.getAttribute("ID") || "";
      if (refUri && assertId && refUri !== assertId) {
        signatureValid = false;
        signatureError = "Signature covers '" + refUri + "' but assertion is '" + assertId + "'";
      }
    }
  }

  let subject = null, subjectFormat = null, issuer = null, audience = null;
  let issuerSource = "none";
  let audienceCount = 0;
  let assertionId = null;
  const attributes = {};
  let nameIdCount = 0;
  let emptyNameIdSemantics = "missing";

  if (signedAssertion) {
    assertionId = signedAssertion.getAttribute("ID") || null;
    const nameIDs = signedAssertion.getElementsByTagNameNS(SAML_NS, "NameID");
    if (nameIDs.length > 0) {
      subject = getText(nameIDs[0]);
      subjectFormat = nameIDs[0].getAttribute("Format");
    }
    const nameIdObs = nameIdObservability(signedAssertion);
    nameIdCount = nameIdObs.count;
    emptyNameIdSemantics = nameIdObs.semantics;

    const issuers = signedAssertion.getElementsByTagNameNS(SAML_NS, "Issuer");
    issuer = issuers.length > 0 ? getText(issuers[0]) : null;
    if (issuer) issuerSource = "assertion";

    const audiences = signedAssertion.getElementsByTagNameNS(SAML_NS, "Audience");
    audienceCount = audiences.length;
    audience = audiences.length > 0 ? getText(audiences[0]) : null;

    const attrElems = signedAssertion.getElementsByTagNameNS(SAML_NS, "Attribute");
    for (let i = 0; i < attrElems.length; i++) {
      const name = attrElems[i].getAttribute("Name");
      const vals = attrElems[i].getElementsByTagNameNS(SAML_NS, "AttributeValue");
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
  }

  // Response-level issuer as fallback
  if (!issuer) {
    const respIssuers = doc.getElementsByTagNameNS(SAML_NS, "Issuer");
    if (respIssuers.length > 0) issuer = getText(respIssuers[0]);
    if (issuer) issuerSource = "response";
  }

  const referenceMatchesSelectedAssertion =
    referenceTargetId && assertionId ? referenceTargetId === assertionId : null;
  const keyInfo = keyInfoType(doc);
  const validatedNode = signatureValid ? signedAssertion : null;
  const validatedNodeTag = validatedNode ? validatedNode.localName : null;
  const validatedNodeId = validatedNode
    ? validatedNode.getAttribute("ID") ||
      validatedNode.getAttribute("Id") ||
      validatedNode.getAttribute("xml:id") ||
      null
    : null;

  // Intermediate processing fields
  const transformChain = extractTransformChain(doc);
  const c14nMethod = firstAlgorithmAttr(doc, "CanonicalizationMethod");
  const c14nMethodUsed = signatureValid ? c14nMethod : null;

  let referenceResolutionMode;
  if (referenceTargetId && assertionId) {
    referenceResolutionMode = referenceTargetId === assertionId
      ? "uri_id_match" : "uri_id_mismatch";
  } else if (selection.referenceUri) {
    referenceResolutionMode = "uri_no_target";
  } else if (assertions.length > 0) {
    referenceResolutionMode = "fallback_first";
  } else {
    referenceResolutionMode = "no_reference";
  }

  const result = {
    signature_valid: signatureValid,
    signature_error: signatureError,
    subject: subject,
    subject_format: subjectFormat || null,
    issuer: issuer,
    audience: audience,
    attributes: attributes,
    assertion_count: assertions.length,
    assertion_id: assertionId,
    selected_assertion_index: selection.selectedAssertionIndex,
    selection_mode: selection.selectionMode,
    reference_uri: selection.referenceUri,
    reference_matches_selected_assertion: referenceMatchesSelectedAssertion,
    signature_count: signatures.length,
    issuer_source: issuerSource,
    audience_count: audienceCount,
    nameid_count: nameIdCount,
    empty_nameid_semantics: emptyNameIdSemantics,
    algorithms: extractAlgorithms(doc),
    validated_reference_uri: signatureValid ? selection.referenceUri : null,
    validated_reference_count: countReferences(doc),
    validated_node_tag: validatedNodeTag,
    validated_node_id: validatedNodeId,
    validated_node_xpath: validatedNodeTag,
    id_resolution_mode: selection.selectionMode,
    resolved_id_attribute: resolvedIdAttribute(validatedNode),
    transform_chain: transformChain,
    transform_chain_length: transformChain.length,
    c14n_method: c14nMethod,
    c14n_method_used: c14nMethodUsed,
    signature_method: firstAlgorithmAttr(doc, "SignatureMethod"),
    validated_signature_algorithm: validatedSignatureIndex >= 0
      ? (() => {
          const valSig = signatures[validatedSignatureIndex];
          const sm = valSig.getElementsByTagNameNS(DS_NS, "SignatureMethod");
          return sm.length > 0 ? sm[0].getAttribute("Algorithm") || null : null;
        })()
      : null,
    digest_method: firstAlgorithmAttr(doc, "DigestMethod"),
    digest_input_hash: stableXmlHash(validatedNode),
    signed_info_hash: signedInfoHash(doc),
    key_source: "configured_cert",
    keyinfo_present: keyInfo.present,
    keyinfo_type: keyInfo.type,
    signature_element_count: signatures.length,
    reference_element_count: countReferences(doc),
    canonical_assertion_hex: canonicalAssertionHex(signedAssertion),
    reference_resolution_mode: referenceResolutionMode,
  };
  return JSON.stringify(result);
}

module.exports = { verifySaml };

// -- Main (CLI only) --
if (require.main === module) {
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
}
