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
const crypto = require("crypto");
const { XMLSerializer } = require("@xmldom/xmldom");

const FIXTURES = path.join(__dirname, "saml_fixtures");
const IDP_CERT = fs.readFileSync(path.join(FIXTURES, "idp_cert.pem"), "utf8");
const IDP_CERT_BARE = IDP_CERT
  .replace(/-----BEGIN CERTIFICATE-----/, "")
  .replace(/-----END CERTIFICATE-----/, "")
  .replace(/\n/g, "");

const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

// Build samlify IdP metadata once at module load
let _idpMeta = null;
function getIdpMeta() {
  if (_idpMeta) return _idpMeta;
  const samlify = require("samlify");
  samlify.setSchemaValidator({ validate: () => Promise.resolve("skipped") });
  const idp = samlify.IdentityProvider({
    metadata: `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>${IDP_CERT_BARE}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`,
  });
  _idpMeta = idp.entityMeta;
  return _idpMeta;
}

function getText(elem) {
  if (!elem) return null;
  const t = elem.textContent || "";
  return t || null;
}

function firstReferenceUri(doc) {
  const refs = doc.getElementsByTagNameNS(DS_NS, "Reference");
  for (let i = 0; i < refs.length; i++) {
    const uri = refs[i].getAttribute("URI") || "";
    if (uri) return uri;
  }
  return null;
}

function countReferences(doc) {
  return doc.getElementsByTagNameNS(DS_NS, "Reference").length;
}

function stableXmlHash(node) {
  if (!node) return null;
  const serialized = new XMLSerializer().serializeToString(node);
  return crypto.createHash("sha256").update(serialized).digest("hex").slice(0, 16);
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
  const { DOMParser } = require("@xmldom/xmldom");
  const SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
  const doc = new DOMParser().parseFromString(xmlInput, "text/xml");

  let signatureValid = false;
  let signatureError = null;
  let validatedSignatureIndex = -1;

  // samlify rejects non-Success StatusCode in parseLoginResponse
  const statusCodes = doc.getElementsByTagNameNS(SAMLP_NS, "StatusCode");
  if (statusCodes.length > 0) {
    const statusValue = statusCodes[0].getAttribute("Value") || "";
    if (!statusValue.endsWith(":Success")) {
      signatureError = "Non-success StatusCode: " + statusValue;
      // Don't even attempt signature verification — matches samlify behavior
      const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
      const selection = findSignedAssertion(doc);
      return buildResult(doc, assertions, selection, false, signatureError, -1);
    }
  }

  try {
    const libsaml = require("samlify/build/src/libsaml").default;
    const meta = getIdpMeta();

    try {
      const result = libsaml.verifySignature(xmlInput, { metadata: meta });
      signatureValid = Array.isArray(result) ? result[0] === true : !!result;
      if (signatureValid) validatedSignatureIndex = 0;
    } catch (e) {
      signatureError = e.message;
    }
  } catch (e) {
    signatureError = "samlify: " + e.message;
  }

  // Extract SAML fields from the signed assertion (not from full document)
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");
  const selection = findSignedAssertion(doc);
  const signedAssertion = selection.assertion;

  // Verify that the signature's Reference URI covers the selected assertion
  if (signatureValid && signedAssertion) {
    const sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
    if (sigs.length > 0) {
      const refs = sigs[0].getElementsByTagNameNS(DS_NS, "Reference");
      if (refs.length > 0) {
        const refUri = (refs[0].getAttribute("URI") || "").replace(/^#/, "");
        const assertId = signedAssertion.getAttribute("ID") || "";
        if (refUri && assertId && refUri !== assertId) {
          signatureValid = false;
          signatureError = "Signature covers '" + refUri + "' but assertion is '" + assertId + "'";
        }
      }
    }
  }

  return buildResult(doc, assertions, selection, signatureValid, signatureError, validatedSignatureIndex);
}

function buildResult(doc, assertions, selection, signatureValid, signatureError, validatedSignatureIndex) {
  const signedAssertion = selection ? selection.assertion : null;
  let subject = null, subjectFormat = null, issuer = null, audience = null;
  let issuerSource = "none";
  let audienceCount = 0;
  let assertionId = null;
  const attributes = {};
  let nameIdCount = 0;
  let emptyNameIdSemantics = "missing";
  const referenceTargetId =
    selection && selection.referenceUri && selection.referenceUri.startsWith("#")
      ? selection.referenceUri.substring(1)
      : null;

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
    if (issuer) issuerSource = "response";
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
    selected_assertion_index: selection ? selection.selectedAssertionIndex : null,
    selection_mode: selection ? selection.selectionMode : "no_assertion",
    reference_uri: selection ? selection.referenceUri : null,
    reference_matches_selected_assertion: referenceMatchesSelectedAssertion,
    signature_count: doc.getElementsByTagNameNS(DS_NS, "Signature").length,
    issuer_source: issuerSource,
    audience_count: audienceCount,
    nameid_count: nameIdCount,
    empty_nameid_semantics: emptyNameIdSemantics,
    algorithms,
    validated_reference_uri: signatureValid && selection ? selection.referenceUri : null,
    validated_reference_count: countReferences(doc),
    validated_node_tag: validatedNodeTag,
    validated_node_id: validatedNodeId,
    validated_node_xpath: validatedNodeTag,
    id_resolution_mode: selection ? selection.selectionMode : "no_assertion",
    resolved_id_attribute: resolvedIdAttribute(validatedNode),
    transform_chain: extractTransformChain(doc),
    c14n_method: firstAlgorithmAttr(doc, "CanonicalizationMethod"),
    signature_method: firstAlgorithmAttr(doc, "SignatureMethod"),
    validated_signature_algorithm: validatedSignatureIndex >= 0
      ? (() => {
          const sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
          if (sigs.length <= validatedSignatureIndex) return null;
          const sm = sigs[validatedSignatureIndex].getElementsByTagNameNS(DS_NS, "SignatureMethod");
          return sm.length > 0 ? sm[0].getAttribute("Algorithm") || null : null;
        })()
      : null,
    digest_method: firstAlgorithmAttr(doc, "DigestMethod"),
    digest_input_hash: stableXmlHash(validatedNode),
    signed_info_hash: signedInfoHash(doc),
    key_source: "configured_cert",
    keyinfo_present: keyInfo.present,
    keyinfo_type: keyInfo.type,
    signature_element_count: doc.getElementsByTagNameNS(DS_NS, "Signature").length,
    reference_element_count: countReferences(doc),
  });
}

module.exports = { verifySaml };

// -- Main (CLI only) --
if (require.main === module) {
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
}
