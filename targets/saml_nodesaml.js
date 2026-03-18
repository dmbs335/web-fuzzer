/**
 * SAML target -- @node-saml/node-saml (passport-saml core).
 *
 * Uses the actual node-saml library (validatePostResponseAsync) for
 * signature verification and SAML validation.  This provides real
 * node-saml behavior including:
 *   - xml-crypto-based signature verification
 *   - Assertion selection (first-match)
 *   - Conditions / NotBefore / NotOnOrAfter
 *   - AudienceRestriction enforcement
 *   - InResponseTo handling
 *
 * Clock skew is disabled (acceptedClockSkewMs=-1) so that static
 * seeds with expired timestamps are still accepted.
 *
 * Usage: node saml_nodesaml.js <input_file>
 */

"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { SAML } = require("@node-saml/node-saml");
const { DOMParser, XMLSerializer } = require("@xmldom/xmldom");

const FIXTURES = path.join(__dirname, "saml_fixtures");
const IDP_CERT = fs.readFileSync(path.join(FIXTURES, "idp_cert.pem"), "utf8");
const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
const SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const DS_NS = "http://www.w3.org/2000/09/xmldsig#";

// Match the audience used in test seeds
const SP_ENTITY_ID = "https://sp.example.com";

// Pre-configured SAML instance (reused across invocations)
const samlInstance = new SAML({
  callbackUrl: "https://sp.example.com/acs",
  entryPoint: "https://idp.example.com/sso",
  issuer: SP_ENTITY_ID,
  idpCert: IDP_CERT,
  wantAssertionsSigned: false,
  wantAuthnResponseSigned: false,
  validateInResponseTo: "never",
  acceptedClockSkewMs: -1, // Disable time validation for static seeds
});

// ── Observability helpers (shared with other targets) ────────────

function getText(elem) {
  if (!elem) return null;
  return (elem.textContent || "") || null;
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

function normSig(a) {
  const l = a.toLowerCase();
  if (l.includes("hmac")) return a.split("#").pop();
  if (l.includes("sha256")) return "rsa-sha256";
  if (l.includes("sha384")) return "rsa-sha384";
  if (l.includes("sha512")) return "rsa-sha512";
  if (l.includes("sha1")) return "rsa-sha1";
  return a;
}
function normDig(a) {
  const l = a.toLowerCase();
  if (l.includes("sha256")) return "sha256";
  if (l.includes("sha384")) return "sha384";
  if (l.includes("sha512")) return "sha512";
  if (l.includes("sha1")) return "sha1";
  if (l.includes("md5")) return "md5";
  return a;
}

// ── Main verification using actual node-saml library ─────────────

async function verifySaml(xmlInput) {
  const doc = new DOMParser().parseFromString(xmlInput, "text/xml");

  // Run node-saml's full validation pipeline
  let signatureValid = false;
  let signatureError = null;
  let nodeSamlProfile = null;

  try {
    const container = { SAMLResponse: Buffer.from(xmlInput).toString("base64") };
    const result = await samlInstance.validatePostResponseAsync(container);
    signatureValid = true;
    nodeSamlProfile = result.profile || null;
  } catch (e) {
    signatureError = e.message;
  }

  // ── Extract fields from DOM for observability ──────────────────
  const assertions = doc.getElementsByTagNameNS(SAML_NS, "Assertion");

  // node-saml uses first assertion
  const selectedAssertionIndex = assertions.length > 0 ? 0 : null;
  const selectionMode = assertions.length > 0 ? "first_assertion" : "no_assertion";
  const referenceUri = firstReferenceUri(doc);
  const referenceTargetId =
    referenceUri && referenceUri.startsWith("#") ? referenceUri.substring(1) : null;
  const selectedAssertion = assertions.length > 0 ? assertions[0] : null;

  // Extract subject: prefer node-saml's extracted nameID, fallback to DOM
  let subject = null;
  let subjectFormat = null;
  if (nodeSamlProfile) {
    subject = nodeSamlProfile.nameID || null;
    subjectFormat = nodeSamlProfile.nameIDFormat || null;
  }
  if (!subject && selectedAssertion) {
    const nameIDs = selectedAssertion.getElementsByTagNameNS(SAML_NS, "NameID");
    if (nameIDs.length > 0) {
      subject = getText(nameIDs[0]);
      subjectFormat = nameIDs[0].getAttribute("Format");
    }
  }

  let issuer = null;
  let issuerSource = "none";
  let audience = null;
  let audienceCount = 0;
  let assertionId = null;
  const attributes = {};
  let nameIdCount = 0;
  let emptyNameIdSemantics = "missing";

  if (selectedAssertion) {
    assertionId = selectedAssertion.getAttribute("ID") || null;

    const nameIdObs = nameIdObservability(selectedAssertion);
    nameIdCount = nameIdObs.count;
    emptyNameIdSemantics = nameIdObs.semantics;

    const issuers = selectedAssertion.getElementsByTagNameNS(SAML_NS, "Issuer");
    issuer = issuers.length > 0 ? getText(issuers[0]) : null;
    if (issuer) issuerSource = "assertion";

    const audiences = selectedAssertion.getElementsByTagNameNS(SAML_NS, "Audience");
    audienceCount = audiences.length;
    audience = audiences.length > 0 ? getText(audiences[0]) : null;

    // Use node-saml profile attributes if available, else fall back to DOM
    if (nodeSamlProfile && nodeSamlProfile.attributes) {
      Object.assign(attributes, nodeSamlProfile.attributes);
    } else {
      const attrElems = selectedAssertion.getElementsByTagNameNS(SAML_NS, "Attribute");
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
  }

  // Response-level issuer as fallback
  if (!issuer) {
    const respIssuers = doc.getElementsByTagNameNS(SAML_NS, "Issuer");
    if (respIssuers.length > 0) issuer = getText(respIssuers[0]);
    if (issuer) issuerSource = "response";
  }

  // Use node-saml issuer if available
  if (nodeSamlProfile && nodeSamlProfile.issuer) {
    issuer = nodeSamlProfile.issuer;
    issuerSource = "node-saml";
  }

  const sigM = doc.getElementsByTagNameNS(DS_NS, "SignatureMethod");
  const digM = doc.getElementsByTagNameNS(DS_NS, "DigestMethod");
  const algorithms = {};
  if (sigM.length > 0)
    algorithms.signature = normSig(sigM[0].getAttribute("Algorithm") || "");
  if (digM.length > 0)
    algorithms.digest = normDig(digM[0].getAttribute("Algorithm") || "");

  const referenceMatchesSelectedAssertion =
    referenceTargetId && assertionId ? referenceTargetId === assertionId : null;
  const keyInfo = keyInfoType(doc);
  const validatedNode = signatureValid ? selectedAssertion : null;
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
    selected_assertion_index: selectedAssertionIndex,
    selection_mode: selectionMode,
    reference_uri: referenceUri,
    reference_matches_selected_assertion: referenceMatchesSelectedAssertion,
    signature_count: doc.getElementsByTagNameNS(DS_NS, "Signature").length,
    issuer_source: issuerSource,
    audience_count: audienceCount,
    nameid_count: nameIdCount,
    empty_nameid_semantics: emptyNameIdSemantics,
    algorithms,
    validated_reference_uri: signatureValid ? referenceUri : null,
    validated_reference_count: countReferences(doc),
    validated_node_tag: validatedNodeTag,
    validated_node_id: validatedNodeId,
    validated_node_xpath: validatedNodeTag,
    id_resolution_mode: selectionMode,
    resolved_id_attribute: resolvedIdAttribute(validatedNode),
    transform_chain: extractTransformChain(doc),
    c14n_method: firstAlgorithmAttr(doc, "CanonicalizationMethod"),
    signature_method: firstAlgorithmAttr(doc, "SignatureMethod"),
    validated_signature_algorithm: signatureValid
      ? (() => {
          const sigs = doc.getElementsByTagNameNS(DS_NS, "Signature");
          if (sigs.length === 0) return null;
          const sm = sigs[0].getElementsByTagNameNS(DS_NS, "SignatureMethod");
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
    process.stderr.write("Usage: node saml_nodesaml.js <input_file>\n");
    process.exit(2);
  }

  (async () => {
    try {
      const input = fs.readFileSync(inputPath, "utf8");
      process.stdout.write((await verifySaml(input)) + "\n");
      process.exit(0);
    } catch (err) {
      process.stderr.write("REJECT: " + err.message + "\n");
      process.exit(1);
    }
  })();
}
