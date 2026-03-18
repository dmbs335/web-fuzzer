/**
 * JWT target -- Node jsonwebtoken RSA verifier.
 *
 * Configured with RS256 + RSA public key. The public key is "known" to the
 * attacker (exposed via OIDC /.well-known/jwks.json). This enables testing:
 *   §1-2 Algorithm Confusion (RS256→HS256 with public key as HMAC secret)
 *   §2-3 Embedded JWK self-signed tokens
 *   §2-4 Self-signed x5c certificates
 *   §7-1 JWS/JWE confusion
 *
 * Output: standardized JSON for differential comparison.
 */
"use strict";

const fs = require("fs");
const jwt = require("jsonwebtoken");
const { RSA_PUBLIC_KEY_PEM } = require("./jwt_rsa_keys");

function b64urlDecode(data) {
  let raw = String(data || "");
  while (raw.length % 4 !== 0) raw += "=";
  return Buffer.from(raw, "base64url");
}

function duplicateKeys(raw) {
  const matches = raw.match(/"((?:\\.|[^"])*)"\s*:/g) || [];
  const seen = new Set();
  const dupes = new Set();
  for (const match of matches) {
    const key = match.replace(/"\s*:$/, "").slice(1);
    if (seen.has(key)) dupes.add(key);
    seen.add(key);
  }
  return Array.from(dupes).sort();
}

function parseJson(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
  return { value: JSON.parse(text), duplicates: duplicateKeys(text) };
}

function claimTypes(payload) {
  const out = {};
  for (const key of ["sub", "iss", "aud", "role", "scope", "exp", "nbf", "iat"]) {
    if (Object.prototype.hasOwnProperty.call(payload, key)) {
      if (Array.isArray(payload[key])) out[key] = "array";
      else if (payload[key] === null) out[key] = "null";
      else out[key] = typeof payload[key];
    }
  }
  return out;
}

function classifyTime(payload) {
  const now = Math.floor(Date.now() / 1000);
  let timeValid = true;
  function state(name, mode) {
    if (!Object.prototype.hasOwnProperty.call(payload, name)) return "missing";
    const value = payload[name];
    if (typeof value !== "number") { timeValid = false; return "invalid_type"; }
    if (mode === "exp") { if (now >= value) { timeValid = false; return "expired"; } return "valid"; }
    if (mode === "nbf") { if (now < value) { timeValid = false; return "not_yet_valid"; } return "valid"; }
    if (mode === "iat") { if (now + 300 < value) { timeValid = false; return "future"; } return "valid"; }
    return "missing";
  }
  return { timeValid, expState: state("exp", "exp"), nbfState: state("nbf", "nbf"), iatState: state("iat", "iat") };
}

function verifyJwt(tokenInput) {
  const raw = String(tokenInput || "").trim();
  const parts = raw.split(".");
  const tokenTypeObserved = parts.length === 3 ? "jws" : parts.length === 5 ? "jwe" : "unknown";
  const tokenTypeExpected = "jws";
  if (parts.length < 2) throw new Error("JWT must contain at least header and payload segments");

  const headerRaw = b64urlDecode(parts[0]);
  const headerParsed = parseJson(headerRaw);
  const header = headerParsed.value;
  const headerAlg = String(header.alg || "");

  let payload = {};
  let payloadDuplicates = [];
  try {
    const payloadRaw = b64urlDecode(parts[1]);
    const payloadParsed = parseJson(payloadRaw);
    payload = payloadParsed.value;
    payloadDuplicates = payloadParsed.duplicates;
  } catch {}

  let signatureValid = false;
  let signatureError = null;
  let effectiveAlg = headerAlg;
  let keySource = "configured";
  let critProcessed = header.crit == null ? null : false;

  if (header.jku) keySource = "jku";
  else if (header.jwk) keySource = "embedded_jwk";
  else if (header.x5u) keySource = "x5u";
  else if (header.x5c) keySource = "x5c";

  // RS256 verification with RSA public key — only RS256 allowed
  try {
    const decoded = jwt.verify(raw, RSA_PUBLIC_KEY_PEM, {
      algorithms: ["RS256"],
      complete: true,
      clockTolerance: 0,
    });
    signatureValid = true;
    effectiveAlg = decoded.header.alg;
    payload = decoded.payload;
  } catch (err) {
    signatureError = (err.name || "Error") + ": " + (err.message || "").slice(0, 200);
  }

  const nestedCandidate = typeof payload.nested === "string" ? payload.nested : null;
  let innerAlg = null;
  let innerSignatureValid = null;
  if ((header.cty === "JWT" || nestedCandidate) && nestedCandidate && nestedCandidate.split(".").length >= 2) {
    try {
      innerAlg = parseJson(b64urlDecode(nestedCandidate.split(".")[0])).value.alg || null;
    } catch {}
  }

  const time = classifyTime(payload);
  const result = {
    signature_valid: signatureValid,
    signature_error: signatureError,
    header_alg: headerAlg,
    effective_alg: effectiveAlg,
    key_source: keySource,
    resolved_kid: header.kid || null,
    jwk_source: header.jwk ? "embedded" : null,
    jku_source: header.jku || null,
    x5u_source: header.x5u || null,
    token_type_expected: tokenTypeExpected,
    token_type_observed: tokenTypeObserved,
    typ: header.typ || null,
    cty: header.cty || null,
    crit_processed: critProcessed,
    b64_mode: header.b64 === false ? "unencoded" : "normal",
    detached_payload_used: false,
    sub: payload.sub ?? null,
    iss: payload.iss ?? null,
    aud: payload.aud ?? null,
    role: payload.role ?? null,
    scope: payload.scope ?? null,
    claim_types: claimTypes(payload),
    duplicate_header_keys: headerParsed.duplicates,
    duplicate_claim_keys: payloadDuplicates,
    claim_parse_mode: "last_wins",
    time_valid: time.timeValid,
    exp_state: time.expState,
    nbf_state: time.nbfState,
    iat_state: time.iatState,
    nested_jwt: Boolean(header.cty === "JWT" || nestedCandidate),
    inner_alg: innerAlg,
    inner_signature_valid: innerSignatureValid,
  };
  return JSON.stringify(result);
}

module.exports = { verifyJwt };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node jwt_node_jsonwebtoken_rsa.js <input_file>\n");
    process.exit(2);
  }
  try {
    const input = fs.readFileSync(inputPath, "utf8");
    process.stdout.write(verifyJwt(input) + "\n");
    process.exit(0);
  } catch (err) {
    process.stderr.write("REJECT: " + err.message + "\n");
    process.exit(1);
  }
}
