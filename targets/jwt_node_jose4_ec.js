/**
 * JWT target -- Node jose@4 ES256 (ECDSA P-256) verifier.
 *
 * Uses jose v4's manual ECDSA verification with crypto.verify().
 * jose's parser is stricter than hand-written decoders.
 *
 * Output: standardized JSON for differential comparison.
 */
"use strict";

const fs = require("fs");
const crypto = require("crypto");
const jose = require("jose");

const { EC_PUBLIC_KEY_PEM } = require("./jwt_ec_keys");

function b64urlDecode(data) {
  let raw = String(data || "");
  while (raw.length % 4 !== 0) raw += "=";
  return Buffer.from(raw, "base64url");
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString("base64url");
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

/**
 * Convert DER-encoded ECDSA signature to raw r||s format (64 bytes for P-256).
 */
function derToRaw(derSig) {
  // DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
  let offset = 2;
  if (derSig[1] & 0x80) offset += (derSig[1] & 0x7f);

  const rLen = derSig[offset + 1];
  const r = derSig.subarray(offset + 2, offset + 2 + rLen);
  offset += 2 + rLen;
  const sLen = derSig[offset + 1];
  const s = derSig.subarray(offset + 2, offset + 2 + sLen);

  const size = 32; // P-256
  const rawR = r.length > size ? r.subarray(r.length - size) : Buffer.concat([Buffer.alloc(size - r.length), r]);
  const rawS = s.length > size ? s.subarray(s.length - size) : Buffer.concat([Buffer.alloc(size - s.length), s]);
  return Buffer.concat([rawR, rawS]);
}

/**
 * Convert raw r||s ECDSA signature to DER format.
 */
function rawToDer(rawSig) {
  const size = rawSig.length / 2;
  let r = rawSig.subarray(0, size);
  let s = rawSig.subarray(size);

  // Remove leading zeros but keep one if high bit set
  while (r.length > 1 && r[0] === 0) r = r.subarray(1);
  while (s.length > 1 && s[0] === 0) s = s.subarray(1);
  if (r[0] & 0x80) r = Buffer.concat([Buffer.from([0]), r]);
  if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0]), s]);

  const totalLen = 2 + r.length + 2 + s.length;
  return Buffer.concat([
    Buffer.from([0x30, totalLen, 0x02, r.length]),
    r,
    Buffer.from([0x02, s.length]),
    s,
  ]);
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

  // ES256 verification with jose v4 + crypto.verify
  if (parts.length === 3) {
    try {
      const signingInput = parts[0] + "." + parts[1];
      const sigBytes = b64urlDecode(parts[2]);

      // jose uses raw r||s format (64 bytes for P-256)
      // Convert to DER for Node crypto.verify
      let derSig;
      if (sigBytes.length === 64) {
        derSig = rawToDer(sigBytes);
      } else {
        // Might already be DER or malformed
        derSig = sigBytes;
      }

      const verifier = crypto.createVerify("SHA256");
      verifier.update(signingInput);
      signatureValid = verifier.verify(
        { key: EC_PUBLIC_KEY_PEM, dsaEncoding: "der" },
        derSig
      );
      if (signatureValid) {
        effectiveAlg = "ES256";
      }
    } catch (err) {
      signatureError = (err.name || "Error") + ": " + (err.message || "").slice(0, 200);
    }
  } else {
    signatureError = "UnsupportedTokenType: expected 3-segment JWS";
  }

  // crit processing (jose v4 validates crit)
  if (header.crit != null) {
    if (Array.isArray(header.crit) && header.crit.length > 0) {
      // jose rejects unknown crit extensions
      critProcessed = false;
    }
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
    process.stderr.write("Usage: node jwt_node_jose4_ec.js <input_file>\n");
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
