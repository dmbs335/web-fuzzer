/**
 * JWT target -- Node pac4j-like nested JWT verifier.
 *
 * This wrapper models a service that expects an encrypted outer JWE carrying
 * an inner signed JWT. It intentionally exposes the dangerous state where the
 * inner token is an unsecured PlainJWT and signature verification is skipped.
 *
 * We do not implement real JWE cryptography here. Instead, the "ciphertext"
 * segment is treated as base64url-encoded nested token bytes so the fuzzer can
 * explore token-type confusion and skipped-verification states.
 */
"use strict";

const fs = require("fs");
const crypto = require("crypto");

const DEFAULT_HS_SECRET = Buffer.from("secret", "utf8");

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
  return {
    value: JSON.parse(text),
    duplicates: duplicateKeys(text),
  };
}

function classifyTime(payload) {
  const now = Math.floor(Date.now() / 1000);
  let timeValid = true;

  function state(name, mode) {
    if (!Object.prototype.hasOwnProperty.call(payload, name)) return "missing";
    const value = payload[name];
    if (typeof value !== "number") {
      timeValid = false;
      return "invalid_type";
    }
    if (mode === "exp") {
      if (now >= value) {
        timeValid = false;
        return "expired";
      }
      return "valid";
    }
    if (mode === "nbf") {
      if (now < value) {
        timeValid = false;
        return "not_yet_valid";
      }
      return "valid";
    }
    if (mode === "iat") {
      if (now + 300 < value) {
        timeValid = false;
        return "future";
      }
      return "valid";
    }
    return "missing";
  }

  return {
    timeValid,
    expState: state("exp", "exp"),
    nbfState: state("nbf", "nbf"),
    iatState: state("iat", "iat"),
  };
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

function verifyHmac(alg, signingInput, signature, secret) {
  const digest = { HS256: "sha256", HS384: "sha384", HS512: "sha512" }[alg];
  if (!digest) return false;
  const expected = b64urlEncode(
    crypto.createHmac(digest, secret).update(signingInput).digest()
  );
  return crypto.timingSafeEqual(Buffer.from(signature || "", "utf8"), Buffer.from(expected, "utf8"));
}

function verifyJwt(tokenInput) {
  const raw = String(tokenInput || "").trim();
  const parts = raw.split(".");
  if (parts.length !== 5) {
    throw new Error("Expected compact JWE with five segments");
  }

  const outerHeaderParsed = parseJson(b64urlDecode(parts[0]));
  const outerHeader = outerHeaderParsed.value;
  const tokenTypeObserved = "jwe";
  const tokenTypeExpected = "nested_jws";
  let signatureValid = false;
  let signatureError = null;
  let keySource = "configured_public";
  let effectiveAlg = String(outerHeader.alg || "");
  let innerAlg = null;
  let innerSignatureValid = null;
  let innerTokenType = "unknown";
  let duplicateClaimKeys = [];
  let payload = {};
  let claimParseMode = "last_wins";

  if (outerHeader.jku) keySource = "jku";
  else if (outerHeader.x5u) keySource = "x5u";
  else if (outerHeader.jwk) keySource = "embedded_jwk";
  else if (outerHeader.x5c) keySource = "x5c";

  if (outerHeader.cty !== "JWT") {
    signatureError = "Outer token does not declare nested JWT";
  } else {
    const nestedRaw = b64urlDecode(parts[3]).toString("utf8");
    const innerParts = nestedRaw.split(".");
    if (innerParts.length < 2) {
      throw new Error("Nested token must contain header and payload");
    }

    const innerHeaderParsed = parseJson(b64urlDecode(innerParts[0]));
    const innerPayloadParsed = parseJson(b64urlDecode(innerParts[1]));
    const innerHeader = innerHeaderParsed.value;
    payload = innerPayloadParsed.value;
    duplicateClaimKeys = innerPayloadParsed.duplicates;
    innerAlg = String(innerHeader.alg || "");
    if (innerAlg.toLowerCase() === "none") {
      innerTokenType = "plain_jwt";
    } else if (innerParts.length === 3) {
      innerTokenType = "jws";
    }

    if (innerParts.length === 3 && innerAlg.toUpperCase().startsWith("HS")) {
      innerSignatureValid = verifyHmac(
        innerAlg,
        `${innerParts[0]}.${innerParts[1]}`,
        innerParts[2],
        DEFAULT_HS_SECRET
      );
      signatureValid = innerSignatureValid;
      if (!signatureValid) signatureError = "Nested JWT signature mismatch";
    } else if (innerAlg.toLowerCase() === "none") {
      innerSignatureValid = null;
      signatureValid = true;
      signatureError = null;
      effectiveAlg = "none";
    } else {
      innerSignatureValid = false;
      signatureError = `Unsupported nested JWT alg: ${innerAlg}`;
    }
  }

  const time = classifyTime(payload);
  const result = {
    signature_valid: signatureValid,
    signature_error: signatureError,
    header_alg: String(outerHeader.alg || ""),
    effective_alg: effectiveAlg || innerAlg,
    key_source: keySource,
    resolved_kid: outerHeader.kid || null,
    jwk_source: outerHeader.jwk ? "embedded" : null,
    jku_source: outerHeader.jku || null,
    x5u_source: outerHeader.x5u || null,
    token_type_expected: tokenTypeExpected,
    token_type_observed: tokenTypeObserved,
    typ: outerHeader.typ || null,
    cty: outerHeader.cty || null,
    crit_processed: outerHeader.crit == null ? null : false,
    b64_mode: outerHeader.b64 === false ? "unencoded" : "normal",
    detached_payload_used: false,
    sub: payload.sub ?? null,
    iss: payload.iss ?? null,
    aud: payload.aud ?? null,
    role: payload.role ?? null,
    scope: payload.scope ?? null,
    claim_types: claimTypes(payload),
    duplicate_header_keys: outerHeaderParsed.duplicates,
    duplicate_claim_keys: duplicateClaimKeys,
    claim_parse_mode: claimParseMode,
    time_valid: time.timeValid,
    exp_state: time.expState,
    nbf_state: time.nbfState,
    iat_state: time.iatState,
    nested_jwt: true,
    inner_alg: innerAlg,
    inner_signature_valid: innerSignatureValid,
    inner_token_type: innerTokenType,
  };
  return JSON.stringify(result);
}

module.exports = { verifyJwt };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node jwt_node_pac4j_like.js <input_file>\n");
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
