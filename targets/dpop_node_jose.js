/**
 * DPoP proof verification target -- Node.js implementation.
 *
 * Validates DPoP proof JWTs per RFC 9449.
 * Uses WHATWG URL normalization for htu comparison (new URL().href),
 * strips query and fragment before comparing.
 *
 * Input:  JSON { type: "dpop_proof", proof_jwt, http_method, http_uri, access_token?, server_nonce? }
 * Output: standardized JSON for differential comparison.
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");

const ASYMMETRIC_ALGS = new Set([
  "RS256", "RS384", "RS512",
  "ES256", "ES384", "ES512",
  "PS256", "PS384", "PS512",
  "EdDSA",
]);

const PRIVATE_KEY_FIELDS = new Set(["d", "p", "q", "dp", "dq", "qi", "oth"]);

function base64urlDecode(str) {
  return Buffer.from(str, "base64url");
}

function base64urlEncode(buf) {
  return buf.toString("base64url");
}

function normalizeHtu(uri) {
  try {
    const u = new URL(uri);
    u.search = "";
    u.hash = "";
    return u.href;
  } catch {
    return uri;
  }
}

function computeAth(accessToken) {
  const hash = crypto.createHash("sha256").update(accessToken, "ascii").digest();
  return base64urlEncode(hash);
}

function hasPrivateKey(jwk) {
  if (!jwk || typeof jwk !== "object") return false;
  for (const field of PRIVATE_KEY_FIELDS) {
    if (field in jwk) return true;
  }
  return false;
}

function processDPoP(inputStr) {
  const raw = String(inputStr || "").trim();
  const data = JSON.parse(raw);

  if (!data || typeof data !== "object" || data.type !== "dpop_proof") {
    throw new Error("Invalid input: type must be dpop_proof");
  }

  const proofJwt = String(data.proof_jwt || "");
  const httpMethod = data.http_method != null ? String(data.http_method) : null;
  const httpUri = data.http_uri != null ? String(data.http_uri) : null;
  const accessToken = data.access_token != null ? String(data.access_token) : null;
  const serverNonce = data.server_nonce != null ? String(data.server_nonce) : null;

  const result = {
    input_type: "dpop_proof",
    proof_valid: false,
    header_typ: null,
    header_typ_valid: false,
    header_alg: null,
    header_alg_valid: false,
    header_has_jwk: false,
    htm_matches: false,
    htm_value: null,
    htu_matches: false,
    htu_value: null,
    htu_normalized: null,
    ath_valid: null,
    ath_value: null,
    ath_has_padding: false,
    iat_valid: false,
    iat_value: null,
    jti: null,
    jti_valid: false,
    nonce_valid: null,
    nonce_value: null,
    jwt_parse_error: null,
  };

  // Parse JWT
  const parts = proofJwt.split(".");
  if (parts.length !== 3) {
    result.jwt_parse_error = "invalid JWT structure: expected 3 parts";
    return JSON.stringify(result);
  }

  let header, payload;
  try {
    header = JSON.parse(base64urlDecode(parts[0]).toString("utf8"));
  } catch (e) {
    result.jwt_parse_error = "header decode failed: " + e.message;
    return JSON.stringify(result);
  }

  try {
    payload = JSON.parse(base64urlDecode(parts[1]).toString("utf8"));
  } catch (e) {
    result.jwt_parse_error = "payload decode failed: " + e.message;
    return JSON.stringify(result);
  }

  // Check header typ
  result.header_typ = header.typ != null ? String(header.typ) : null;
  result.header_typ_valid = result.header_typ === "dpop+jwt";

  // Check header alg
  result.header_alg = header.alg != null ? String(header.alg) : null;
  result.header_alg_valid =
    result.header_alg !== null &&
    result.header_alg !== "none" &&
    !result.header_alg.startsWith("HS") &&
    ASYMMETRIC_ALGS.has(result.header_alg);

  // Check jwk in header
  result.header_has_jwk = header.jwk != null && typeof header.jwk === "object";

  // Check for private key material in jwk
  if (result.header_has_jwk && hasPrivateKey(header.jwk)) {
    result.header_alg_valid = false; // Reject if private key present
  }

  // Check htm
  result.htm_value = payload.htm != null ? String(payload.htm) : null;
  if (httpMethod != null && result.htm_value != null) {
    result.htm_matches = result.htm_value === httpMethod; // Case-sensitive
  }

  // Check htu with WHATWG URL normalization
  result.htu_value = payload.htu != null ? String(payload.htu) : null;
  if (httpUri != null && result.htu_value != null) {
    const normalizedHtu = normalizeHtu(result.htu_value);
    const normalizedExpected = normalizeHtu(httpUri);
    result.htu_normalized = normalizedHtu;
    result.htu_matches = normalizedHtu === normalizedExpected;
  } else {
    result.htu_normalized = result.htu_value != null ? normalizeHtu(result.htu_value) : null;
  }

  // Check ath (access token hash)
  if (accessToken != null) {
    result.ath_value = payload.ath != null ? String(payload.ath) : null;
    if (result.ath_value != null) {
      const expectedAth = computeAth(accessToken);
      result.ath_valid = result.ath_value === expectedAth;
      result.ath_has_padding = result.ath_value.includes("=");
    } else {
      result.ath_valid = false; // ath missing but access_token provided
    }
  } else {
    // No access_token: ath is not required
    result.ath_valid = null;
    result.ath_value = payload.ath != null ? String(payload.ath) : null;
    result.ath_has_padding = (result.ath_value || "").includes("=");
  }

  // Check iat
  result.iat_value = payload.iat != null ? payload.iat : null;
  if (typeof result.iat_value === "number") {
    const now = Math.floor(Date.now() / 1000);
    const diff = Math.abs(now - result.iat_value);
    result.iat_valid = diff <= 300;
  }

  // Check jti
  result.jti = payload.jti != null ? String(payload.jti) : null;
  result.jti_valid = typeof result.jti === "string" && result.jti.length > 0;

  // Check nonce
  if (serverNonce != null) {
    result.nonce_value = payload.nonce != null ? String(payload.nonce) : null;
    if (result.nonce_value != null) {
      result.nonce_valid = result.nonce_value === serverNonce;
    } else {
      result.nonce_valid = false; // nonce missing but server_nonce provided
    }
  } else {
    result.nonce_valid = null;
    result.nonce_value = payload.nonce != null ? String(payload.nonce) : null;
  }

  // Compute overall validity
  result.proof_valid =
    result.header_typ_valid &&
    result.header_alg_valid &&
    result.htm_matches &&
    result.htu_matches &&
    (accessToken != null ? result.ath_valid === true : true) &&
    result.iat_valid &&
    result.jti_valid &&
    (serverNonce != null ? result.nonce_valid === true : true);

  return JSON.stringify(result);
}

module.exports = { processDPoP };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node dpop_node_jose.js <input_file>\n");
    process.exit(2);
  }
  try {
    const input = fs.readFileSync(inputPath, "utf8");
    process.stdout.write(processDPoP(input) + "\n");
    process.exit(0);
  } catch (err) {
    process.stderr.write("REJECT: " + err.message + "\n");
    process.exit(1);
  }
}
