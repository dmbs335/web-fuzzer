/**
 * OAuth token request validation target -- @node-oauth/oauth2-server REAL logic.
 *
 * Uses REAL library imports:
 *   - @node-oauth/formats: isFormat.nchar(), isFormat.vschar(), isFormat.uri()
 *     Source: node_modules/@node-oauth/formats/index.js
 *   - @node-oauth/oauth2-server parseScope(): NQSCHAR validation + \s+ split
 *     Source: node_modules/@node-oauth/oauth2-server/lib/utils/scope-util.js
 *   - @node-oauth/oauth2-server pkce: isValidMethod(), codeChallengeMatchesABNF()
 *     Source: node_modules/@node-oauth/oauth2-server/lib/pkce/pkce.js
 *
 * grant_type validation:
 *   Source: token-handler.js:97-107
 *   `if (!isFormat.nchar(grantType) && !isFormat.uri(grantType))` → invalid
 *   `if (!grantTypes[grantType])` → unsupported
 *   `if (!client.grants.includes(grantType))` → unauthorized
 *
 * Input:  JSON { type: "token_request", grant_type, code, redirect_uri,
 *                client_id, client_secret, scope, code_verifier }
 * Output: standardized JSON for differential comparison.
 */
"use strict";

const fs = require("fs");

// --- REAL LIBRARY IMPORTS ---
const isFormat = require("@node-oauth/formats");
const { parseScope } = require("@node-oauth/oauth2-server/lib/utils/scope-util");
const pkce = require("@node-oauth/oauth2-server/lib/pkce/pkce");

const KNOWN_GRANTS = new Set([
  "authorization_code",
  "refresh_token",
  "client_credentials",
  "urn:ietf:params:oauth:grant-type:device_code",
  "urn:ietf:params:oauth:grant-type:jwt-bearer",
]);

function checkTokenRequest(data) {
  const grantType = String(data.grant_type || "");
  const clientId = String(data.client_id || "");
  const clientSecret = String(data.client_secret || "");
  const code = String(data.code || "");
  const redirectUri = String(data.redirect_uri || "");
  const scope = String(data.scope || "");
  const codeVerifier = String(data.code_verifier || "");

  // REAL: @node-oauth grant_type format validation
  // Source: token-handler.js `if (!isFormat.nchar(grantType) && !isFormat.uri(grantType))`
  const grantTypeNormalized = grantType.trim();
  const grantTypeFormatValid = isFormat.nchar(grantTypeNormalized) || isFormat.uri(grantTypeNormalized);
  const grantTypeValid = grantTypeFormatValid && KNOWN_GRANTS.has(grantTypeNormalized);

  // REAL: @node-oauth client_id — no explicit format check in library,
  // but NQCHAR is the OAuth 2.0 spec format for client identifiers
  // The library relies on the model to validate client_id existence
  const clientIdValid = clientId.length > 0 && isFormat.nqchar(clientId);

  // REAL: @node-oauth client_secret uses VSCHAR
  // Source: @node-oauth/formats VSCHAR: /^[\x20-\x7e]+$/
  const clientSecretFormatValid =
    clientSecret.length === 0 || isFormat.vschar(clientSecret);

  // REAL: @node-oauth redirect_uri format check
  // Source: authorization-code-grant-type.js:151 `if (!isFormat.uri(redirectUri))`
  let redirectUriFormatValid = false;
  if (redirectUri) {
    redirectUriFormatValid = isFormat.uri(redirectUri);
  }

  // REAL: @node-oauth code must be VSCHAR
  // Source: authorization-code-grant-type.js `if (!isFormat.vschar(request.body.code))`
  const codeFormatValid =
    code.length > 0 && isFormat.vschar(code) && code.length <= 2048;

  // REAL: @node-oauth scope via parseScope()
  // Source: scope-util.js — validates NQSCHAR then splits on \s+
  let scopeParsed = [];
  let scopeValid = true;
  let scopeParseError = null;
  if (scope) {
    try {
      scopeParsed = parseScope(scope) || [];
      scopeValid = scopeParsed.length > 0;
    } catch (e) {
      scopeValid = false;
      scopeParseError = e.message;
    }
  }

  // REAL: @node-oauth PKCE verifier validation
  // Source: pkce.js codeChallengeMatchesABNF() — 43-128 chars, unreserved chars
  const pkceVerifierPresent = codeVerifier.length > 0;
  let pkceVerifierFormatValid = null;
  if (pkceVerifierPresent) {
    pkceVerifierFormatValid = pkce.codeChallengeMatchesABNF(codeVerifier);
  }

  // Overall validity
  let overallValid = grantTypeValid && clientIdValid;
  let rejectionReason = null;
  if (!grantTypeFormatValid) {
    rejectionReason = "invalid_request";
    overallValid = false;
  } else if (!grantTypeValid) {
    rejectionReason = "unsupported_grant_type";
  } else if (!clientIdValid) {
    rejectionReason = "invalid_client";
  } else if (grantTypeNormalized === "authorization_code") {
    if (!code) {
      overallValid = false;
      rejectionReason = "invalid_request";
    } else if (!codeFormatValid) {
      overallValid = false;
      rejectionReason = "invalid_request";
    } else if (redirectUri && !redirectUriFormatValid) {
      overallValid = false;
      rejectionReason = "invalid_request";
    }
  }

  return {
    input_type: "token_request",
    grant_type_valid: grantTypeValid,
    grant_type_format_valid: grantTypeFormatValid,
    grant_type_normalized: grantTypeNormalized,
    client_id_valid: clientIdValid,
    client_secret_format_valid: clientSecretFormatValid,
    redirect_uri_present: redirectUri.length > 0,
    redirect_uri_format_valid: redirectUri ? redirectUriFormatValid : null,
    code_format_valid: code ? codeFormatValid : null,
    code_length: code.length,
    scope_valid: scopeValid,
    scope_parsed: scopeParsed,
    scope_parse_error: scopeParseError,
    pkce_verifier_present: pkceVerifierPresent,
    pkce_verifier_format_valid: pkceVerifierFormatValid,
    overall_valid: overallValid,
    rejection_reason: rejectionReason,
  };
}

function processOAuth(inputStr) {
  const raw = String(inputStr || "").trim();
  const data = JSON.parse(raw);

  if (!data || typeof data !== "object" || !data.type) {
    throw new Error("Invalid input");
  }

  if (data.type === "token_request") {
    return JSON.stringify(checkTokenRequest(data));
  }

  // Delegate other types to PKCE node target
  const { processOAuth: pkceProcess } = require("./oauth_pkce_node");
  return pkceProcess(inputStr);
}

module.exports = { processOAuth };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node oauth_tokenreq_node.js <input_file>\n");
    process.exit(2);
  }
  try {
    const input = fs.readFileSync(inputPath, "utf8");
    process.stdout.write(processOAuth(input) + "\n");
    process.exit(0);
  } catch (err) {
    process.stderr.write("REJECT: " + err.message + "\n");
    process.exit(1);
  }
}
