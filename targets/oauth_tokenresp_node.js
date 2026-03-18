/**
 * OAuth token response parsing target -- @node-oauth/oauth2-server REAL logic.
 *
 * Uses REAL library imports:
 *   - @node-oauth/oauth2-server parseScope(): NQSCHAR validation + \s+ split
 *     Source: node_modules/@node-oauth/oauth2-server/lib/utils/scope-util.js
 *   - @node-oauth/formats: isFormat.vschar() for token format validation
 *     Source: node_modules/@node-oauth/formats/index.js
 *
 * Token response structure from BearerTokenType:
 *   Source: node_modules/@node-oauth/oauth2-server/lib/token-types/bearer-token-type.js
 *   - access_token: required (InvalidArgumentError if missing)
 *   - token_type: always "Bearer"
 *   - expires_in: from accessTokenLifetime (integer)
 *   - refresh_token: optional
 *   - scope: optional, joined as string
 *
 * Token header parsing:
 *   Source: authenticate-handler.js:91
 *   /^Bearer ([0-9a-zA-Z-._~+/]+=*)$/
 *
 * Input:  JSON { type: "token_response", status_code, body, requested_scope }
 * Output: standardized JSON for differential comparison.
 */
"use strict";

const fs = require("fs");

// --- REAL LIBRARY IMPORTS ---
const { parseScope } = require("@node-oauth/oauth2-server/lib/utils/scope-util");
const isFormat = require("@node-oauth/formats");

function checkTokenResponse(statusCode, body, requestedScope) {
  let parseSuccess = false;
  let tokenData = {};
  try {
    tokenData = JSON.parse(body);
    if (tokenData && typeof tokenData === "object" && !Array.isArray(tokenData)) {
      parseSuccess = true;
    }
  } catch {
    // parse failed
  }

  const isError = "error" in tokenData || statusCode >= 400;

  // token_type: BearerTokenType always sets "Bearer" (case-sensitive)
  // Source: bearer-token-type.js `token_type: 'Bearer'`
  const tokenTypeRaw = tokenData.token_type;
  let tokenTypeNormalized = null;
  let tokenTypeValid = false;
  if (tokenTypeRaw !== undefined && tokenTypeRaw !== null) {
    tokenTypeNormalized = String(tokenTypeRaw).toLowerCase();
    tokenTypeValid = tokenTypeNormalized === "bearer";
  }

  // expires_in: BearerTokenType stores as integer from accessTokenLifetime
  // Source: bearer-token-type.js `object.expires_in = this.accessTokenLifetime`
  const expiresInRaw = tokenData.expires_in;
  let expiresInRawType = "missing";
  let expiresInValue = null;
  let expiresInValid = false;
  if (expiresInRaw !== undefined && expiresInRaw !== null) {
    expiresInRawType = typeof expiresInRaw;
    const parsed = parseInt(expiresInRaw, 10);
    if (!isNaN(parsed)) {
      expiresInValue = parsed;
      expiresInValid = parsed > 0;
    }
  }

  // Access token — must be VSCHAR per spec
  // Source: authenticate-handler.js token regex: /^Bearer ([0-9a-zA-Z-._~+/]+=*)$/
  const accessToken = tokenData.access_token;
  const accessTokenPresent = accessToken !== undefined && accessToken !== null;
  const accessTokenLength = accessTokenPresent ? String(accessToken).length : 0;
  const accessTokenFormatValid = accessTokenPresent
    ? isFormat.vschar(String(accessToken))
    : null;

  // Refresh token
  const refreshTokenPresent = "refresh_token" in tokenData;

  // REAL scope parsing via parseScope()
  // Source: @node-oauth/oauth2-server/lib/utils/scope-util.js
  const scopeReturnedStr = tokenData.scope || "";
  let scopeReturned = [];
  let scopeReturnedError = null;
  if (scopeReturnedStr) {
    try {
      scopeReturned = parseScope(String(scopeReturnedStr)) || [];
    } catch (e) {
      scopeReturnedError = e.message;
    }
  }

  let scopeRequested = [];
  let scopeRequestedError = null;
  if (requestedScope) {
    try {
      scopeRequested = parseScope(requestedScope) || [];
    } catch (e) {
      scopeRequestedError = e.message;
    }
  }

  let scopeSubset = false;
  let scopeChanged = false;
  if (scopeReturned.length > 0 && scopeRequested.length > 0) {
    const reqSet = new Set(scopeRequested);
    scopeSubset = scopeReturned.every((s) => reqSet.has(s));
    const retSet = new Set(scopeReturned);
    scopeChanged =
      retSet.size !== reqSet.size ||
      ![...retSet].every((s) => reqSet.has(s));
  } else if (scopeReturned.length > 0 && scopeRequested.length === 0) {
    scopeSubset = false;
    scopeChanged = true;
  }

  // Error fields
  const errorCode = tokenData.error || null;
  const errorDescription = tokenData.error_description || null;

  return {
    input_type: "token_response",
    is_error_response: isError,
    access_token_present: accessTokenPresent,
    access_token_length: accessTokenLength,
    access_token_format_valid: accessTokenFormatValid,
    token_type_raw: tokenTypeRaw !== undefined && tokenTypeRaw !== null
      ? String(tokenTypeRaw)
      : null,
    token_type_normalized: tokenTypeNormalized,
    token_type_valid: tokenTypeValid,
    expires_in_raw_type: expiresInRawType,
    expires_in_value: expiresInValue,
    expires_in_valid: expiresInValid,
    refresh_token_present: refreshTokenPresent,
    scope_returned: scopeReturned,
    scope_requested: scopeRequested,
    scope_subset_of_requested: scopeSubset,
    scope_changed: scopeChanged,
    scope_returned_error: scopeReturnedError,
    scope_requested_error: scopeRequestedError,
    error_code: errorCode ? String(errorCode) : null,
    error_description: errorDescription ? String(errorDescription) : null,
    parse_success: parseSuccess,
  };
}

function processOAuth(inputStr) {
  const raw = String(inputStr || "").trim();
  const data = JSON.parse(raw);

  if (!data || typeof data !== "object" || !data.type) {
    throw new Error("Invalid input");
  }

  if (data.type === "token_response") {
    const statusCode = parseInt(data.status_code || "200", 10);
    const body = String(data.body || "");
    const requestedScope = String(data.requested_scope || "");
    return JSON.stringify(checkTokenResponse(statusCode, body, requestedScope));
  }

  // Delegate other types to token request node target
  const { processOAuth: reqProcess } = require("./oauth_tokenreq_node");
  return reqProcess(inputStr);
}

module.exports = { processOAuth };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node oauth_tokenresp_node.js <input_file>\n");
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
