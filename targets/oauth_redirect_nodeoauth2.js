/**
 * OAuth redirect_uri target -- @node-oauth/oauth2-server REAL validation logic.
 *
 * Uses REAL library imports:
 *   - @node-oauth/formats: isFormat.uri() for URI format validation
 *     Source: node_modules/@node-oauth/formats/index.js
 *   - @node-oauth/oauth2-server parseScope(): NQSCHAR validation + \s+ split
 *     Source: node_modules/@node-oauth/oauth2-server/lib/utils/scope-util.js
 *
 * Redirect URI matching: client.redirectUris.includes(redirectUri)
 *   Source: node_modules/@node-oauth/oauth2-server/lib/handlers/authorize-handler.js:304-310
 *   This is exact string match with NO URL normalization.
 *
 * Input:  JSON { type, registered, candidate } or { type, granted, requested }
 * Output: standardized JSON for differential comparison.
 * Exit 0 = processed, Exit 1 = parse failure.
 */
"use strict";

const fs = require("fs");

// --- REAL LIBRARY IMPORTS ---
const isFormat = require("@node-oauth/formats");
const { parseScope } = require("@node-oauth/oauth2-server/lib/utils/scope-util");

function parseInput(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
  return JSON.parse(text);
}

function urlComponents(candidate) {
  try {
    const u = new URL(candidate);
    return {
      scheme: u.protocol.replace(/:$/, ""),
      host: u.hostname,
      port: u.port || null,
      path: u.pathname,
    };
  } catch {
    const schemeMatch = candidate.match(/^([a-zA-Z][a-zA-Z0-9+\-.]*):\/\//);
    return {
      scheme: schemeMatch ? schemeMatch[1] : null,
      host: null,
      port: null,
      path: null,
    };
  }
}

/**
 * Redirect URI validation using REAL @node-oauth logic.
 *
 * Format check: isFormat.uri() from @node-oauth/formats
 *   Source: /^[a-zA-Z][a-zA-Z0-9+.-]+:/
 *
 * Match: client.redirectUris.includes(redirectUri) — exact string comparison
 *   Source: authorize-handler.js:304-310
 *
 * Also validates redirect_uri format at token endpoint:
 *   Source: authorization-code-grant-type.js:149-163
 *   Uses isFormat.uri() check before string comparison.
 */
function checkRedirectUri(registered, candidate) {
  // REAL library validation: isFormat.uri() from @node-oauth/formats
  const isValid = isFormat.uri(candidate);
  const fragment_present = candidate.includes("#");
  const components = urlComponents(candidate);

  if (!isValid) {
    return {
      redirect_match: false,
      redirect_matched_index: null,
      candidate_scheme: components.scheme,
      candidate_host: components.host,
      candidate_port: components.port,
      candidate_path: components.path,
      candidate_normalized: candidate,
      candidate_format_valid: false,
      loopback_detected: false,
      fragment_present,
    };
  }

  // REAL library match: Array.includes() — exact string comparison, NO normalization
  // Source: authorize-handler.js `client.redirectUris.includes(redirectUri)`
  const matchIdx = registered.indexOf(candidate);

  return {
    redirect_match: matchIdx !== -1,
    redirect_matched_index: matchIdx !== -1 ? matchIdx : null,
    candidate_scheme: components.scheme,
    candidate_host: components.host,
    candidate_port: components.port,
    candidate_path: components.path,
    candidate_normalized: candidate,
    candidate_format_valid: true,
    loopback_detected: false,
    fragment_present,
  };
}

/**
 * Scope parsing using REAL @node-oauth parseScope().
 * Source: @node-oauth/oauth2-server/lib/utils/scope-util.js
 *
 * Behavior:
 *   1. Validates NQSCHAR format: /^[\u0020-\u0021\u0023-\u005B\u005D-\u007E]+$/
 *   2. Trims whitespace
 *   3. Splits on /\s+/g (any whitespace sequence)
 *   4. Throws InvalidScopeError for tabs, newlines, control chars
 */
function checkScope(granted, requested) {
  let grantedList, requestedList;
  let grantedError = null, requestedError = null;

  try {
    grantedList = parseScope(granted || null);
    if (grantedList === undefined) grantedList = [];
  } catch (e) {
    grantedList = [];
    grantedError = e.message;
  }

  try {
    requestedList = parseScope(requested || null);
    if (requestedList === undefined) requestedList = [];
  } catch (e) {
    requestedList = [];
    requestedError = e.message;
  }

  const grantedSet = new Set(grantedList);
  const allMatch = requestedList.every((s) => grantedSet.has(s));

  const rawParts = granted ? granted.split(" ") : [];

  return {
    scope_match: allMatch,
    scope_parsed_granted: grantedList,
    scope_parsed_requested: requestedList,
    scope_count_granted: grantedList.length,
    scope_count_requested: requestedList.length,
    scope_empty_elements: rawParts.filter((s) => s === "").length,
    scope_parse_error_granted: grantedError,
    scope_parse_error_requested: requestedError,
  };
}

/**
 * Token exchange: @node-oauth uses raw string comparison for redirect_uri.
 * Source: authorization-code-grant-type.js:155
 *   `if (redirectUri !== code.redirectUri)`
 */
function checkTokenExchange(data) {
  const registered = Array.isArray(data.registered) ? data.registered : [];
  const authUri = String(data.auth_redirect_uri || "");
  const tokenUri = data.token_redirect_uri;

  const authComponents = urlComponents(authUri);

  // Exact string match — NO normalization
  const authMatch = registered.includes(authUri);

  let tokenMatch = false;
  let uriIdentical = false;
  let tokenNormalized = null;
  let tokenHost = null;
  let tokenPort = null;

  if (tokenUri != null) {
    const tokenStr = String(tokenUri);
    const tokenComponents = urlComponents(tokenStr);
    tokenMatch = registered.includes(tokenStr);
    uriIdentical = authUri === tokenStr;
    tokenNormalized = tokenStr;
    tokenHost = tokenComponents.host;
    tokenPort = tokenComponents.port;
  }

  return {
    input_type: "token_exchange",
    auth_match: authMatch,
    token_match: tokenMatch,
    uri_identical: uriIdentical,
    auth_normalized: authUri,
    token_normalized: tokenNormalized,
    auth_host: authComponents.host,
    token_host: tokenHost,
    auth_port: authComponents.port,
    token_port: tokenPort,
  };
}

function processOAuth(inputStr) {
  const raw = String(inputStr || "").trim();
  const data = parseInput(raw);

  if (!data || typeof data !== "object" || !data.type) {
    throw new Error("Invalid input: must be JSON with 'type' field");
  }

  const result = {
    input_type: data.type,
    redirect_match: null,
    redirect_matched_index: null,
    candidate_scheme: null,
    candidate_host: null,
    candidate_port: null,
    candidate_path: null,
    candidate_normalized: null,
    loopback_detected: null,
    fragment_present: null,
    scope_match: null,
    scope_parsed_granted: null,
    scope_parsed_requested: null,
    scope_count_granted: null,
    scope_count_requested: null,
    scope_empty_elements: null,
  };

  if (data.type === "redirect_uri") {
    const registered = Array.isArray(data.registered) ? data.registered : [];
    const candidate = String(data.candidate || "");
    const redir = checkRedirectUri(registered, candidate);
    Object.assign(result, redir);
  } else if (data.type === "scope") {
    const granted = data.granted != null ? String(data.granted) : "";
    const requested = data.requested != null ? String(data.requested) : "";
    const sc = checkScope(granted, requested);
    Object.assign(result, sc);
  } else if (data.type === "token_exchange") {
    return JSON.stringify(checkTokenExchange(data));
  }

  return JSON.stringify(result);
}

module.exports = { processOAuth };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write(
      "Usage: node oauth_redirect_nodeoauth2.js <input_file>\n"
    );
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
