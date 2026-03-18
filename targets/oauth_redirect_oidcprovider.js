/**
 * OAuth redirect_uri target -- oidc-provider (panva) REAL validation logic.
 *
 * Uses the EXACT algorithm from oidc-provider v9.x:
 *   Source: node_modules/oidc-provider/lib/models/client.js:432-459
 *   - URL.parse(value)?.href comparison (WHATWG URL normalization)
 *   - For native apps on loopback, port-agnostic matching (RFC 8252)
 *
 * Scope parsing uses REAL @node-oauth/oauth2-server parseScope():
 *   Source: node_modules/@node-oauth/oauth2-server/lib/utils/scope-util.js
 *   - Validates NQSCHAR format before splitting on \s+
 *   - Rejects tabs, newlines, control characters
 *
 * Input:  JSON { type, registered, candidate } or { type, granted, requested }
 * Output: standardized JSON for differential comparison.
 * Exit 0 = processed, Exit 1 = parse failure.
 */
"use strict";

const fs = require("fs");

// --- REAL LIBRARY IMPORTS ---
const { parseScope } = require("@node-oauth/oauth2-server/lib/utils/scope-util");

// Loopback addresses for RFC 8252 native app matching
// Source: oidc-provider/lib/models/client.js
const LOOPBACKS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function parseInput(raw) {
  const text = Buffer.isBuffer(raw) ? raw.toString("utf8") : String(raw);
  return JSON.parse(text);
}

/**
 * EXACT replica of oidc-provider #redirectAllowed() from:
 * oidc-provider/lib/models/client.js lines 432-459
 *
 * Uses URL.parse() (WHATWG URL API) for normalization, then compares .href.
 */
function checkRedirectUri(registered, candidate, applicationType) {
  // oidc-provider uses URL.parse() which returns null on failure (no throw)
  const parsed = URL.parse(candidate);
  if (!parsed) {
    return {
      redirect_match: false,
      redirect_matched_index: null,
      candidate_scheme: null,
      candidate_host: null,
      candidate_port: null,
      candidate_path: null,
      candidate_normalized: null,
      loopback_detected: false,
      fragment_present: candidate.includes("#"),
    };
  }

  const fragment_present = parsed.hash.length > 0;

  // Step 1: Exact .href match against registered URIs (normalized comparison)
  // Source: `allowedUris.find((allowed) => URL.parse(allowed)?.href === parsed.href)`
  let matchIdx = null;
  for (let i = 0; i < registered.length; i++) {
    const reg = URL.parse(registered[i]);
    if (reg && reg.href === parsed.href) {
      matchIdx = i;
      break;
    }
  }

  // Step 2: Loopback port-agnostic matching for native apps (RFC 8252)
  // Source: oidc-provider checks applicationType !== 'native', protocol, hostname
  let loopback_detected = false;
  if (
    matchIdx === null &&
    applicationType === "native" &&
    parsed.protocol === "http:" &&
    LOOPBACKS.has(parsed.hostname)
  ) {
    loopback_detected = true;
    const parsedNoPort = new URL(parsed.href);
    parsedNoPort.port = "";
    for (let i = 0; i < registered.length; i++) {
      const reg = URL.parse(registered[i]);
      if (!reg) continue;
      const regNoPort = new URL(reg.href);
      regNoPort.port = "";
      if (parsedNoPort.href === regNoPort.href) {
        matchIdx = i;
        break;
      }
    }
  }

  return {
    redirect_match: matchIdx !== null,
    redirect_matched_index: matchIdx,
    candidate_scheme: parsed.protocol.replace(/:$/, ""),
    candidate_host: parsed.hostname,
    candidate_port: parsed.port || null,
    candidate_path: parsed.pathname,
    candidate_normalized: parsed.href,
    loopback_detected,
    fragment_present,
  };
}

/**
 * Scope parsing using REAL @node-oauth parseScope().
 * Source: @node-oauth/oauth2-server/lib/utils/scope-util.js
 *
 * parseScope() validates NQSCHAR format then splits on \s+.
 * Tabs, newlines, control chars → InvalidScopeError (thrown).
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

  // Count empty elements from raw space-split for comparison metadata
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
 * Token exchange: oidc-provider compares redirect_uri via normalized .href.
 * Source: oidc-provider/lib/actions/grants/authorization_code.js
 *   `if (code.redirectUri !== ctx.oidc.params.redirect_uri)`
 *
 * Note: The token endpoint does raw string comparison for redirect_uri match
 * (not URL-normalized). But the authorization endpoint uses URL.parse().href
 * for the initial registration check.
 */
function checkTokenExchange(data) {
  const registered = Array.isArray(data.registered) ? data.registered : [];
  const authUri = String(data.auth_redirect_uri || "");
  const tokenUri = data.token_redirect_uri;

  const authParsed = URL.parse(authUri);
  const authNormalized = authParsed ? authParsed.href : authUri;
  const authHost = authParsed ? authParsed.hostname : null;
  const authPort = authParsed ? authParsed.port || null : null;

  // Authorization endpoint: URL.parse().href comparison
  let authMatch = false;
  for (const r of registered) {
    const rParsed = URL.parse(r);
    if (rParsed && authParsed && rParsed.href === authParsed.href) {
      authMatch = true;
      break;
    }
  }

  let tokenMatch = false;
  let uriIdentical = false;
  let tokenNormalized = null;
  let tokenHost = null;
  let tokenPort = null;

  if (tokenUri != null) {
    const tokenStr = String(tokenUri);
    const tokenParsed = URL.parse(tokenStr);
    tokenNormalized = tokenParsed ? tokenParsed.href : tokenStr;
    tokenHost = tokenParsed ? tokenParsed.hostname : null;
    tokenPort = tokenParsed ? tokenParsed.port || null : null;

    // Token endpoint: raw string comparison (oidc-provider)
    // Source: authorization_code.js `if (code.redirectUri !== ctx.oidc.params.redirect_uri)`
    // But for registration check we still use URL-normalized comparison
    for (const r of registered) {
      const rParsed = URL.parse(r);
      if (rParsed && tokenParsed && rParsed.href === tokenParsed.href) {
        tokenMatch = true;
        break;
      }
    }

    uriIdentical = authNormalized === tokenNormalized;
  }

  return {
    input_type: "token_exchange",
    auth_match: authMatch,
    token_match: tokenMatch,
    uri_identical: uriIdentical,
    auth_normalized: authNormalized,
    token_normalized: tokenNormalized,
    auth_host: authHost,
    token_host: tokenHost,
    auth_port: authPort,
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
    const appType = data.application_type || "web";
    const redir = checkRedirectUri(registered, candidate, appType);
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
      "Usage: node oauth_redirect_oidcprovider.js <input_file>\n"
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
