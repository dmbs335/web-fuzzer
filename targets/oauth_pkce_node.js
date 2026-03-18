/**
 * OAuth PKCE target -- @node-oauth/oauth2-server REAL PKCE validation.
 *
 * Uses REAL library imports:
 *   - @node-oauth/oauth2-server pkce module:
 *     - getHashForCodeChallenge({ method, verifier }): S256 hash computation
 *     - isValidMethod(method): only 'S256' and 'plain' (case-sensitive!)
 *     - codeChallengeMatchesABNF(challenge): 43-128 chars, unreserved only
 *     - isPKCERequest({ grantType, codeVerifier }): detect PKCE request
 *     Source: node_modules/@node-oauth/oauth2-server/lib/pkce/pkce.js
 *
 * Key behavioral differences from other libraries:
 *   - isValidMethod is CASE-SENSITIVE: 'plain' valid, 'PLAIN' invalid
 *   - getHashForCodeChallenge returns undefined for invalid method/verifier
 *   - S256 uses SHA256 + base64url encoding (via crypto-util + string-util)
 *
 * Input:  JSON { type: "pkce", method, verifier, challenge }
 * Output: standardized JSON for differential comparison.
 */
"use strict";

const fs = require("fs");

// --- REAL LIBRARY IMPORT ---
const pkce = require("@node-oauth/oauth2-server/lib/pkce/pkce");

function checkPKCE(method, verifier, challenge) {
  // REAL: @node-oauth PKCE method validation (case-sensitive!)
  // Source: pkce.js `isValidMethod: function(method) { return method === 'S256' || method === 'plain' }`
  const methodValid = pkce.isValidMethod(method || "");

  // REAL: @node-oauth verifier format validation
  // Source: pkce.js `codeChallengeMatchesABNF` — /^([a-zA-Z0-9.\-_~]){43,128}$/
  const verifierValid = pkce.codeChallengeMatchesABNF(verifier || "");

  // REAL: @node-oauth S256/plain hash computation
  // Source: pkce.js `getHashForCodeChallenge({ method, verifier })`
  // Returns undefined if method invalid or verifier empty
  let challengeComputed = null;
  let challengeMatch = false;

  const resolvedMethod = method || "S256";
  const hash = pkce.getHashForCodeChallenge({
    method: resolvedMethod,
    verifier: verifier || "",
  });

  if (hash !== undefined) {
    challengeComputed = hash;
    challengeMatch = hash === challenge;
  }

  return {
    input_type: "pkce",
    method: method,
    method_resolved: resolvedMethod,
    method_valid: methodValid,
    challenge_computed: challengeComputed,
    challenge_match: challengeMatch,
    verifier_valid: verifierValid,
    challenge_has_padding: (challengeComputed || "").includes("="),
    verifier_length: (verifier || "").length,
  };
}

function processOAuth(inputStr) {
  const raw = String(inputStr || "").trim();
  const data = JSON.parse(raw);

  if (!data || typeof data !== "object" || !data.type) {
    throw new Error("Invalid input");
  }

  if (data.type === "pkce") {
    const methodWasAbsent = !("method" in data);
    const challengeWasAbsent = !("challenge" in data);
    const verifierWasAbsent = !("verifier" in data);
    const method = String(data.method || "S256");
    const verifier = String(data.verifier || "");
    const challenge = String(data.challenge || "");
    const result = checkPKCE(method, verifier, challenge);
    result.method_was_absent = methodWasAbsent;
    result.challenge_was_absent = challengeWasAbsent;
    result.verifier_was_absent = verifierWasAbsent;
    return JSON.stringify(result);
  }

  // For scope/redirect_uri, delegate to oidcprovider target
  const { processOAuth: oidcProcess } = require("./oauth_redirect_oidcprovider");
  return oidcProcess(inputStr);
}

module.exports = { processOAuth };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node oauth_pkce_node.js <input_file>\n");
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
