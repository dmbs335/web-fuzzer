/**
 * URL parser target — Node.js Legacy url.parse().
 *
 * Parses URLs using the legacy Node.js url.parse() API and outputs
 * parsed components as JSON for differential comparison.
 *
 * Legacy url.parse() has known divergences from WHATWG:
 *   - Does NOT normalize backslash to forward slash
 *   - Looser scheme validation
 *   - Different handling of authority vs path-only URLs
 *   - Different percent-decoding behavior
 *   - Known SSRF-relevant parsing differences with userinfo
 *
 * References:
 *   - Node.js url.parse() docs (legacy API)
 *   - CVE-2018-12116 (Node.js HTTP request splitting via url.parse)
 */
"use strict";

const fs = require("fs");
const url = require("url");

function parseUrl(data) {
  data = data.trim();
  if (!data) throw new Error("Empty input");

  const parsed = url.parse(data);

  // Extract userinfo
  let userinfo = "";
  if (parsed.auth) {
    userinfo = parsed.auth;
  }

  // Extract host without port
  const host = parsed.hostname || "";

  // Extract port
  const port = parsed.port || "";

  // Extract path (url.parse combines path + search)
  let path = parsed.pathname || "";

  // Extract query without leading ?
  let query = "";
  if (parsed.search) {
    query = parsed.search.startsWith("?")
      ? parsed.search.slice(1)
      : parsed.search;
  }

  // Extract fragment without leading #
  let fragment = "";
  if (parsed.hash) {
    fragment = parsed.hash.startsWith("#")
      ? parsed.hash.slice(1)
      : parsed.hash;
  }

  return JSON.stringify({
    scheme: parsed.protocol ? parsed.protocol.replace(/:$/, "") : "",
    userinfo: userinfo,
    host: host,
    port: port,
    path: path,
    query: query,
    fragment: fragment,
  });
}

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("Usage: node url_node_legacy.js <file>\n");
    process.exit(2);
  }

  let data;
  try {
    data = fs.readFileSync(process.argv[2], "utf8");
  } catch (e) {
    process.stderr.write("IO error: " + e.message + "\n");
    process.exit(2);
  }

  try {
    const result = parseUrl(data);
    process.stdout.write(result + "\n");
    process.exit(0);
  } catch (e) {
    process.stderr.write("REJECT: " + e.message + "\n");
    process.exit(1);
  }
}

main();
