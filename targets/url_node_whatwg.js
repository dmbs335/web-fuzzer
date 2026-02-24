/**
 * URL parser target — Node.js WHATWG URL Standard.
 *
 * Parses URLs using the WHATWG URL API (new URL()) and outputs
 * parsed components as JSON for differential comparison.
 *
 * The WHATWG URL Standard differs from RFC 3986 in many ways:
 *   - Backslash normalization (\ → /)
 *   - Special scheme handling (http, https, ftp, ws, wss, file)
 *   - Percent-encoding normalization
 *   - Punycode for hostnames
 *   - Strict scheme validation
 *
 * References:
 *   - WHATWG URL Standard (https://url.spec.whatwg.org/)
 *   - Node.js URL docs
 */
"use strict";

const fs = require("fs");

function parseUrl(data) {
  data = data.trim();
  if (!data) throw new Error("Empty input");

  let parsed;
  try {
    parsed = new URL(data);
  } catch (_) {
    // Retry with base URL for relative references
    try {
      parsed = new URL(data, "http://placeholder.invalid/");
    } catch (e) {
      throw new Error("Invalid URL: " + e.message);
    }
  }

  // Extract userinfo
  let userinfo = "";
  if (parsed.username || parsed.password) {
    userinfo = parsed.username;
    if (parsed.password) {
      userinfo += ":" + parsed.password;
    }
  }

  // Extract host without port
  const host = parsed.hostname || "";

  // Extract port (WHATWG omits default ports)
  const port = parsed.port || "";

  // Extract path
  const path = parsed.pathname || "";

  // Extract query without leading ?
  const query = parsed.search ? parsed.search.slice(1) : "";

  // Extract fragment without leading #
  const fragment = parsed.hash ? parsed.hash.slice(1) : "";

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
    process.stderr.write("Usage: node url_node_whatwg.js <file>\n");
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
