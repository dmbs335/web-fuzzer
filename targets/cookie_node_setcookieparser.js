/**
 * Cookie parser target — Node.js set-cookie-parser.
 *
 * Parses Set-Cookie header values using the set-cookie-parser npm
 * package and outputs parsed components as JSON for differential
 * comparison.
 *
 * set-cookie-parser is the most popular dedicated Set-Cookie parser
 * for Node.js, used by many frameworks and HTTP clients.
 *
 * References:
 *   - RFC 6265bis (Cookies: HTTP State Management Mechanism)
 *   - npm: set-cookie-parser
 */
"use strict";

const fs = require("fs");
const setCookieParser = require("set-cookie-parser");

function parseCookie(data) {
  data = data.trim();
  if (!data) throw new Error("Empty input");

  const cookies = setCookieParser.parse(data, { decodeValues: false });
  if (!cookies || cookies.length === 0) {
    throw new Error("No cookies parsed");
  }

  const c = cookies[0];
  return JSON.stringify({
    name: c.name || "",
    value: c.value || "",
    domain: c.domain || "",
    path: c.path || "",
    expires: c.expires ? c.expires.toUTCString() : "",
    max_age: c.maxAge !== undefined ? String(c.maxAge) : "",
    secure: !!c.secure,
    httponly: !!c.httpOnly,
    samesite: c.sameSite || "",
  });
}

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("Usage: node cookie_node_setcookieparser.js <file>\n");
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
    const result = parseCookie(data);
    process.stdout.write(result + "\n");
    process.exit(0);
  } catch (e) {
    process.stderr.write("REJECT: " + e.message + "\n");
    process.exit(1);
  }
}

main();
