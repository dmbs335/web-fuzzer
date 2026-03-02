/**
 * Cookie parser target — Node.js tough-cookie.
 *
 * Parses Set-Cookie header values using tough-cookie's Cookie.parse()
 * and outputs parsed components as JSON for differential comparison.
 *
 * tough-cookie is a comprehensive cookie jar implementation that
 * strictly follows RFC 6265. It's used by got, axios-cookiejar,
 * and many HTTP clients.
 *
 * References:
 *   - RFC 6265bis (Cookies: HTTP State Management Mechanism)
 *   - npm: tough-cookie
 */
"use strict";

const fs = require("fs");
const { Cookie } = require("tough-cookie");

function parseCookie(data) {
  data = data.trim();
  if (!data) throw new Error("Empty input");

  const c = Cookie.parse(data);
  if (!c) {
    throw new Error("No cookies parsed");
  }

  return JSON.stringify({
    name: c.key || "",
    value: c.value || "",
    domain: c.domain || "",
    path: c.path || "",
    expires: c.expires && c.expires !== "Infinity" ? new Date(c.expires).toUTCString() : "",
    max_age: c.maxAge !== undefined && c.maxAge !== null && c.maxAge !== "Infinity"
      ? String(c.maxAge) : "",
    secure: !!c.secure,
    httponly: !!c.httpOnly,
    samesite: c.sameSite || "",
    hostonly: !!c.hostOnly,
  });
}

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("Usage: node cookie_node_toughcookie.js <file>\n");
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
