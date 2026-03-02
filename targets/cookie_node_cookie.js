/**
 * Cookie parser target — Node.js cookie (npm).
 *
 * Parses Set-Cookie header values using the cookie npm package.
 * This library has a manual Set-Cookie attribute parser since
 * cookie.parse() only handles Cookie headers (name=value pairs).
 *
 * CVE-2024-47764: Out-of-bounds character injection in cookie
 * name/path/domain enabling XSS/injection attacks.
 *
 * References:
 *   - RFC 6265bis (Cookies: HTTP State Management Mechanism)
 *   - npm: cookie
 *   - CVE-2024-47764 (cookie <0.7.0)
 */
"use strict";

const fs = require("fs");
const cookie = require("cookie");

function parseCookie(data) {
  data = data.trim();
  if (!data) throw new Error("Empty input");

  // cookie.parse() parses "Cookie:" header format (name=value pairs)
  // For Set-Cookie, we manually extract name=value and attributes
  const parts = data.split(/;\s*/);
  if (parts.length === 0 || !parts[0].includes("=")) {
    throw new Error("No cookies parsed");
  }

  // First part is name=value
  const eqIdx = parts[0].indexOf("=");
  const name = parts[0].substring(0, eqIdx).trim();
  const value = parts[0].substring(eqIdx + 1).trim();

  if (!name) {
    throw new Error("Empty cookie name");
  }

  // Parse remaining parts as attributes
  const attrs = {
    domain: "",
    path: "",
    expires: "",
    max_age: "",
    secure: false,
    httponly: false,
    samesite: "",
  };

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i].trim();
    if (!part) continue;

    const attrEq = part.indexOf("=");
    let attrName, attrValue;
    if (attrEq === -1) {
      attrName = part.toLowerCase();
      attrValue = "";
    } else {
      attrName = part.substring(0, attrEq).trim().toLowerCase();
      attrValue = part.substring(attrEq + 1).trim();
    }

    switch (attrName) {
      case "domain": attrs.domain = attrValue; break;
      case "path": attrs.path = attrValue; break;
      case "expires":
        try {
          const d = new Date(attrValue);
          attrs.expires = isNaN(d.getTime()) ? attrValue : d.toUTCString();
        } catch (_) {
          attrs.expires = attrValue;
        }
        break;
      case "max-age": attrs.max_age = attrValue; break;
      case "secure": attrs.secure = true; break;
      case "httponly": attrs.httponly = true; break;
      case "samesite": attrs.samesite = attrValue; break;
    }
  }

  // Also validate via cookie.parse to detect library-level parsing diffs
  let libParsed;
  try {
    libParsed = cookie.parse(name + "=" + value);
  } catch (_) {
    libParsed = {};
  }

  const libValue = libParsed[name] !== undefined ? libParsed[name] : value;

  return JSON.stringify({
    name: name,
    value: libValue,
    domain: attrs.domain,
    path: attrs.path,
    expires: attrs.expires,
    max_age: attrs.max_age,
    secure: attrs.secure,
    httponly: attrs.httponly,
    samesite: attrs.samesite,
  });
}

function main() {
  if (process.argv.length < 3) {
    process.stderr.write("Usage: node cookie_node_cookie.js <file>\n");
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
