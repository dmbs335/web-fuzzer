/**
 * Persistent module — set-cookie-parser.
 *
 * Exports process(input) for use with persistent_wrapper.js.
 */
"use strict";

const setCookieParser = require("set-cookie-parser");

function process(input) {
  const data = input.trim();
  if (!data) {
    return { output: "", exitCode: 1 };
  }

  try {
    const cookies = setCookieParser.parse(data, { decodeValues: false });
    if (!cookies || cookies.length === 0) {
      return { output: "", exitCode: 1 };
    }
    const c = cookies[0];
    const result = JSON.stringify({
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
    return { output: result, exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
}

module.exports = { process };
