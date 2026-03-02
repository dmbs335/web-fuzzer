/**
 * Persistent module — tough-cookie.
 *
 * Exports process(input) for use with persistent_wrapper.js.
 */
"use strict";

const { Cookie } = require("tough-cookie");

function process(input) {
  const data = input.trim();
  if (!data) {
    return { output: "", exitCode: 1 };
  }

  try {
    const c = Cookie.parse(data);
    if (!c) {
      return { output: "", exitCode: 1 };
    }
    const result = JSON.stringify({
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
    return { output: result, exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
}

module.exports = { process };
