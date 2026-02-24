/**
 * Persistent module — WHATWG URL parser.
 *
 * Exports process(input) for use with persistent_wrapper.js.
 * Returns {output, exitCode} where output is JSON-serialized
 * URL components.
 */
"use strict";

function process(input) {
  const data = input.trim();
  if (!data) {
    return { output: "", exitCode: 1 };
  }

  let parsed;
  try {
    parsed = new URL(data);
  } catch (_) {
    try {
      parsed = new URL(data, "http://placeholder.invalid/");
    } catch (e) {
      return { output: "", exitCode: 1 };
    }
  }

  let userinfo = "";
  if (parsed.username || parsed.password) {
    userinfo = parsed.username;
    if (parsed.password) {
      userinfo += ":" + parsed.password;
    }
  }

  const result = JSON.stringify({
    scheme: parsed.protocol ? parsed.protocol.replace(/:$/, "") : "",
    userinfo: userinfo,
    host: parsed.hostname || "",
    port: parsed.port || "",
    path: parsed.pathname || "",
    query: parsed.search ? parsed.search.slice(1) : "",
    fragment: parsed.hash ? parsed.hash.slice(1) : "",
  });

  return { output: result, exitCode: 0 };
}

module.exports = { process };
