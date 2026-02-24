/**
 * Persistent module — Node.js legacy URL parser.
 *
 * Exports process(input) for use with persistent_wrapper.js.
 * Returns {output, exitCode} where output is JSON-serialized
 * URL components.
 */
"use strict";

const url = require("url");

function process(input) {
  const data = input.trim();
  if (!data) {
    return { output: "", exitCode: 1 };
  }

  try {
    const parsed = url.parse(data);

    const userinfo = parsed.auth || "";
    const host = parsed.hostname || "";
    const port = parsed.port || "";
    const path = parsed.pathname || "";

    let query = "";
    if (parsed.search) {
      query = parsed.search.startsWith("?")
        ? parsed.search.slice(1)
        : parsed.search;
    }

    let fragment = "";
    if (parsed.hash) {
      fragment = parsed.hash.startsWith("#")
        ? parsed.hash.slice(1)
        : parsed.hash;
    }

    const result = JSON.stringify({
      scheme: parsed.protocol ? parsed.protocol.replace(/:$/, "") : "",
      userinfo: userinfo,
      host: host,
      port: port,
      path: path,
      query: query,
      fragment: fragment,
    });

    return { output: result, exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
}

module.exports = { process };
