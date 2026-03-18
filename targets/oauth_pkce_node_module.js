/**
 * Persistent module -- Node.js PKCE target.
 */
"use strict";

const { processOAuth } = require("./oauth_pkce_node");

module.exports.process = function (input) {
  try {
    return { output: processOAuth(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
