/**
 * Persistent module -- Node.js token request target.
 */
"use strict";

const { processOAuth } = require("./oauth_tokenreq_node");

module.exports = {
  process(inputStr) {
    try {
      const output = processOAuth(inputStr);
      return { output, exitCode: 0 };
    } catch {
      return { output: "", exitCode: 1 };
    }
  },
};
