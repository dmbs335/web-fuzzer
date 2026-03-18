/**
 * Persistent module -- Node.js token response target.
 */
"use strict";

const { processOAuth } = require("./oauth_tokenresp_node");

module.exports = {
  process(input) {
    try {
      const output = processOAuth(input);
      return { output, exitCode: 0 };
    } catch {
      return { output: "", exitCode: 1 };
    }
  },
};
