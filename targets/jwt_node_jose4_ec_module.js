/**
 * Persistent module -- jose4 EC Node JWT verifier.
 */
"use strict";
const { verifyJwt } = require("./jwt_node_jose4_ec");

function process(inputStr) {
  try {
    const output = verifyJwt(inputStr);
    return { output, exit_code: 0 };
  } catch {
    return { output: "", exit_code: 1 };
  }
}

module.exports = { process };
