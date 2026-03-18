/**
 * Persistent module -- pac4j-like nested JWT verifier.
 */
"use strict";

const { verifyJwt } = require("./jwt_node_pac4j_like");

module.exports.process = function (input) {
  try {
    return { output: verifyJwt(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
