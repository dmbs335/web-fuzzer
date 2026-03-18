/**
 * Persistent module -- permissive Node JWT verifier.
 */
"use strict";

const { verifyJwt } = require("./jwt_node_permissive");

module.exports.process = function (input) {
  try {
    return { output: verifyJwt(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
