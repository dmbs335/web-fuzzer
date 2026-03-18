/**
 * Persistent module -- fast-jwt Node JWT verifier.
 */
"use strict";

const { verifyJwt } = require("./jwt_node_fastjwt");

module.exports.process = function (input) {
  try {
    return { output: verifyJwt(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
