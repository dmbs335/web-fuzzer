/**
 * node-saml persistent module for SAML verification.
 * Imports verifySaml from the one-shot script to avoid code duplication.
 * Returns a Promise (async) — persistent_wrapper.js handles this.
 * Exports process(input) for use with persistent_wrapper.js.
 */
"use strict";

const { verifySaml } = require("./saml_nodesaml");

module.exports.process = async function (input) {
  try {
    const output = await verifySaml(input);
    return { output, exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
