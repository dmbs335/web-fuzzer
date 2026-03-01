/**
 * xml-crypto persistent module for SAML verification.
 * Imports verifySaml from the one-shot script to avoid code duplication.
 * Exports process(input) for use with persistent_wrapper.js.
 */
"use strict";

const { verifySaml } = require("./saml_xmlcrypto");

module.exports.process = function (input) {
  try {
    return { output: verifySaml(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
