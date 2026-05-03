/**
 * node-saml persistent module with time validation enabled.
 *
 * Exports process(input) for use with persistent_wrapper.js.
 */
"use strict";

process.env.SAML_NODESAML_ACCEPTED_CLOCK_SKEW_MS = "0";

const { verifySaml } = require("./saml_nodesaml");

module.exports.process = async function (input) {
  try {
    const output = await verifySaml(input);
    return { output, exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
