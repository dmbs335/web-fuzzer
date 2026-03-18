/**
 * Persistent module -- oidc-provider style OAuth redirect_uri verifier.
 */
"use strict";

const { processOAuth } = require("./oauth_redirect_oidcprovider");

module.exports.process = function (input) {
  try {
    return { output: processOAuth(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
