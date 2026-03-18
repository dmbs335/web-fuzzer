/**
 * Persistent module -- @node-oauth/oauth2-server style OAuth redirect_uri verifier.
 */
"use strict";

const { processOAuth } = require("./oauth_redirect_nodeoauth2");

module.exports.process = function (input) {
  try {
    return { output: processOAuth(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
