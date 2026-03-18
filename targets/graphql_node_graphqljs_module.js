/**
 * Persistent module -- graphql-js Node GraphQL analyzer.
 */
"use strict";

const { analyzeQuery } = require("./graphql_node_graphqljs");

module.exports.process = function (input) {
  try {
    return { output: analyzeQuery(input), exitCode: 0 };
  } catch (e) {
    return { output: "", exitCode: 1 };
  }
};
