/**
 * Persistent module wrapper for GraphQL execution target (graphql-js).
 */
"use strict";
const { analyzeQuery } = require("./graphql_node_graphqljs_exec");

module.exports.process = async function (input) {
  try {
    const result = await analyzeQuery(input);
    return { output: result, exitCode: 0 };
  } catch (err) {
    return { output: "", exitCode: 1 };
  }
};
