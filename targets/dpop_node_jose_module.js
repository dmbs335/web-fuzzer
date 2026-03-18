const { processDPoP } = require("./dpop_node_jose");
module.exports.process = function (input) {
  try { return { output: processDPoP(input), exitCode: 0 }; }
  catch (e) { return { output: "", exitCode: 1 }; }
};
