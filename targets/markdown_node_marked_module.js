/**
 * marked markdown module for persistent wrapper.
 */
"use strict";

const { marked } = require("marked");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

module.exports.sanitize = (md) => {
  const html = marked.parse(md);
  return JSON.stringify(analyzeRenderedHtml(html));
};
