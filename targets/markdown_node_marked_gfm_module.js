/**
 * marked GFM module for persistent wrapper.
 */
"use strict";

const { marked } = require("marked");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

marked.setOptions({ gfm: true, breaks: true });

module.exports.sanitize = (input) => {
  const html = marked.parse(input);
  return JSON.stringify(analyzeRenderedHtml(html));
};
