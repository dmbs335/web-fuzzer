/**
 * markdown-it module for persistent wrapper.
 */
"use strict";

const markdownIt = require("markdown-it");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

const md = markdownIt({ html: true });

module.exports.sanitize = (input) => {
  const html = md.render(input);
  return JSON.stringify(analyzeRenderedHtml(html));
};
