/**
 * markdown-it (html disabled) module for persistent wrapper.
 */
"use strict";

const markdownIt = require("markdown-it");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

const md = markdownIt({ html: false, linkify: true });

module.exports.sanitize = (input) => {
  const html = md.render(input);
  return JSON.stringify(analyzeRenderedHtml(html));
};
