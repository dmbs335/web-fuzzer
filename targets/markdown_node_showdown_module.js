/**
 * showdown module for persistent wrapper.
 */
"use strict";

const showdown = require("showdown");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

const converter = new showdown.Converter();

module.exports.sanitize = (md) => {
  const html = converter.makeHtml(md);
  return JSON.stringify(analyzeRenderedHtml(html));
};
