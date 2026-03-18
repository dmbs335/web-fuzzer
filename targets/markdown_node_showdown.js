/**
 * Markdown target -- showdown (Node.js).
 * Usage: node markdown_node_showdown.js <input_file>
 * Output: JSON with security signals from rendered HTML.
 */
"use strict";

const fs = require("fs");
const showdown = require("showdown");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

const converter = new showdown.Converter();

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node markdown_node_showdown.js <input_file>\n");
  process.exit(1);
}

try {
  const md = fs.readFileSync(inputPath, "utf8");
  const html = converter.makeHtml(md);
  const result = analyzeRenderedHtml(html);
  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
