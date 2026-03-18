/**
 * Markdown target -- marked with GFM extensions.
 * Usage: node markdown_node_marked_gfm.js <input_file>
 */
"use strict";

const fs = require("fs");
const { marked } = require("marked");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

// GFM is enabled by default in marked, but explicitly set options
marked.setOptions({ gfm: true, breaks: true });

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node markdown_node_marked_gfm.js <input_file>\n");
  process.exit(1);
}

try {
  const input = fs.readFileSync(inputPath, "utf8");
  const html = marked.parse(input);
  const result = analyzeRenderedHtml(html);
  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
