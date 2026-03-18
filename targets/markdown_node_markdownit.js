/**
 * Markdown target -- markdown-it (Node.js).
 * Usage: node markdown_node_markdownit.js <input_file>
 * Output: JSON with security signals from rendered HTML.
 */
"use strict";

const fs = require("fs");
const markdownIt = require("markdown-it");
const { analyzeRenderedHtml } = require("./markdown_analysis_common");

const md = markdownIt({ html: true });

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node markdown_node_markdownit.js <input_file>\n");
  process.exit(1);
}

try {
  const input = fs.readFileSync(inputPath, "utf8");
  const html = md.render(input);
  const result = analyzeRenderedHtml(html);
  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
