/**
 * sanitize-html target for differential fuzzing.
 *
 * Usage: node sanitizer_sanitize_html.js <input_file>
 * Output: sanitized HTML to stdout
 */
"use strict";

const fs = require("fs");
const sanitizeHtml = require("sanitize-html");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_sanitize_html.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");
  const clean = sanitizeHtml(html);
  process.stdout.write(clean);
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
