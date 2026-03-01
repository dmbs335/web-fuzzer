/**
 * sanitize-html differential target (process mode).
 *
 * Usage: node sanitizer_sanitize_html_diff.js <input_file>
 * Output: Standardized JSON with security signals.
 */
"use strict";

const fs = require("fs");
const mod = require("./sanitizer_sanitize_html_diff_module");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_sanitize_html_diff.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");
  const result = mod.process(html);
  process.stdout.write(result.output);
  process.exit(result.exitCode);
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
