/**
 * sanitize-html combined mXSS + diff target (process mode).
 *
 * Usage: node sanitizer_sanitize_html_mxss.js <input_file>
 * Output: JSON with security signals + mXSS detection fields.
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const sanitizeHtml = require("sanitize-html");
const { buildResult } = require("./sanitizer_diff_common");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_sanitize_html_mxss.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");

  const clean = sanitizeHtml(html);
  const result = buildResult(clean);

  const dom2 = new JSDOM(`<body>${clean}</body>`);
  const reparsed = dom2.window.document.body.innerHTML;
  const clean2 = sanitizeHtml(clean);

  result.reparsed = reparsed;
  result.resanitized = clean2;
  result.mxss = clean !== reparsed;
  result.idempotency = clean !== clean2;

  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
