/**
 * js-xss combined mXSS + diff target (process mode).
 *
 * Usage: node sanitizer_jsxss_mxss.js <input_file>
 * Output: JSON with security signals + mXSS detection fields.
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const xss = require("xss");
const { buildResult } = require("./sanitizer_diff_common");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_jsxss_mxss.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");

  const clean = xss(html);
  const result = buildResult(clean);

  const reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  reparseWindow.document.body.innerHTML = clean;
  const reparsed = reparseWindow.document.body.innerHTML;
  const clean2 = xss(clean);

  result.reparsed = reparsed;
  result.resanitized = clean2;
  result.mxss = clean !== reparsed;
  result.idempotency = clean !== clean2;

  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
