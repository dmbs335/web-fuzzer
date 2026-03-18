/**
 * DOMPurify mXSS target with XHTML parser mode.
 *
 * Usage: node sanitizer_dompurify_mxss_xhtml.js <input_file>
 *
 * PARSER_MEDIA_TYPE: "application/xhtml+xml" switches DOMPurify to
 * XML parsing mode where CDATA sections and Processing Instructions
 * are handled differently than HTML mode.
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { buildResult } = require("./sanitizer_diff_common");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_dompurify_mxss_xhtml.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);

  const clean = purify.sanitize(html, { PARSER_MEDIA_TYPE: "application/xhtml+xml" });
  const result = buildResult(clean);

  const reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  reparseWindow.document.body.innerHTML = clean;
  const reparsed = reparseWindow.document.body.innerHTML;
  const clean2 = purify.sanitize(clean, { PARSER_MEDIA_TYPE: "application/xhtml+xml" });

  result.reparsed = reparsed;
  result.resanitized = clean2;
  result.mxss = clean !== reparsed;
  result.idempotency = clean !== clean2;

  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
