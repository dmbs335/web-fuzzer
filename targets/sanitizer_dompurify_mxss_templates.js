/**
 * DOMPurify mXSS target with SAFE_FOR_TEMPLATES config.
 *
 * Usage: node sanitizer_dompurify_mxss_templates.js <input_file>
 *
 * SAFE_FOR_TEMPLATES removes mustache/ERB/ASP patterns ({{, <%, etc.)
 * but had a regex flaw (CVE-2025-26791) enabling bypass via crafted
 * template delimiters.
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { buildResult } = require("./sanitizer_diff_common");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_dompurify_mxss_templates.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);

  const clean = purify.sanitize(html, { SAFE_FOR_TEMPLATES: true });
  const result = buildResult(clean);

  const reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  reparseWindow.document.body.innerHTML = clean;
  const reparsed = reparseWindow.document.body.innerHTML;
  const clean2 = purify.sanitize(clean, { SAFE_FOR_TEMPLATES: true });

  result.reparsed = reparsed;
  result.resanitized = clean2;
  result.mxss = clean !== reparsed;
  result.idempotency = clean !== clean2;

  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
