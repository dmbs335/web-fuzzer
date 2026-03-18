/**
 * DOMPurify mXSS target with CUSTOM_ELEMENT_HANDLING config.
 *
 * Usage: node sanitizer_dompurify_mxss_custom.js <input_file>
 *
 * CUSTOM_ELEMENT_HANDLING with tagNameCheck: /-/ allows custom elements
 * (e.g. <my-widget>). This can interact with annotation-xml and
 * namespace integration points in unexpected ways.
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { buildResult } = require("./sanitizer_diff_common");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_dompurify_mxss_custom.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);

  const config = {
    CUSTOM_ELEMENT_HANDLING: {
      tagNameCheck: /-/,
      attributeNameCheck: () => true,
      allowCustomizedBuiltInElements: true,
    },
  };
  const clean = purify.sanitize(html, config);
  const result = buildResult(clean);

  const reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  reparseWindow.document.body.innerHTML = clean;
  const reparsed = reparseWindow.document.body.innerHTML;
  const clean2 = purify.sanitize(clean, config);

  result.reparsed = reparsed;
  result.resanitized = clean2;
  result.mxss = clean !== reparsed;
  result.idempotency = clean !== clean2;

  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
