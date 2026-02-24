/**
 * DOMPurify mXSS detection target (process mode).
 *
 * Usage: node sanitizer_dompurify_mxss.js <input_file>
 * Output: JSON with sanitized, reparsed, resanitized, and diff flags.
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_dompurify_mxss.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);

  const clean = purify.sanitize(html);
  const dom2 = new JSDOM(`<body>${clean}</body>`);
  const reparsed = dom2.window.document.body.innerHTML;
  const clean2 = purify.sanitize(clean);

  const result = {
    sanitized: clean,
    reparsed,
    resanitized: clean2,
    mxss: clean !== reparsed,
    idempotency: clean !== clean2,
  };

  process.stdout.write(JSON.stringify(result));
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
