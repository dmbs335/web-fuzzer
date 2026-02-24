/**
 * DOMPurify sanitizer target for differential fuzzing.
 *
 * Usage: node sanitizer_dompurify.js <input_file>
 * Output: sanitized HTML to stdout
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_dompurify.js <input_file>\n");
  process.exit(1);
}

try {
  const html = fs.readFileSync(inputPath, "utf8");
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);
  const clean = purify.sanitize(html);
  process.stdout.write(clean);
} catch (err) {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
}
