#!/usr/bin/env node
/**
 * sanitize-html mXSS browser target (standalone mode).
 * Usage: node sanitizer_sanitize_html_mxss_browser.js <input_file>
 */
"use strict";
const fs = require("fs");
const mod = require("./sanitizer_sanitize_html_mxss_browser_module");

const inputFile = process.argv[2];
if (!inputFile) { process.stderr.write("Usage: node sanitizer_sanitize_html_mxss_browser.js <input_file>\n"); process.exit(1); }

(async () => {
  const html = fs.readFileSync(inputFile, "utf8");
  const result = await mod.sanitize(html);
  process.stdout.write(result);
  if (mod.cleanup) await mod.cleanup();
})();
