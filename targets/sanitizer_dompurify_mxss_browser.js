#!/usr/bin/env node
/**
 * DOMPurify mXSS target with REAL BROWSER re-parsing (file-based mode).
 *
 * Usage: node sanitizer_dompurify_mxss_browser.js <input_file>
 *
 * Launches Chromium via Playwright for each invocation.
 * For persistent mode, use persistent_wrapper_async.js + _browser_module.js.
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { buildResult } = require("./sanitizer_diff_common");
const { chromium } = require("playwright");

const inputPath = process.argv[2];
if (!inputPath) {
  process.stderr.write("Usage: node sanitizer_dompurify_mxss_browser.js <input_file>\n");
  process.exit(1);
}

(async () => {
  try {
    const html = fs.readFileSync(inputPath, "utf8");
    const dom = new JSDOM("");
    const purify = DOMPurify(dom.window);

    const clean = purify.sanitize(html);
    const result = buildResult(clean);

    // JSDOM re-parse
    const reparseDOM = new JSDOM("<!DOCTYPE html><html><body></body></html>");
    reparseDOM.window.document.body.innerHTML = clean;
    const jsdomReparsed = reparseDOM.window.document.body.innerHTML;

    // Browser re-parse
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.setContent("<!DOCTYPE html><html><body></body></html>");

    const browserReparsed = await page.evaluate((s) => {
      document.body.innerHTML = s;
      return document.body.innerHTML;
    }, clean);

    // Cascade re-parse
    const browserReparsed2 = await page.evaluate((s) => {
      document.body.innerHTML = s;
      return document.body.innerHTML;
    }, browserReparsed);

    await browser.close();

    // Idempotency
    const clean2 = purify.sanitize(clean);

    result.reparsed = jsdomReparsed.substring(0, 2000);
    result.resanitized = clean2.substring(0, 2000);
    result.mxss = clean !== jsdomReparsed;
    result.idempotency = clean !== clean2;
    result.browser_reparsed = browserReparsed.substring(0, 2000);
    result.browser_mxss = clean !== browserReparsed;
    result.browser_parser_diff = jsdomReparsed !== browserReparsed;
    result.cascade_mxss = browserReparsed !== browserReparsed2;

    dom.window.close();
    reparseDOM.window.close();

    process.stdout.write(JSON.stringify(result));
  } catch (err) {
    process.stderr.write(`Error: ${err.message}\n`);
    process.exit(1);
  }
})();
