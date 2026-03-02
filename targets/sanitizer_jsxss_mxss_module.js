/**
 * js-xss combined mXSS + diff module for persistent wrapper.
 *
 * Outputs BOTH:
 *   - Security signal fields (elements_kept, has_script, ...) for diff coverage
 *   - mXSS fields (reparsed, mxss, idempotency) for mXSS oracle
 *
 * This unified schema enables both differential coverage AND mXSS detection.
 */
"use strict";

const { JSDOM } = require("jsdom");
const xss = require("xss");
const { buildResult } = require("./sanitizer_diff_common");

module.exports.sanitize = (html) => {
  // Step 1: sanitize with js-xss
  const clean = xss(html);

  // Step 2: extract security signals (same as diff targets)
  const result = buildResult(clean);

  // Step 3: double-parse (simulate innerHTML assignment)
  const dom2 = new JSDOM(`<body>${clean}</body>`);
  const reparsed = dom2.window.document.body.innerHTML;

  // Step 4: idempotency check
  const clean2 = xss(clean);

  // Detect differences
  const mxss = clean !== reparsed;
  const idempotency = clean !== clean2;

  // Build diff details for mXSS
  let mxssDiff = null;
  if (mxss) {
    let diffPos = 0;
    const minLen = Math.min(clean.length, reparsed.length);
    while (diffPos < minLen && clean[diffPos] === reparsed[diffPos]) diffPos++;
    const ctx = 60;
    mxssDiff = {
      pos: diffPos,
      cleanSnippet: clean.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      reparsedSnippet: reparsed.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      cleanLen: clean.length,
      reparsedLen: reparsed.length,
    };
  }

  let idempotencyDiff = null;
  if (idempotency) {
    let diffPos = 0;
    const minLen = Math.min(clean.length, clean2.length);
    while (diffPos < minLen && clean[diffPos] === clean2[diffPos]) diffPos++;
    const ctx = 60;
    idempotencyDiff = {
      pos: diffPos,
      firstSnippet: clean.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      secondSnippet: clean2.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      firstLen: clean.length,
      secondLen: clean2.length,
    };
  }

  // Merge: security signals + mXSS fields
  result.reparsed = reparsed;
  result.resanitized = clean2;
  result.mxss = mxss;
  result.idempotency = idempotency;
  result.mxssDiff = mxssDiff;
  result.idempotencyDiff = idempotencyDiff;

  return JSON.stringify(result);
};
