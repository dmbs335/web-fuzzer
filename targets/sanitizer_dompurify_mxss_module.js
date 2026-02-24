/**
 * DOMPurify mXSS detection module for persistent wrapper.
 *
 * Performs three checks:
 *   1. Sanitize input → clean
 *   2. Double-parse: assign clean to innerHTML, serialize back → reparsed
 *   3. Idempotency: sanitize(clean) → clean2
 *
 * Returns JSON with all results + diff flags.
 * JSDOM window created once, reused across all calls.
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");

const window = new JSDOM("").window;
const purify = DOMPurify(window);

module.exports.sanitize = (html) => {
  // Step 1: sanitize
  const clean = purify.sanitize(html);

  // Step 2: double-parse (simulate innerHTML assignment)
  // This is the core mXSS vector: browser re-parses the sanitized string
  const dom2 = new JSDOM(`<body>${clean}</body>`);
  const reparsed = dom2.window.document.body.innerHTML;

  // Step 3: idempotency check
  const clean2 = purify.sanitize(clean);

  // Detect differences
  const mxss = clean !== reparsed;
  const idempotency = clean !== clean2;

  // Build diff details for mXSS
  let mxssDiff = null;
  if (mxss) {
    // Find first divergence point
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

  // Build diff details for idempotency
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

  return JSON.stringify({
    sanitized: clean,
    reparsed,
    resanitized: clean2,
    mxss,
    idempotency,
    mxssDiff,
    idempotencyDiff,
  });
};
