/**
 * DOMPurify mXSS module with REAL BROWSER re-parsing via Playwright.
 *
 * Key difference from JSDOM-only module:
 *   - Sanitization: DOMPurify on JSDOM (same as before)
 *   - Re-parse: Chromium headless via Playwright (real browser behavior)
 *   - Detects: nesting depth flattening, <noscript> scripting flag,
 *              <image>→<img> renaming, browser-specific error recovery
 *
 * Exports async sanitize(html) → JSON string.
 * Must be used with persistent_wrapper_async.js.
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { buildResult } = require("./sanitizer_diff_common");
const { chromium } = require("playwright");

// JSDOM windows for sanitization (recycled periodically)
const _RECYCLE_EVERY = 500;
let _callCount = 0;
let _dpWindow = new JSDOM("").window;
let _purify = DOMPurify(_dpWindow);
let _reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;

function _recycle() {
  if (++_callCount >= _RECYCLE_EVERY) {
    _callCount = 0;
    _dpWindow.close();
    _dpWindow = new JSDOM("").window;
    _purify = DOMPurify(_dpWindow);
    _reparseWindow.close();
    _reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  }
}

// Browser state (initialized lazily on first call)
let _browser = null;
let _context = null;
let _page = null;
const _EVAL_TIMEOUT = 3000; // 3s per evaluate call

async function _launchBrowser() {
  _browser = await chromium.launch({ headless: true });
  _context = await _browser.newContext({ javaScriptEnabled: true });
  _page = await _context.newPage();
  await _page.setContent("<!DOCTYPE html><html><body></body></html>");
}

async function _ensureBrowser() {
  if (!_browser || !_browser.isConnected()) {
    // Browser crashed or never started — (re)launch
    if (_browser) {
      try { await _browser.close(); } catch (_) {}
    }
    _browser = null;
    _page = null;
    await _launchBrowser();
  }
}

// Estimate max nesting depth from HTML string (fast heuristic).
// Counts net open tags — if depth exceeds threshold, JSDOM serializer
// will stack-overflow (uncatchable RangeError kills the process).
function _estimateDepth(html) {
  let depth = 0, max = 0;
  for (let i = 0; i < html.length - 1; i++) {
    if (html[i] === "<") {
      if (html[i + 1] === "/") depth--;
      else if (html[i + 1] !== "!" && html[i + 1] !== "?") depth++;
      if (depth > max) max = depth;
    }
  }
  return max;
}

const _MAX_SAFE_DEPTH = 2000; // JSDOM/parse5 crashes at ~3000 depth

module.exports.sanitize = async (html) => {
  _recycle();
  await _ensureBrowser();

  // Pre-check: estimate depth on raw input to prevent uncatchable stack overflow
  // in DOMPurify/JSDOM (parse5 serializer uses recursion, crashes at ~500 depth).
  // For deep inputs, bypass JSDOM entirely and use only Chromium browser re-parse.
  const isDeep = _estimateDepth(html) > _MAX_SAFE_DEPTH;

  let clean, jsdomReparsed;

  if (isDeep) {
    // Deep input: send raw HTML to Chromium for sanitize+reparse comparison.
    // DOMPurify on JSDOM would crash, so we skip it.
    // Chromium handles arbitrary depth natively (it flattens at ~512).
    clean = html; // pass through unsanitized for browser comparison
    jsdomReparsed = html; // no JSDOM re-parse
  } else {
    // Normal path: DOMPurify sanitize + JSDOM re-parse
    clean = _purify.sanitize(html);
    _reparseWindow.document.body.innerHTML = clean;
    jsdomReparsed = _reparseWindow.document.body.innerHTML;
  }

  // Step 2: extract security signals
  const result = buildResult(clean);

  // Helper: evaluate with timeout + crash recovery
  async function _safeEval(html) {
    try {
      return await Promise.race([
        _page.evaluate((h) => {
          document.body.innerHTML = h;
          return document.body.innerHTML;
        }, html),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error("eval timeout")), _EVAL_TIMEOUT)
        ),
      ]);
    } catch (err) {
      // Page/browser crashed — try to recover
      try {
        if (_browser && _browser.isConnected()) {
          // Page crashed, create new page
          _page = await _context.newPage();
          await _page.setContent("<!DOCTYPE html><html><body></body></html>");
        } else {
          // Browser crashed entirely
          await _launchBrowser();
        }
      } catch (_) {
        _browser = null;
        _page = null;
      }
      return null; // signal fallback
    }
  }

  // Step 3b: Chromium re-parse (real browser)
  // Skip browser eval for very large sanitized output (Chromium hangs on huge DOMs)
  const _MAX_BROWSER_INPUT = 50000;
  let browserReparsed;
  if (clean.length > _MAX_BROWSER_INPUT) {
    browserReparsed = jsdomReparsed; // fallback to JSDOM
  } else {
    browserReparsed = await _safeEval(clean);
    if (browserReparsed === null) browserReparsed = jsdomReparsed;
  }

  // Step 4: idempotency check (skip for deep inputs — DOMPurify would crash)
  const clean2 = isDeep ? clean : _purify.sanitize(clean);

  // Step 5: multi-round cascade (browser)
  let browserReparsed2 = browserReparsed;
  let browserReparsed3 = browserReparsed;
  if (_page) {
    const r2 = await _safeEval(browserReparsed);
    if (r2 !== null) {
      browserReparsed2 = r2;
      if (browserReparsed2 !== browserReparsed) {
        const r3 = await _safeEval(browserReparsed2);
        if (r3 !== null) browserReparsed3 = r3;
      }
    }
  }

  const jsdomMxss = clean !== jsdomReparsed;
  const browserMxss = clean !== browserReparsed;
  const browserParserDiff = jsdomReparsed !== browserReparsed;
  const idempotency = clean !== clean2;
  const cascadeMxss = browserReparsed !== browserReparsed2 || browserReparsed2 !== browserReparsed3;

  // Build diff info for browser mXSS
  let browserMxssDiff = null;
  if (browserMxss) {
    let diffPos = 0;
    const minLen = Math.min(clean.length, browserReparsed.length);
    while (diffPos < minLen && clean[diffPos] === browserReparsed[diffPos]) diffPos++;
    const ctx = 60;
    browserMxssDiff = {
      pos: diffPos,
      cleanSnippet: clean.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      browserSnippet: browserReparsed.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      cleanLen: clean.length,
      browserLen: browserReparsed.length,
    };
  }

  // JSDOM mXSS diff (backward compatible)
  let mxssDiff = null;
  if (jsdomMxss) {
    let diffPos = 0;
    const minLen = Math.min(clean.length, jsdomReparsed.length);
    while (diffPos < minLen && clean[diffPos] === jsdomReparsed[diffPos]) diffPos++;
    const ctx = 60;
    mxssDiff = {
      pos: diffPos,
      cleanSnippet: clean.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      reparsedSnippet: jsdomReparsed.substring(Math.max(0, diffPos - ctx), diffPos + ctx),
      cleanLen: clean.length,
      reparsedLen: jsdomReparsed.length,
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

  // Merge all fields
  result.reparsed = jsdomReparsed.substring(0, 2000);
  result.resanitized = clean2.substring(0, 2000);
  result.mxss = jsdomMxss;
  result.idempotency = idempotency;
  result.mxssDiff = mxssDiff;
  result.idempotencyDiff = idempotencyDiff;

  // Browser-specific fields
  result.browser_reparsed = browserReparsed.substring(0, 2000);
  result.browser_mxss = browserMxss;
  result.browser_mxss_diff = browserMxssDiff;
  result.browser_parser_diff = browserParserDiff;
  result.cascade_mxss = cascadeMxss;
  result.browser_reparsed2 = cascadeMxss ? browserReparsed2.substring(0, 1000) : null;
  result.browser_reparsed3 = cascadeMxss ? browserReparsed3.substring(0, 1000) : null;

  return JSON.stringify(result);
};

// Cleanup hook
module.exports.cleanup = async () => {
  if (_browser) {
    await _browser.close();
    _browser = null;
    _page = null;
  }
};
