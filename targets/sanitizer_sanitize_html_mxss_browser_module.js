/**
 * sanitize-html mXSS module with REAL BROWSER re-parsing via Playwright.
 *
 * Key difference from JSDOM-only module:
 *   - Sanitization: sanitize-html (htmlparser2-based)
 *   - Re-parse: Chromium headless via Playwright (real browser behavior)
 *   - Detects: parser differential between sanitize-html output and browser innerHTML
 *
 * Exports async sanitize(html) → JSON string.
 * Must be used with persistent_wrapper_async.js.
 */
"use strict";

const { JSDOM } = require("jsdom");
const sanitizeHtml = require("sanitize-html");
const { buildResult } = require("./sanitizer_diff_common");
const { chromium } = require("playwright");

// JSDOM window for re-parse (recycled periodically)
const _RECYCLE_EVERY = 500;
let _callCount = 0;
let _reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;

function _recycle() {
  if (++_callCount >= _RECYCLE_EVERY) {
    _callCount = 0;
    _reparseWindow.close();
    _reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  }
}

// Browser state (initialized lazily on first call)
let _browser = null;
let _context = null;
let _page = null;
const _EVAL_TIMEOUT = 3000;

async function _launchBrowser() {
  _browser = await chromium.launch({ headless: true });
  _context = await _browser.newContext({ javaScriptEnabled: true });
  _page = await _context.newPage();
  await _page.setContent("<!DOCTYPE html><html><body></body></html>");
}

async function _ensureBrowser() {
  if (!_browser || !_browser.isConnected()) {
    if (_browser) {
      try { await _browser.close(); } catch (_) {}
    }
    _browser = null;
    _page = null;
    await _launchBrowser();
  }
}

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

const _MAX_SAFE_DEPTH = 2000;

module.exports.sanitize = async (html) => {
  _recycle();
  await _ensureBrowser();

  const isDeep = _estimateDepth(html) > _MAX_SAFE_DEPTH;

  let clean, jsdomReparsed;

  if (isDeep) {
    clean = html;
    jsdomReparsed = html;
  } else {
    // sanitize-html (uses htmlparser2, different from JSDOM's parse5)
    clean = sanitizeHtml(html);
    _reparseWindow.document.body.innerHTML = clean;
    jsdomReparsed = _reparseWindow.document.body.innerHTML;
  }

  const result = buildResult(clean);

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
      try {
        if (_browser && _browser.isConnected()) {
          _page = await _context.newPage();
          await _page.setContent("<!DOCTYPE html><html><body></body></html>");
        } else {
          await _launchBrowser();
        }
      } catch (_) {
        _browser = null;
        _page = null;
      }
      return null;
    }
  }

  const _MAX_BROWSER_INPUT = 50000;
  let browserReparsed;
  if (clean.length > _MAX_BROWSER_INPUT) {
    browserReparsed = jsdomReparsed;
  } else {
    browserReparsed = await _safeEval(clean);
    if (browserReparsed === null) browserReparsed = jsdomReparsed;
  }

  const clean2 = isDeep ? clean : sanitizeHtml(clean);

  // Multi-round cascade (browser)
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

  result.reparsed = jsdomReparsed.substring(0, 2000);
  result.resanitized = clean2.substring(0, 2000);
  result.mxss = jsdomMxss;
  result.idempotency = idempotency;
  result.mxssDiff = mxssDiff;
  result.idempotencyDiff = idempotencyDiff;

  result.browser_reparsed = browserReparsed.substring(0, 2000);
  result.browser_mxss = browserMxss;
  result.browser_mxss_diff = browserMxssDiff;
  result.browser_parser_diff = browserParserDiff;
  result.cascade_mxss = cascadeMxss;
  result.browser_reparsed2 = cascadeMxss ? browserReparsed2.substring(0, 1000) : null;
  result.browser_reparsed3 = cascadeMxss ? browserReparsed3.substring(0, 1000) : null;

  return JSON.stringify(result);
};

module.exports.cleanup = async () => {
  if (_browser) {
    await _browser.close();
    _browser = null;
    _page = null;
  }
};
