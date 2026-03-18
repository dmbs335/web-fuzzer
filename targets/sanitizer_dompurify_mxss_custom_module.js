/**
 * DOMPurify mXSS module with CUSTOM_ELEMENT_HANDLING (persistent mode).
 *
 * annotation-xml abuse, custom element namespace confusion.
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { buildResult } = require("./sanitizer_diff_common");

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

const CONFIG = {
  CUSTOM_ELEMENT_HANDLING: {
    tagNameCheck: /-/,
    attributeNameCheck: () => true,
    allowCustomizedBuiltInElements: true,
  },
};

module.exports.sanitize = (html) => {
  _recycle();

  const clean = _purify.sanitize(html, CONFIG);
  const result = buildResult(clean);

  _reparseWindow.document.body.innerHTML = clean;
  const reparsed = _reparseWindow.document.body.innerHTML;
  const clean2 = _purify.sanitize(clean, CONFIG);

  const mxss = clean !== reparsed;
  const idempotency = clean !== clean2;

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

  result.reparsed = reparsed;
  result.resanitized = clean2;
  result.mxss = mxss;
  result.idempotency = idempotency;
  result.mxssDiff = mxssDiff;
  result.idempotencyDiff = idempotencyDiff;

  return JSON.stringify(result);
};
