/**
 * DOMPurify differential fuzzing module for persistent wrapper.
 *
 * Sanitizes input with DOMPurify and returns standardized JSON
 * with security signal fields for cross-library comparison.
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { buildResult } = require("./sanitizer_diff_common");

// Periodically recreate DOMPurify window to prevent heap accumulation
// (~58 KB/iter residue from DOMPurify internal DOM operations).
const _RECYCLE_EVERY = 500;
let _dpWindow = new JSDOM("").window;
let _purify = DOMPurify(_dpWindow);
let _dpCallCount = 0;

module.exports.process = function (html) {
  if (++_dpCallCount >= _RECYCLE_EVERY) {
    _dpCallCount = 0;
    _dpWindow.close();
    _dpWindow = new JSDOM("").window;
    _purify = DOMPurify(_dpWindow);
  }
  try {
    const clean = _purify.sanitize(html);
    const result = buildResult(clean);
    return { output: JSON.stringify(result), exitCode: 0 };
  } catch (e) {
    return {
      output: JSON.stringify({ error: e.message, empty_output: true }),
      exitCode: 1,
    };
  }
};
