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

const window = new JSDOM("").window;
const purify = DOMPurify(window);

module.exports.process = function (html) {
  try {
    const clean = purify.sanitize(html);
    const result = buildResult(clean);
    return { output: JSON.stringify(result), exitCode: 0 };
  } catch (e) {
    return {
      output: JSON.stringify({ error: e.message, empty_output: true }),
      exitCode: 1,
    };
  }
};
