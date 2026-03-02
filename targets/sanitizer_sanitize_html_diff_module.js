/**
 * sanitize-html differential fuzzing module for persistent wrapper.
 *
 * Sanitizes input with sanitize-html and returns standardized JSON
 * with security signal fields for cross-library comparison.
 */
"use strict";

const sanitizeHtml = require("sanitize-html");
const { buildResult } = require("./sanitizer_diff_common");

module.exports.process = function (html) {
  try {
    const clean = sanitizeHtml(html);
    const result = buildResult(clean);
    return { output: JSON.stringify(result), exitCode: 0 };
  } catch (e) {
    return {
      output: JSON.stringify({ error: e.message, empty_output: true }),
      exitCode: 1,
    };
  }
};
