/**
 * sanitize-html module for persistent wrapper.
 */
"use strict";

const sanitizeHtml = require("sanitize-html");

module.exports.sanitize = (html) => sanitizeHtml(html);
