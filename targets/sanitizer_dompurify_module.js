/**
 * DOMPurify module for persistent wrapper.
 * JSDOM window created once, reused across all calls.
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");

const window = new JSDOM("").window;
const purify = DOMPurify(window);

module.exports.sanitize = (html) => purify.sanitize(html);
