/**
 * js-xss module for persistent wrapper.
 */
"use strict";

const xss = require("xss");

module.exports.sanitize = (html) => xss(html);
