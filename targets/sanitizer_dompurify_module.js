/**
 * DOMPurify module for persistent wrapper.
 * JSDOM window recycled every 500 calls to prevent state accumulation.
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");

const _RECYCLE_EVERY = 500;
let _callCount = 0;
let _window = new JSDOM("").window;
let _purify = DOMPurify(_window);

module.exports.sanitize = (html) => {
  if (++_callCount >= _RECYCLE_EVERY) {
    _callCount = 0;
    _window.close();
    _window = new JSDOM("").window;
    _purify = DOMPurify(_window);
  }
  return _purify.sanitize(html);
};
