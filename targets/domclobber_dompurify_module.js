/**
 * DOMPurify DOM Clobbering differential module for persistent wrapper.
 *
 * Outputs:
 *   - Standard sanitizer diff signals (elements, attributes, script, etc.)
 *   - DOM Clobbering signals (ids, names, collections, chain depth, etc.)
 *   - mXSS fields (reparsed, idempotency)
 *
 * DOMPurify has SANITIZE_DOM=true by default, which strips some clobbering
 * vectors.  This module detects what survives that defense.
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const { analyzeHtml, buildClobberResult } = require("./domclobber_diff_common");

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

module.exports.sanitize = (html) => {
  _recycle();

  if (_estimateDepth(html) > _MAX_SAFE_DEPTH) {
    return JSON.stringify({ sanitized: "", empty_output: true, error: "depth_skip" });
  }

  // DOMPurify with defaults (SANITIZE_DOM=true)
  const clean = _purify.sanitize(html);
  const result = buildClobberResult(clean);

  // Reparse
  _reparseWindow.document.body.innerHTML = clean;
  const reparsed = _reparseWindow.document.body.innerHTML;

  // Idempotency
  const clean2 = _purify.sanitize(clean);

  const mxss = clean !== reparsed;
  const idempotency = clean !== clean2;

  // ── Reparsed analysis ──
  const rAnalysis = analyzeHtml(reparsed);
  result.r_has_script = rAnalysis.hasScript;
  result.r_has_event_handler = rAnalysis.hasEventHandler;
  result.r_has_javascript_uri = rAnalysis.hasJavascriptUri;
  result.r_has_data_uri = rAnalysis.hasDataUri;
  result.r_has_svg = rAnalysis.hasSvg;
  result.r_has_math = rAnalysis.hasMath;
  result.r_has_style = rAnalysis.hasStyle;
  result.r_has_iframe = rAnalysis.hasIframe;
  result.r_has_noscript = rAnalysis.hasNoscript;
  result.r_elements = rAnalysis.elements;
  result.r_ns_transitions = rAnalysis.nsTransitions;
  result.r_max_depth = rAnalysis.maxDepth;

  // ── Danger escalation ──
  result.danger_escalation = (
    (!result.has_script && rAnalysis.hasScript) ||
    (!result.has_event_handler && rAnalysis.hasEventHandler) ||
    (!result.has_javascript_uri && rAnalysis.hasJavascriptUri) ||
    (!result.has_iframe && rAnalysis.hasIframe) ||
    (!result.has_object_embed && rAnalysis.hasObjectEmbed)
  );

  // ── Near-miss signals ──
  const elems = new Set(result.elements_kept);
  result.near_miss_img = elems.has("img") && !result.has_event_handler;
  result.near_miss_a_href = elems.has("a") && !result.has_javascript_uri;
  result.near_miss_style = elems.has("style");
  result.near_miss_form = elems.has("form");
  result.near_miss_svg = result.has_svg && !result.has_script;
  result.near_miss_math = result.has_math && !result.has_script;

  // ── New elements after reparse ──
  const rElems = new Set(rAnalysis.elements);
  const newElems = [...rElems].filter(e => !elems.has(e));
  result.new_elements_after_reparse = newElems;

  // ── Security-relevant mXSS ──
  result.mxss_security = mxss && (
    result.danger_escalation ||
    newElems.length > 0 ||
    rAnalysis.nsTransitions !== (result.ns_transitions || 0) ||
    rAnalysis.hasScript !== result.has_script ||
    rAnalysis.hasEventHandler !== result.has_event_handler ||
    rAnalysis.hasJavascriptUri !== result.has_javascript_uri
  );

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
