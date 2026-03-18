/**
 * sanitize-html DOM Clobbering differential module for persistent wrapper.
 *
 * Outputs:
 *   - Standard sanitizer diff signals (elements, attributes, script, etc.)
 *   - DOM Clobbering signals (ids, names, collections, chain depth, etc.)
 *   - mXSS fields (reparsed, idempotency)
 *
 * sanitize-html does NOT have built-in DOM Clobbering protection — id/name
 * attributes generally survive if they are in the allowedAttributes config.
 */
"use strict";

const { JSDOM } = require("jsdom");
const sanitizeHtml = require("sanitize-html");
const { analyzeHtml, buildClobberResult } = require("./domclobber_diff_common");

const _RECYCLE_EVERY = 500;
let _reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
let _reparseCallCount = 0;

function _getReparseWindow() {
  if (++_reparseCallCount >= _RECYCLE_EVERY) {
    _reparseCallCount = 0;
    _reparseWindow.close();
    _reparseWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  }
  return _reparseWindow;
}

module.exports.sanitize = (html) => {
  const clean = sanitizeHtml(html);
  const result = buildClobberResult(clean);

  // Reparse
  const rw = _getReparseWindow();
  rw.document.body.innerHTML = clean;
  const reparsed = rw.document.body.innerHTML;

  // Idempotency
  const clean2 = sanitizeHtml(clean);

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
