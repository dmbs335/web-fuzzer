/**
 * js-xss combined mXSS + diff module for persistent wrapper.
 *
 * Outputs:
 *   - Security signal fields for sanitized AND reparsed output
 *   - Near-miss signals (dangerous tag survived but attr stripped)
 *   - Danger escalation (reparse introduces new danger)
 *   - mXSS fields (reparsed, mxss, idempotency) for oracle
 */
"use strict";

const { JSDOM } = require("jsdom");
const xss = require("xss");
const { analyzeHtml, buildResult } = require("./sanitizer_diff_common");

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
  const clean = xss(html);
  const result = buildResult(clean);

  // Reparse: simulate innerHTML assignment
  const rw = _getReparseWindow();
  rw.document.body.innerHTML = clean;
  const reparsed = rw.document.body.innerHTML;

  // Idempotency check
  const clean2 = xss(clean);

  const mxss = clean !== reparsed;
  const idempotency = clean !== clean2;

  // ── Reparsed analysis: detect danger AFTER reparse ──
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

  // ── Danger escalation: did reparse introduce new danger? ──
  // This is THE signal — sanitizer thought safe, but reparse makes dangerous.
  result.danger_escalation = (
    (!result.has_script && rAnalysis.hasScript) ||
    (!result.has_event_handler && rAnalysis.hasEventHandler) ||
    (!result.has_javascript_uri && rAnalysis.hasJavascriptUri) ||
    (!result.has_iframe && rAnalysis.hasIframe) ||
    (!result.has_object_embed && rAnalysis.hasObjectEmbed)
  );

  // ── Near-miss signals: sanitizer allowed the tag but stripped the danger ──
  // These guide the fuzzer to explore attribute/value variations of surviving tags.
  const elems = new Set(result.elements_kept);
  result.near_miss_img = elems.has("img") && !result.has_event_handler;
  result.near_miss_a_href = elems.has("a") && !result.has_javascript_uri;
  result.near_miss_style = elems.has("style");
  result.near_miss_form = elems.has("form");
  result.near_miss_svg = result.has_svg && !result.has_script;
  result.near_miss_math = result.has_math && !result.has_script;

  // ── New elements after reparse (not in sanitized) ──
  const rElems = new Set(rAnalysis.elements);
  const newElems = [...rElems].filter(e => !elems.has(e));
  result.new_elements_after_reparse = newElems;

  // ── Security-relevant mXSS (filter out benign entity/whitespace diffs) ──
  result.mxss_security = mxss && (
    result.danger_escalation ||
    newElems.length > 0 ||
    rAnalysis.nsTransitions !== (result.ns_transitions || 0) ||
    rAnalysis.hasScript !== result.has_script ||
    rAnalysis.hasEventHandler !== result.has_event_handler ||
    rAnalysis.hasJavascriptUri !== result.has_javascript_uri
  );

  // Standard mXSS diff
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
