/**
 * Shared analysis utilities for sanitizer differential fuzzing targets.
 *
 * Extracts security-relevant signals from sanitized HTML output
 * and produces a standardized JSON schema for cross-library comparison.
 */
"use strict";

const { JSDOM } = require("jsdom");

const EVENT_HANDLER_RE = /^on[a-z]/i;
const JS_URI_RE = /^\s*javascript\s*:/i;
const DATA_HTML_RE = /^\s*data\s*:\s*text\/html/i;

const NAMESPACE_ELEMENTS = new Set([
  "svg", "math", "foreignobject", "annotation-xml",
  "desc", "mtext", "mi", "mo", "mn", "ms",
  "mglyph", "malignmark",
]);

// Elements that define a namespace context for transition detection
const SVG_NS_ELEMENTS = new Set(["svg", "foreignobject", "desc", "title"]);
const MATH_NS_ELEMENTS = new Set([
  "math", "annotation-xml", "mtext", "mi", "mo", "mn", "ms",
  "mglyph", "malignmark",
]);

const URI_ATTRS = new Set(["href", "src", "action", "formaction", "poster", "data", "codebase"]);

// Reuse a JSDOM window for analysis.  Periodically recreate to prevent
// residual DOM node accumulation that slows V8 GC over long sessions.
const _RECYCLE_EVERY = 500;
let _analysisWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
let _analysisCallCount = 0;

function _getAnalysisWindow() {
  if (++_analysisCallCount >= _RECYCLE_EVERY) {
    _analysisCallCount = 0;
    _analysisWindow.close();
    _analysisWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  }
  return _analysisWindow;
}

/**
 * Walk a DOM tree and collect element names, attribute names, and security signals.
 */
// Estimate max nesting depth from HTML string (fast heuristic).
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

const _EMPTY_ANALYSIS = {
  elements: [],
  attributes: [],
  hasScript: false,
  hasEventHandler: false,
  hasJavascriptUri: false,
  hasDataUri: false,
  hasSvg: false,
  hasMath: false,
  hasStyle: false,
  hasForm: false,
  hasBase: false,
  hasIframe: false,
  hasObjectEmbed: false,
  hasNoscript: false,
  nsTransitions: 0,
  maxDepth: 0,
};

function analyzeHtml(html) {
  if (!html || !html.trim()) {
    return { ..._EMPTY_ANALYSIS };
  }

  // Guard: JSDOM innerHTML setter + recursive walk both crash on deep nesting
  if (_estimateDepth(html) > _MAX_SAFE_DEPTH) {
    // Regex-based shallow analysis for deep inputs (no DOM parsing)
    const tagRe = /<([a-z][a-z0-9-]*)/gi;
    const elements = new Set();
    let m;
    while ((m = tagRe.exec(html)) !== null) elements.add(m[1].toLowerCase());
    const hasEH = /\bon[a-z]+\s*=/i.test(html);
    const hasJS = /javascript\s*:/i.test(html);
    return {
      elements: [...elements].sort(),
      attributes: [],
      hasScript: elements.has("script"),
      hasEventHandler: hasEH,
      hasJavascriptUri: hasJS,
      hasDataUri: /data\s*:\s*text\/html/i.test(html),
      hasSvg: elements.has("svg"),
      hasMath: elements.has("math"),
      hasStyle: elements.has("style"),
      hasForm: elements.has("form"),
      hasBase: elements.has("base"),
      hasIframe: elements.has("iframe"),
      hasObjectEmbed: elements.has("object") || elements.has("embed") || elements.has("applet"),
      hasNoscript: elements.has("noscript"),
      nsTransitions: 0,
      maxDepth: _MAX_SAFE_DEPTH,
    };
  }

  const win = _getAnalysisWindow();
  win.document.body.innerHTML = html;
  const body = win.document.body;

  const elements = new Set();
  const attributes = new Set();
  let hasScript = false;
  let hasEventHandler = false;
  let hasJavascriptUri = false;
  let hasDataUri = false;
  let nsTransitions = 0;
  let maxDepth = 0;

  // Determine namespace context of an element: "html", "svg", or "mathml"
  function nsOf(tag) {
    if (SVG_NS_ELEMENTS.has(tag)) return "svg";
    if (MATH_NS_ELEMENTS.has(tag)) return "mathml";
    return "html";
  }

  function walk(node, parentNs, depth) {
    if (node.nodeType !== 1) return; // ELEMENT_NODE only
    const tag = node.tagName.toLowerCase();
    elements.add(tag);
    if (depth > maxDepth) maxDepth = depth;

    const myNs = nsOf(tag);
    if (parentNs && myNs !== parentNs) nsTransitions++;

    for (const attr of node.attributes) {
      const name = attr.name.toLowerCase();
      attributes.add(name);

      if (EVENT_HANDLER_RE.test(name)) {
        hasEventHandler = true;
      }
      if (URI_ATTRS.has(name)) {
        if (JS_URI_RE.test(attr.value)) hasJavascriptUri = true;
        if (DATA_HTML_RE.test(attr.value)) hasDataUri = true;
      }
    }

    if (tag === "script") hasScript = true;

    for (const child of node.childNodes) walk(child, myNs, depth + 1);
  }

  // Walk children of body, not body itself (body is JSDOM wrapper)
  for (const child of body.childNodes) walk(child, "html", 1);

  const elArr = [...elements].sort();
  return {
    elements: elArr,
    attributes: [...attributes].sort(),
    hasScript,
    hasEventHandler,
    hasJavascriptUri,
    hasDataUri,
    hasSvg: elements.has("svg"),
    hasMath: elements.has("math"),
    hasStyle: elements.has("style"),
    hasForm: elements.has("form"),
    hasBase: elements.has("base"),
    hasIframe: elements.has("iframe"),
    hasObjectEmbed: elements.has("object") || elements.has("embed") || elements.has("applet"),
    hasNoscript: elements.has("noscript"),
    nsTransitions,
    maxDepth,
  };
}

/**
 * Build the standardized JSON output from sanitized HTML.
 * Truncates sanitized output to 2000 chars for comparison.
 */
function buildResult(sanitized) {
  const analysis = analyzeHtml(sanitized);
  return {
    sanitized: sanitized.substring(0, 2000),
    elements_kept: analysis.elements,
    attributes_kept: analysis.attributes,
    has_script: analysis.hasScript,
    has_event_handler: analysis.hasEventHandler,
    has_javascript_uri: analysis.hasJavascriptUri,
    has_data_uri: analysis.hasDataUri,
    has_svg: analysis.hasSvg,
    has_math: analysis.hasMath,
    has_style: analysis.hasStyle,
    has_form: analysis.hasForm,
    has_base: analysis.hasBase,
    has_iframe: analysis.hasIframe,
    has_object_embed: analysis.hasObjectEmbed,
    has_noscript: analysis.hasNoscript,
    ns_transitions: analysis.nsTransitions,
    max_depth: analysis.maxDepth,
    empty_output: !sanitized || !sanitized.trim(),
    error: null,
  };
}

module.exports = { analyzeHtml, buildResult, ELEMENT_CLASSES: {
  scripting: new Set(["script", "noscript", "template"]),
  namespace: new Set(["svg", "math", "foreignobject", "annotation-xml", "desc", "title", "mtext", "mi", "mo", "mn", "mglyph"]),
  dangerous: new Set(["iframe", "object", "embed", "applet", "base", "form"]),
  media: new Set(["img", "video", "audio", "source", "picture", "canvas"]),
  style: new Set(["style", "link"]),
}};
