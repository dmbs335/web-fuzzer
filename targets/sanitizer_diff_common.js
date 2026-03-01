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

const URI_ATTRS = new Set(["href", "src", "action", "formaction", "poster", "data", "codebase"]);

/**
 * Walk a DOM tree and collect element names, attribute names, and security signals.
 */
function analyzeHtml(html) {
  if (!html || !html.trim()) {
    return {
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
    };
  }

  const dom = new JSDOM(`<body>${html}</body>`);
  const body = dom.window.document.body;

  const elements = new Set();
  const attributes = new Set();
  let hasScript = false;
  let hasEventHandler = false;
  let hasJavascriptUri = false;
  let hasDataUri = false;

  function walk(node) {
    if (node.nodeType !== 1) return; // ELEMENT_NODE only
    const tag = node.tagName.toLowerCase();
    elements.add(tag);

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

    for (const child of node.childNodes) walk(child);
  }

  // Walk children of body, not body itself (body is JSDOM wrapper)
  for (const child of body.childNodes) walk(child);

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
    empty_output: !sanitized || !sanitized.trim(),
    error: null,
  };
}

module.exports = { analyzeHtml, buildResult };
