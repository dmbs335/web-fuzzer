/**
 * Shared analysis utilities for DOM Clobbering differential fuzzing.
 *
 * Extends sanitizer_diff_common with clobbering-specific signals:
 * id/name attribute collection, duplicate id detection, anchor+href
 * patterns, form-child clobbering, chain depth, and dangerous target
 * matching.
 */
"use strict";

const { JSDOM } = require("jsdom");
const { analyzeHtml, buildResult } = require("./sanitizer_diff_common");

// ── Dangerous clobbering targets ──
// Properties that, if shadowed via DOM Clobbering, lead to security impact.
const DANGEROUS_TARGETS = new Set([
  "currentScript", "location", "cookie", "domain", "referrer",
  "defaultView", "body", "head", "getElementById", "querySelector",
  "CLOSURE_BASE_PATH", "AMP_MODE", "__webpack_public_path__",
  "__webpack_nonce__", "__webpack_require__", "analytics", "ga",
  "_gaq", "dataLayer",
]);

// Built-in document/element properties that clobbering can shadow.
const BUILTIN_PROPS = new Set([
  "getElementById", "querySelector", "querySelectorAll",
  "getElementsByTagName", "getElementsByClassName",
  "createElement", "createElementNS", "currentScript",
  "cookie", "domain", "referrer", "location", "URL",
  "body", "head", "forms", "images", "links", "scripts",
  "title", "documentElement", "implementation",
]);

// ── JSDOM window recycling for clobber analysis ──
const _RECYCLE_EVERY = 500;
let _clobberWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
let _clobberCallCount = 0;

function _getClobberWindow() {
  if (++_clobberCallCount >= _RECYCLE_EVERY) {
    _clobberCallCount = 0;
    _clobberWindow.close();
    _clobberWindow = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
  }
  return _clobberWindow;
}

/**
 * Build a result object with both standard sanitizer signals and
 * DOM Clobbering-specific analysis fields.
 *
 * @param {string} sanitizedHtml - HTML after sanitization
 * @returns {object} Combined result object
 */
function buildClobberResult(sanitizedHtml) {
  // 1. Get base sanitizer analysis
  const result = buildResult(sanitizedHtml);

  // 2. Parse into DOM and walk for clobbering signals
  const clobberIds = [];
  const clobberNames = [];
  let hasAnchorHref = false;
  let hasFormChildren = false;

  if (sanitizedHtml && sanitizedHtml.trim()) {
    const win = _getClobberWindow();
    win.document.body.innerHTML = sanitizedHtml;
    const body = win.document.body;

    function walk(node, inForm) {
      if (node.nodeType !== 1) return; // ELEMENT_NODE only
      const tag = node.tagName.toLowerCase();

      const idVal = node.getAttribute("id");
      if (idVal) clobberIds.push(idVal);

      const nameVal = node.getAttribute("name");
      if (nameVal) clobberNames.push(nameVal);

      // Detect <a> with both id and href — enables two-step clobbering
      // (document.x.toString() returns href value)
      if (tag === "a" && idVal && node.hasAttribute("href")) {
        hasAnchorHref = true;
      }

      // Detect <form> children with name/id — enables form.childName clobbering
      if (inForm && (idVal || nameVal)) {
        hasFormChildren = true;
      }

      const isForm = tag === "form";
      for (const child of node.childNodes) {
        walk(child, isForm || inForm);
      }
    }

    for (const child of body.childNodes) walk(child, false);
  }

  // 3. Detect duplicate ids → HTMLCollection clobbering
  const idCounts = {};
  for (const id of clobberIds) {
    idCounts[id] = (idCounts[id] || 0) + 1;
  }
  const hasCollection = Object.values(idCounts).some(c => c > 1);

  // 4. Compute chain depth
  //    1 = simple id/name, 2 = collection or form-child, 3 = both
  let chainDepth = 0;
  if (clobberIds.length > 0 || clobberNames.length > 0) {
    chainDepth = 1;
    if (hasCollection || hasFormChildren) chainDepth = 2;
    if (hasCollection && hasFormChildren) chainDepth = 3;
  }

  // 5. Match against dangerous targets
  const allClobberNames = new Set([...clobberIds, ...clobberNames]);
  const dangerousTargets = [...allClobberNames].filter(n => DANGEROUS_TARGETS.has(n));
  const builtinsShadowed = [...allClobberNames].filter(n => BUILTIN_PROPS.has(n));

  // 6. Detect sanitizer defenses
  //    sanitize_named_props_active: id values prefixed with "user-content-"
  const hasPrefix = clobberIds.length > 0 &&
    clobberIds.every(id => id.startsWith("user-content-"));
  const idPrefix = hasPrefix ? "user-content-" : null;

  //    sanitize_dom_active: heuristic — check if known builtin-name elements
  //    were stripped (e.g., input had id="location" but output doesn't)
  //    We approximate by checking if NO dangerous targets survived despite
  //    the HTML containing id/name attributes at all.
  const sanitizeDomActive = (clobberIds.length > 0 || clobberNames.length > 0) &&
    dangerousTargets.length === 0 &&
    builtinsShadowed.length === 0;

  // 7. Attach clobbering fields to result
  result.clobber_ids = clobberIds;
  result.clobber_names = clobberNames;
  result.clobber_has_collection = hasCollection;
  result.clobber_has_anchor_href = hasAnchorHref;
  result.clobber_has_form_children = hasFormChildren;
  result.clobber_chain_depth = chainDepth;
  result.clobber_dangerous_targets = dangerousTargets;
  result.clobber_builtins_shadowed = builtinsShadowed;
  result.clobber_count = allClobberNames.size;
  result.sanitize_dom_active = sanitizeDomActive;
  result.sanitize_named_props_active = hasPrefix;
  result.id_prefix = idPrefix;

  return result;
}

module.exports = {
  analyzeHtml,
  buildResult,
  buildClobberResult,
  DANGEROUS_TARGETS,
  BUILTIN_PROPS,
};
