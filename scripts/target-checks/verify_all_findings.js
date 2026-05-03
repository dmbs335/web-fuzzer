"use strict";
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");
const window = new JSDOM("").window;
const DOMPurify = require("dompurify")(window);

const FINDINGS = [
  {
    id: "Campaign1 #0 (MEDIUM differential)",
    dir: "../results/xss_sanitizer_diff/findings/0000_medium_differential",
    type: "differential",
  },
  {
    id: "Campaign1 #1 (CRITICAL xss) - already verified FP",
    dir: "../results/xss_sanitizer_diff/findings/0001_critical_xss",
    type: "xss",
  },
  {
    id: "Campaign2 #0 (MEDIUM differential)",
    dir: "../results/xss_sanitizer_long/findings/0000_medium_differential",
    type: "differential",
  },
  {
    id: "Campaign3 #0 (MEDIUM differential)",
    dir: "../results/xss_enhanced/findings/0000_medium_differential",
    type: "differential",
  },
  {
    id: "Campaign3 #1 (HIGH xss)",
    dir: "../results/xss_enhanced/findings/0001_high_xss",
    type: "xss",
  },
];

// Dangerous pattern checks in actual DOM
function domCheck(html) {
  const findings = [];
  const dom = new JSDOM(html);
  const doc = dom.window.document;
  const all = doc.querySelectorAll("*");

  for (const el of all) {
    // Event handlers
    for (const attr of el.attributes) {
      if (/^on/i.test(attr.name)) {
        findings.push(`EVENT_HANDLER: <${el.tagName} ${attr.name}="${attr.value.slice(0,40)}">`);
      }
      if (/^(href|src|action|formaction|data|poster)$/i.test(attr.name)) {
        if (/^\s*javascript\s*:/i.test(attr.value)) {
          findings.push(`JS_URI_ATTR: <${el.tagName} ${attr.name}="${attr.value.slice(0,40)}">`);
        }
      }
    }
    // Script elements
    if (el.tagName === "SCRIPT") {
      findings.push(`SCRIPT_TAG: <script>${el.textContent.slice(0,40)}</script>`);
    }
  }

  // CSS in <style> elements
  const styles = doc.querySelectorAll("style");
  for (const s of styles) {
    const css = s.textContent;
    if (/expression\s*\(/i.test(css))
      findings.push(`CSS_EXPRESSION: ${css.match(/expression\s*\([^)]{0,30}\)/i)?.[0]}`);
    if (/@import\s+['"(]*\s*javascript/i.test(css))
      findings.push(`CSS_IMPORT_JS: ${css.match(/@import[^;]{0,60}/i)?.[0]}`);
    if (/url\s*\(\s*['"]?\s*javascript/i.test(css))
      findings.push(`CSS_URL_JS: ${css.match(/url\s*\([^)]{0,60}\)/i)?.[0]}`);
    if (/-moz-binding\s*:/i.test(css))
      findings.push(`CSS_MOZ_BINDING`);
    if (/@import\s+['"(]*\s*(\/\/|https?:)/i.test(css))
      findings.push(`CSS_EXTERNAL_IMPORT: ${css.match(/@import[^;]{0,60}/i)?.[0]}`);
    if (/url\s*\(\s*['"]?\s*(\/\/|https?:)/i.test(css))
      findings.push(`CSS_EXTERNAL_URL: ${css.match(/url\s*\([^)]{0,60}\)/i)?.[0]}`);
    if (/behavior\s*:\s*url/i.test(css))
      findings.push(`CSS_BEHAVIOR`);
    // @import url("javascript:...") pattern
    if (/@import\s+url\s*\(\s*['"]?\s*javascript/i.test(css))
      findings.push(`CSS_IMPORT_URL_JS: ${css.match(/@import\s+url\s*\([^)]{0,60}\)/i)?.[0]}`);
  }

  return findings;
}

console.log("=".repeat(80));
console.log("COMPREHENSIVE FINDING VERIFICATION (DOM-parsed)");
console.log("=".repeat(80));

for (const f of FINDINGS) {
  console.log(`\n${"─".repeat(70)}`);
  console.log(`[${f.id}]`);

  const inputFile = path.join(f.dir, "input");
  if (!fs.existsSync(inputFile)) {
    console.log("  INPUT FILE NOT FOUND - skipping");
    continue;
  }

  const input = fs.readFileSync(inputFile, "utf8");
  console.log(`  Input (${input.length} bytes): ${input.slice(0, 100).replace(/\n/g, "\\n")}...`);

  // Run through DOMPurify
  const output = DOMPurify.sanitize(input);
  console.log(`  Output (${output.length} bytes): ${output.slice(0, 120).replace(/\n/g, "\\n")}...`);

  if (f.type === "xss") {
    // DOM-based verification
    const dangers = domCheck(output);
    if (dangers.length > 0) {
      console.log(`  VERDICT: *** REAL VULNERABILITY ***`);
      for (const d of dangers) {
        console.log(`    → ${d}`);
      }
    } else {
      console.log(`  VERDICT: FALSE POSITIVE (no dangerous patterns in actual DOM)`);

      // Show why the regex matched
      const rawMatches = [];
      if (/javascript\s*:/i.test(output)) rawMatches.push("javascript: in text");
      if (/on\w+\s*=/i.test(output)) rawMatches.push("onXXX= in text");
      if (/@import.*javascript/i.test(output)) rawMatches.push("@import javascript in text");
      if (rawMatches.length > 0) {
        console.log(`    Regex matched because: ${rawMatches.join(", ")}`);

        // Show the context
        for (const pat of [/javascript\s*:/i, /@import[^;]*javascript/i]) {
          const m = output.match(pat);
          if (m) {
            const idx = m.index;
            const ctx = output.slice(Math.max(0, idx - 40), idx + m[0].length + 20);
            const isEncoded = /&lt;|&gt;/.test(output.slice(Math.max(0, idx - 80), idx));
            console.log(`    Context: ...${ctx.replace(/\n/g, "\\n").slice(0, 100)}...`);
            console.log(`    Entity-encoded context: ${isEncoded ? "YES (text, not HTML)" : "NO (check manually)"}`);
          }
        }
      }
    }
  } else if (f.type === "differential") {
    // For differential findings, check if the output difference is security-relevant
    const dangers = domCheck(output);
    if (dangers.length > 0) {
      console.log(`  VERDICT: SECURITY-RELEVANT DIFFERENTIAL`);
      for (const d of dangers) {
        console.log(`    → ${d}`);
      }
    } else {
      console.log(`  VERDICT: BEHAVIORAL DIFFERENCE (not a direct security issue)`);
      console.log(`    DOMPurify allowed more elements, but none are directly exploitable`);
    }
  }
}

console.log(`\n${"=".repeat(80)}`);
console.log("ALSO VERIFYING: DOMPurify CSS injection (manually confirmed earlier)");
console.log("=".repeat(80));

const CSS_TESTS = [
  ['SVG @import javascript:', '<svg><style>@import "javascript:alert(1)"</style></svg>'],
  ['SVG expression()', '<svg><style>*{x:expression(alert(1))}</style></svg>'],
  ['SVG url(javascript:)', '<svg><style>*{background:url(javascript:alert(1))}</style></svg>'],
  ['SVG -moz-binding', '<svg><style>*{-moz-binding:url(javascript:alert(1))}</style></svg>'],
  ['SVG external @import', '<svg><style>@import "//evil.com/xss.css"</style></svg>'],
  ['Table url(javascript:)', '<table><style>*{background:url(javascript:alert(1))}</style></table>'],
  ['SVG behavior', '<svg><style>*{behavior:url(#default#userData)}</style></svg>'],
];

for (const [name, input] of CSS_TESTS) {
  const output = DOMPurify.sanitize(input);
  const dangers = domCheck(output);
  if (dangers.length > 0) {
    console.log(`  [REAL] ${name}: ${dangers.join(", ")}`);
  } else {
    console.log(`  [SAFE] ${name}`);
  }
}

console.log(`\n${"=".repeat(80)}`);
console.log("FINAL SUMMARY");
console.log("=".repeat(80));
