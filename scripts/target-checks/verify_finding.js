"use strict";
const fs = require("fs");
const { JSDOM } = require("jsdom");
const window = new JSDOM("").window;
const DOMPurify = require("dompurify")(window);

// Read the exact input that triggered the finding
const input = fs.readFileSync("../results/xss_sanitizer_diff/findings/0001_critical_xss/input", "utf8");

console.log("=== INPUT (first 500 chars) ===");
console.log(input.slice(0, 500));

console.log("\n=== DOMPURIFY OUTPUT ===");
const output = DOMPurify.sanitize(input);
console.log(output);

console.log("\n=== DOM ANALYSIS ===");
// Parse the output as DOM and check for actual javascript: URIs
const dom = new JSDOM(output);
const doc = dom.window.document;

// Check all elements
const all = doc.querySelectorAll("*");
let realDanger = false;
for (const el of all) {
  for (const attr of el.attributes) {
    if (/^(href|src|action|formaction|data)$/i.test(attr.name)) {
      if (/javascript\s*:/i.test(attr.value)) {
        console.log(`[REAL DANGER] <${el.tagName} ${attr.name}="${attr.value}">`);
        realDanger = true;
      }
    }
    if (/^on/i.test(attr.name)) {
      console.log(`[REAL DANGER] <${el.tagName} ${attr.name}="${attr.value}">`);
      realDanger = true;
    }
  }
}

// Check if "javascript:" appears only in text content (entity-encoded)
const textContent = doc.body ? doc.body.textContent : "";
if (/javascript:/i.test(textContent) && !realDanger) {
  console.log("[FALSE POSITIVE] 'javascript:' only appears in text content (entity-encoded), not in actual attributes");
}

if (!realDanger) {
  console.log("\nVERDICT: FALSE POSITIVE - no actual dangerous attributes in DOM");
} else {
  console.log("\nVERDICT: REAL VULNERABILITY - dangerous attributes present in DOM");
}

// Also show raw output to inspect entity encoding
console.log("\n=== RAW OUTPUT INSPECTION ===");
const hasEncodedBase = output.includes("&lt;base");
const hasRealBase = /<base\s/i.test(output);
console.log(`Entity-encoded <base>: ${hasEncodedBase}`);
console.log(`Real <base> tag: ${hasRealBase}`);

if (output.includes('href="javascript:')) {
  // Check if it's inside entity-encoded context
  const idx = output.indexOf('href="javascript:');
  const before = output.slice(Math.max(0, idx - 50), idx);
  console.log(`Context before match: ...${before}`);
  if (before.includes("&lt;") || before.includes("&gt;")) {
    console.log("=> Inside entity-encoded text, NOT a real attribute");
  } else {
    console.log("=> In actual HTML tag context - REAL vulnerability");
  }
}
