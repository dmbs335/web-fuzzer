/**
 * mXSS verification script.
 *
 * Tests if DOMPurify-sanitized output becomes dangerous after
 * a browser re-parses it (innerHTML round-trip).
 *
 * Usage: node verify_mxss.js <input_file>
 */
"use strict";

const fs = require("fs");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");

const inputPath = process.argv[2];
if (!inputPath) {
  console.error("Usage: node verify_mxss.js <input_file>");
  process.exit(1);
}

const EVENT_HANDLER_RE = /^on[a-z]+$/i;

function findEventHandlers(element, path = "") {
  const results = [];
  if (!element || !element.attributes) return results;

  const tag = element.tagName?.toLowerCase() || "?";
  const currentPath = path ? `${path} > ${tag}` : tag;

  for (const attr of element.attributes) {
    if (EVENT_HANDLER_RE.test(attr.name)) {
      results.push({
        path: currentPath,
        attribute: attr.name,
        value: attr.value,
      });
    }
  }

  if (element.children) {
    for (const child of element.children) {
      results.push(...findEventHandlers(child, currentPath));
    }
  }
  return results;
}

try {
  const html = fs.readFileSync(inputPath, "utf8");

  // Step 1: Sanitize with DOMPurify
  const window1 = new JSDOM("").window;
  const purify = DOMPurify(window1);
  const sanitized = purify.sanitize(html);

  console.log("=== Original Input (first 200 chars) ===");
  console.log(html.slice(0, 200));
  console.log("\n=== DOMPurify Output ===");
  console.log(sanitized);

  // Step 2: Re-parse sanitized HTML (simulating innerHTML assignment)
  const dom2 = new JSDOM(`<!DOCTYPE html><html><body></body></html>`);
  const body = dom2.window.document.body;
  body.innerHTML = sanitized;

  // Step 3: Serialize again (what the browser actually sees)
  const reparsed = body.innerHTML;
  console.log("\n=== Re-parsed (innerHTML round-trip) ===");
  console.log(reparsed);

  // Step 4: Check for event handlers in the DOM
  const handlers = findEventHandlers(body);

  // Step 5: Check if sanitized != reparsed (mutation detected)
  const mutated = sanitized !== reparsed;

  console.log("\n=== Analysis ===");
  console.log(`Mutation detected: ${mutated}`);
  if (mutated) {
    console.log("  Sanitized output differs from re-parsed output (mXSS candidate!)");
  }

  if (handlers.length > 0) {
    console.log(`\n*** VERIFIED: ${handlers.length} event handler(s) found in DOM ***`);
    for (const h of handlers) {
      console.log(`  [${h.path}] ${h.attribute}="${h.value}"`);
    }
    console.log("\nVERDICT: EXPLOITABLE");
  } else {
    // Also check raw text for patterns that might be dangerous in other contexts
    const dangerousPatterns = reparsed.match(/\bon[a-z]+=(?:[^\s>]*)/gi) || [];
    if (dangerousPatterns.length > 0) {
      console.log(`\nEvent handler patterns in output text (not in DOM attributes):`);
      for (const p of dangerousPatterns) {
        console.log(`  ${p}`);
      }
      console.log("\nVERDICT: FALSE POSITIVE (pattern in text/attribute value, not executable)");
    } else {
      console.log("\nNo event handlers found in DOM or output text.");
      console.log("VERDICT: FALSE POSITIVE");
    }
  }

  process.exit(handlers.length > 0 ? 0 : 1);

} catch (err) {
  console.error(`Error: ${err.message}`);
  process.exit(2);
}
