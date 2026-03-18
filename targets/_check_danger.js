"use strict";
const xss = require("xss");
const { JSDOM } = require("jsdom");
const { buildResult } = require("./sanitizer_diff_common");
const fs = require("fs");
const path = require("path");

const seedDir = "../output/session_jsxss_fast_6h/checkpoint/corpus/seeds";
const files = fs.readdirSync(seedDir).filter(f => !f.endsWith(".meta")).slice(0, 300);

const levels = {0:0, 1:0, 2:0, 3:0, 4:0, 5:0};
const details = [];

const rw = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;

for (const f of files) {
  const html = fs.readFileSync(path.join(seedDir, f), "utf8");

  let clean, result, mxss, idempotency;
  try {
    clean = xss(html);
    result = buildResult(clean);
    rw.document.body.innerHTML = clean;
    const reparsed = rw.document.body.innerHTML;
    mxss = clean !== reparsed;
    const clean2 = xss(clean);
    idempotency = clean !== clean2;
  } catch(e) { continue; }

  let danger = 0;
  if (!result.empty_output) danger = 1;
  if (result.has_svg || result.has_math) danger = Math.max(danger, 2);
  if (mxss || idempotency) danger = Math.max(danger, 3);
  if (result.has_event_handler || result.has_javascript_uri) danger = Math.max(danger, 5);

  levels[danger]++;
  if (danger >= 3) {
    details.push({f, danger, mxss, idempotency, eh: result.has_event_handler, js: result.has_javascript_uri, preview: clean.substring(0, 120)});
  }
}

console.log("=== Danger Level Distribution ===");
for (const [lvl, cnt] of Object.entries(levels)) {
  const bar = "#".repeat(Math.min(cnt, 50));
  console.log("  Level " + lvl + ": " + cnt + " seeds " + bar);
}
console.log("");
console.log("=== Level 3+ Seeds (mXSS/dangerous) ===");
for (const d of details.slice(0, 20)) {
  console.log("  " + d.f + " danger=" + d.danger + " mxss=" + d.mxss + " idem=" + d.idempotency + " eh=" + d.eh);
  console.log("    " + d.preview);
}
console.log("");
console.log("Total: " + files.length + " seeds, " + details.length + " at danger>=3");
rw.close();
