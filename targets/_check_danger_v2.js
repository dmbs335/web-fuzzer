"use strict";
const mod = require("./sanitizer_jsxss_mxss_module");
const fs = require("fs");
const path = require("path");

const seedDir = "../output/session_jsxss_v2_6h/checkpoint/corpus/seeds";
if (!fs.existsSync(seedDir)) { console.log("No checkpoint"); process.exit(0); }
const files = fs.readdirSync(seedDir).filter(f => !f.endsWith(".meta"));

const levels = {0:0, 1:0, 2:0, 3:0, 4:0, 5:0, 6:0};
const nearMisses = {img:0, a:0, style:0, form:0, svg:0, math:0};
let securityMxss = 0;
const interesting = [];

for (const f of files) {
  const html = fs.readFileSync(path.join(seedDir, f), "utf8");
  const r = JSON.parse(mod.sanitize(html));

  // Compute danger level (same as coverage collector)
  let danger = 0;
  const elems = new Set(r.elements_kept.map(e => e.toLowerCase()));
  if (!r.empty_output) danger = 1;
  if (r.has_svg || r.has_math) danger = Math.max(danger, 2);
  if (r.mxss_security) danger = Math.max(danger, 3);
  if (r.r_has_event_handler || r.r_has_javascript_uri) danger = Math.max(danger, 5);
  if (r.danger_escalation) danger = Math.max(danger, 6);

  levels[danger]++;
  if (r.near_miss_img) nearMisses.img++;
  if (r.near_miss_a_href) nearMisses.a++;
  if (r.near_miss_style) nearMisses.style++;
  if (r.near_miss_form) nearMisses.form++;
  if (r.near_miss_svg) nearMisses.svg++;
  if (r.near_miss_math) nearMisses.math++;
  if (r.mxss_security) securityMxss++;
  if (danger >= 3) {
    interesting.push({f, danger, esc: r.danger_escalation, secMxss: r.mxss_security,
      newElems: r.new_elements_after_reparse, rEH: r.r_has_event_handler, rJS: r.r_has_javascript_uri,
      preview: r.sanitized.substring(0, 100)});
  }
}

console.log("=== Danger Level Distribution (" + files.length + " seeds) ===");
for (const [lvl, cnt] of Object.entries(levels)) {
  const pct = (cnt/files.length*100).toFixed(0);
  const bar = "#".repeat(Math.min(Math.round(cnt/files.length*40), 40));
  console.log("  L" + lvl + ": " + String(cnt).padStart(3) + " (" + pct + "%) " + bar);
}

console.log("\n=== Near-Miss Signals ===");
for (const [k,v] of Object.entries(nearMisses)) {
  if (v > 0) console.log("  " + k + ": " + v + " seeds");
}
console.log("  security_mxss: " + securityMxss + " seeds");

console.log("\n=== Level 3+ Seeds ===");
for (const d of interesting.slice(0, 10)) {
  console.log("  " + d.f + " danger=" + d.danger + " secMxss=" + d.secMxss + " newElems=[" + d.newElems.join(",") + "] rEH=" + d.rEH);
  console.log("    " + d.preview);
}
