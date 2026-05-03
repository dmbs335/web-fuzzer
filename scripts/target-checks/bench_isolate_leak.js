#!/usr/bin/env node
/**
 * Isolate which operation leaks memory: DOMPurify, buildResult, or innerHTML.
 */
"use strict";

const path = require("path");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const TARGETS_DIR = path.resolve(__dirname, "..", "..", "targets");
const { buildResult } = require(path.join(TARGETS_DIR, "sanitizer_diff_common.js"));

const PAYLOAD = '<div><svg><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></svg></div>';
const N = 1500;

function measure(label, fn) {
  if (global.gc) global.gc();
  const startHeap = process.memoryUsage().heapUsed;
  const startTime = Date.now();

  for (let i = 0; i < N; i++) fn(i);

  if (global.gc) global.gc();
  const endHeap = process.memoryUsage().heapUsed;
  const elapsed = Date.now() - startTime;
  const growth = endHeap - startHeap;

  console.log(`${label}:`);
  console.log(`  Time: ${(elapsed/1000).toFixed(1)}s (${(N/(elapsed/1000)).toFixed(0)}/s)`);
  console.log(`  Heap: ${(growth/1024/1024).toFixed(1)} MB total (${(growth/N/1024).toFixed(1)} KB/iter)`);
  console.log();
}

// Test 1: DOMPurify.sanitize() only
const w1 = new JSDOM("").window;
const p1 = DOMPurify(w1);
measure("1. DOMPurify.sanitize() only", () => p1.sanitize(PAYLOAD));

// Test 2: buildResult() only (includes analyzeHtml → innerHTML)
measure("2. buildResult() only", () => buildResult(PAYLOAD));

// Test 3: innerHTML assign+read only (reparse simulation)
const rw = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
measure("3. innerHTML reparse only", () => {
  rw.document.body.innerHTML = PAYLOAD;
  rw.document.body.innerHTML;
});

// Test 4: new JSDOM() per call (old leaky behavior)
measure("4. new JSDOM() per call [LEAKY]", () => {
  const d = new JSDOM(`<body>${PAYLOAD}</body>`);
  d.window.document.body.innerHTML;
});

// Test 5: Full pipeline (sanitize + buildResult + reparse + idempotency)
const w5 = new JSDOM("").window;
const p5 = DOMPurify(w5);
const rw5 = new JSDOM("<!DOCTYPE html><html><body></body></html>").window;
measure("5. Full pipeline (DOMPurify + buildResult + reparse)", () => {
  const clean = p5.sanitize(PAYLOAD);
  buildResult(clean);
  rw5.document.body.innerHTML = clean;
  rw5.document.body.innerHTML;
  p5.sanitize(clean); // idempotency
});
