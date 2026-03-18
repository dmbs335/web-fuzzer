#!/usr/bin/env node
/**
 * Benchmark persistent wrapper memory and speed.
 *
 * Measures:
 *   - Execution speed (exec/s) over N iterations
 *   - RSS memory growth over time
 *   - GC pause accumulation
 *
 * Usage: node targets/bench_persistent_memory.js [module_path] [iterations]
 *
 * Compares FIXED (innerHTML reuse) vs LEAK (new JSDOM per call).
 */
"use strict";

const { JSDOM } = require("jsdom");

const modulePath = process.argv[2] || "./sanitizer_dompurify_mxss_module.js";
const ITERATIONS = parseInt(process.argv[3] || "2000", 10);
const REPORT_EVERY = 200;

// Test payloads of varying complexity
const PAYLOADS = [
  '<div>hello</div>',
  '<script>alert(1)</script>',
  '<svg><foreignObject><body><img src=x onerror=alert(1)></body></foreignObject></svg>',
  '<math><mtext><style><img src=x onerror=alert(1)></style></mtext></math>',
  '<div><svg><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></svg></div>',
  '<table><tr><td><svg><foreignObject><body><math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math></body></foreignObject></svg></td></tr></table>',
  '<noscript><svg><math><mtext><style>' + '<div>'.repeat(50) + 'payload' + '</div>'.repeat(50) + '</style></mtext></math></svg></noscript>',
  '<div>' + '<svg><foreignObject><body>'.repeat(5) + '<img src=x onerror=alert(1)>' + '</body></foreignObject></svg>'.repeat(5) + '</div>',
];

// Also test with a LEAKED version to compare
function createLeakyModule() {
  const DOMPurify = require("dompurify");
  const window = new JSDOM("").window;
  const purify = DOMPurify(window);
  const { buildResult } = require("./sanitizer_diff_common");

  return {
    sanitize(html) {
      const clean = purify.sanitize(html);
      const result = buildResult(clean);
      // LEAK: new JSDOM per call (old behavior)
      const dom2 = new JSDOM(`<body>${clean}</body>`);
      const reparsed = dom2.window.document.body.innerHTML;
      const clean2 = purify.sanitize(clean);
      result.reparsed = reparsed;
      result.mxss = clean !== reparsed;
      result.idempotency = clean !== clean2;
      return JSON.stringify(result);
    }
  };
}

function formatMB(bytes) {
  return (bytes / 1024 / 1024).toFixed(1);
}

function benchmark(label, mod, iterations) {
  const snapshots = [];
  const startMem = process.memoryUsage();
  const startTime = Date.now();

  for (let i = 0; i < iterations; i++) {
    const payload = PAYLOADS[i % PAYLOADS.length];
    mod.sanitize(payload);

    if ((i + 1) % REPORT_EVERY === 0) {
      const mem = process.memoryUsage();
      const elapsed = Date.now() - startTime;
      snapshots.push({
        iter: i + 1,
        elapsed_ms: elapsed,
        rss_mb: parseFloat(formatMB(mem.rss)),
        heap_used_mb: parseFloat(formatMB(mem.heapUsed)),
        heap_total_mb: parseFloat(formatMB(mem.heapTotal)),
        external_mb: parseFloat(formatMB(mem.external)),
        exec_per_sec: ((i + 1) / (elapsed / 1000)).toFixed(1),
      });
    }
  }

  const endTime = Date.now();
  const endMem = process.memoryUsage();
  const totalSec = (endTime - startTime) / 1000;

  return {
    label,
    iterations,
    total_sec: totalSec.toFixed(2),
    avg_exec_per_sec: (iterations / totalSec).toFixed(1),
    start_rss_mb: formatMB(startMem.rss),
    end_rss_mb: formatMB(endMem.rss),
    rss_growth_mb: formatMB(endMem.rss - startMem.rss),
    start_heap_mb: formatMB(startMem.heapUsed),
    end_heap_mb: formatMB(endMem.heapUsed),
    heap_growth_mb: formatMB(endMem.heapUsed - startMem.heapUsed),
    external_mb: formatMB(endMem.external),
    snapshots,
  };
}

// Run benchmarks
console.error(`Benchmarking: ${ITERATIONS} iterations each\n`);

// 1. Fixed version (current code with innerHTML reuse)
console.error("=== FIXED (innerHTML reuse) ===");
const fixedMod = require(modulePath);
const fixedResult = benchmark("FIXED", fixedMod, ITERATIONS);
console.error(`  Speed: ${fixedResult.avg_exec_per_sec} exec/s`);
console.error(`  RSS: ${fixedResult.start_rss_mb} -> ${fixedResult.end_rss_mb} MB (+${fixedResult.rss_growth_mb} MB)`);
console.error(`  Heap: ${fixedResult.start_heap_mb} -> ${fixedResult.end_heap_mb} MB (+${fixedResult.heap_growth_mb} MB)\n`);

// Force GC before next benchmark
if (global.gc) global.gc();

// 2. Leaky version (old behavior: new JSDOM per call)
console.error("=== LEAKY (new JSDOM per call) ===");
const leakyMod = createLeakyModule();
const leakyResult = benchmark("LEAKY", leakyMod, ITERATIONS);
console.error(`  Speed: ${leakyResult.avg_exec_per_sec} exec/s`);
console.error(`  RSS: ${leakyResult.start_rss_mb} -> ${leakyResult.end_rss_mb} MB (+${leakyResult.rss_growth_mb} MB)`);
console.error(`  Heap: ${leakyResult.start_heap_mb} -> ${leakyResult.end_heap_mb} MB (+${leakyResult.heap_growth_mb} MB)\n`);

// Output JSON for analysis
const output = {
  fixed: fixedResult,
  leaky: leakyResult,
  speedup: (parseFloat(fixedResult.avg_exec_per_sec) / parseFloat(leakyResult.avg_exec_per_sec)).toFixed(2) + "x",
  memory_savings_mb: (parseFloat(leakyResult.rss_growth_mb) - parseFloat(fixedResult.rss_growth_mb)).toFixed(1),
};

console.log(JSON.stringify(output, null, 2));
