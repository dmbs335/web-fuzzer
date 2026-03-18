/**
 * Persistent wrapper for fuzzing target modules.
 *
 * Keeps Node.js process alive and reuses loaded modules.
 * Protocol: length-prefixed binary over stdin/stdout.
 *
 *   Request:  [4-byte BE length][input bytes]
 *   Response: [4-byte BE length][output bytes][4-byte BE exit code]
 *
 * Extended protocol (--coverage flag):
 *   Response: [4B len][output][4B exit_code|0x01000000][4B cov_len][coverage bitmap]
 *   V8 function-level coverage is hashed into a 16KB bitmap.
 *
 * Supported module interfaces:
 *   - sanitize(input) → string (exit code always 0; throws → exit code 1)
 *   - process(input)  → {output: string, exitCode: number}
 *
 * Usage: node persistent_wrapper.js ./module_path.js [--coverage]
 */
"use strict";

const path = require("path");

// Parse args: module path + optional --coverage flag
let modulePath = null;
let coverageEnabled = false;
let linesOnly = false;  // --coverage-lines-only: inject _covered_lines but no bitmap
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === "--coverage") {
    coverageEnabled = true;
  } else if (process.argv[i] === "--coverage-lines-only") {
    coverageEnabled = true;
    linesOnly = true;
  } else if (!modulePath) {
    modulePath = process.argv[i];
  }
}
if (!modulePath) {
  process.stderr.write("Usage: node persistent_wrapper.js <module_path> [--coverage]\n");
  process.exit(1);
}

const mod = require(path.resolve(modulePath));
const useProcess = typeof mod.process === "function";
const useSanitize = typeof mod.sanitize === "function";
if (!useProcess && !useSanitize) {
  process.stderr.write(`Module ${modulePath} must export process(input) or sanitize(input)\n`);
  process.exit(1);
}

const stdin = process.stdin;
const stdout = process.stdout;

// Periodic GC to prevent heap exhaustion in long-running sessions.
// Only effective when Node.js is started with --expose-gc.
const _hasGC = typeof global.gc === "function";
const _GC_EVERY = 200;
let _gcCounter = 0;

// ── V8 Coverage Collection ──────────────────────────────────────
// When --coverage is enabled, uses V8's built-in function-level coverage
// to produce a 16KB bitmap that tracks which functions were executed.
const COV_BITMAP_SIZE = 16384;
const COV_FLAG = 0x01000000;  // Flag bit in exit code

let _v8CovSession = null;
let _covBitmap = null;        // Persistent global bitmap (cumulative)
let _prevCovBitmap = null;    // Snapshot from last iteration (for delta)

if (coverageEnabled) {
  try {
    const inspector = require("inspector");
    _v8CovSession = new inspector.Session();
    _v8CovSession.connect();
    _v8CovSession.post("Profiler.enable");
    _v8CovSession.post("Profiler.startPreciseCoverage", {
      callCount: false,
      detailed: false,  // detailed:true is 20x slower; use function-level + offset→line
    });
    _covBitmap = Buffer.alloc(COV_BITMAP_SIZE);
    _prevCovBitmap = Buffer.alloc(COV_BITMAP_SIZE);
  } catch (e) {
    process.stderr.write(`Coverage init failed: ${e.message}\n`);
    coverageEnabled = false;
  }
}

/**
 * Collect V8 function coverage and hash into a bitmap.
 * Returns the delta bitmap (new bits since last call) or null.
 */
function collectCoverage() {
  if (!coverageEnabled || !_v8CovSession) return null;

  let covResult = null;
  _v8CovSession.post("Profiler.takePreciseCoverage", (err, res) => {
    if (!err) covResult = res;
  });

  if (!covResult || !covResult.result) return null;

  // Save previous state for delta computation
  _prevCovBitmap.fill(0);
  _covBitmap.copy(_prevCovBitmap);

  // Hash each covered range into the bitmap + collect line numbers
  _iterNewLines = [];
  _covCollectCounter++;
  const doLineCollection = (_covCollectCounter % _COV_COLLECT_EVERY === 0);
  const fs = doLineCollection ? require("fs") : null;
  const _sourceCache = collectCoverage._sourceCache || (collectCoverage._sourceCache = {});

  for (const script of covResult.result) {
    const url = script.url || "";
    if (!url || url.startsWith("node:") || url.includes("persistent_wrapper")) continue;

    // Resolve to full path for unambiguous source resolution
    const filePath = url.replace(/^file:\/\/\//, "").replace(/^file:\/\//, "");

    // Lazy-load source for offset→line mapping (only on line collection iterations)
    let sourceLines = _sourceCache[url];
    if (doLineCollection && sourceLines === undefined) {
      try {
        const src = require("fs").readFileSync(filePath, "utf8");
        const starts = [0];
        for (let j = 0; j < src.length; j++) {
          if (src[j] === "\n") starts.push(j + 1);
        }
        _sourceCache[url] = starts;
        sourceLines = starts;
      } catch (e) {
        _sourceCache[url] = null;
        sourceLines = null;
      }
    }

    for (const func of script.functions) {
      for (const range of func.ranges) {
        if (range.count > 0) {
          // Bitmap hash (existing)
          const h = simpleHash(`${script.scriptId}:${range.startOffset}`);
          const idx = h % COV_BITMAP_SIZE;
          _covBitmap[idx] = 1;

          // Line-level tracking (for real concolic) — only every N iterations
          if (doLineCollection && sourceLines) {
            // Binary search for line number from startOffset
            let lo = 0, hi = sourceLines.length - 1;
            while (lo < hi) {
              const mid = (lo + hi + 1) >> 1;
              if (sourceLines[mid] <= range.startOffset) lo = mid;
              else hi = mid - 1;
            }
            const lineNum = lo + 1;  // 1-based
            const key = `${filePath}:${lineNum}`;
            if (!_cumulativeLines.has(key)) {
              _cumulativeLines.add(key);
              _iterNewLines.push([filePath, lineNum]);
            }
          }
        }
      }
    }
  }

  // Compute delta: only new bits
  const delta = Buffer.alloc(COV_BITMAP_SIZE);
  let hasNew = false;
  for (let i = 0; i < COV_BITMAP_SIZE; i++) {
    if (_covBitmap[i] && !_prevCovBitmap[i]) {
      delta[i] = 1;
      hasNew = true;
    }
  }
  return hasNew ? delta : null;
}

// ── Line-level coverage tracking (for real concolic) ────────────
// Tracks actual source file + line numbers, not just bitmap hashes.
// Cumulative set of all lines ever hit + per-iteration new lines.
const _cumulativeLines = new Set();  // "file:line" strings
let _iterNewLines = [];              // [[filePath, line], ...] — new this iteration
let _covCollectCounter = 0;
// In lines-only mode, collect every iteration (needed for near-miss analysis).
// In full coverage mode, throttle to every 10th (perf optimization for fuzzing).
const _COV_COLLECT_EVERY = linesOnly ? 1 : 10;

/** Simple non-crypto hash for coverage bitmap indexing. */
function simpleHash(str) {
  let h = 0x811c9dc5;  // FNV-1a offset basis
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;  // FNV prime, force uint32
  }
  return h;
}

function sendResponse(output, exitCode) {
  if (coverageEnabled) {
    // Collect coverage FIRST (populates _iterNewLines)
    const covBitmap = collectCoverage();

    // Inject _covered_lines into JSON output for real concolic
    if (_iterNewLines.length > 0) {
      try {
        const parsed = JSON.parse(output);
        parsed._covered_lines = _iterNewLines;
        output = JSON.stringify(parsed);
      } catch (e) { /* not JSON, skip */ }
    }

    const outBuf = Buffer.from(output, "utf8");

    if (covBitmap && !linesOnly) {
      // Extended protocol: [4B len][output][4B exit_code|COV_FLAG][4B cov_len][bitmap]
      const resp = Buffer.alloc(4 + outBuf.length + 4 + 4 + covBitmap.length);
      resp.writeUInt32BE(outBuf.length, 0);
      outBuf.copy(resp, 4);
      resp.writeUInt32BE((exitCode | COV_FLAG) >>> 0, 4 + outBuf.length);
      resp.writeUInt32BE(covBitmap.length, 4 + outBuf.length + 4);
      covBitmap.copy(resp, 4 + outBuf.length + 4 + 4);
      stdout.write(resp);
      return;
    }
  }

  // Standard protocol: [4-byte len][output][4-byte exit code]
  const stdBuf = Buffer.from(output, "utf8");
  const resp = Buffer.alloc(4 + stdBuf.length + 4);
  resp.writeUInt32BE(stdBuf.length, 0);
  stdBuf.copy(resp, 4);
  resp.writeUInt32BE(exitCode, 4 + stdBuf.length);
  stdout.write(resp);
}

let buf = Buffer.alloc(0);

stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);

  // Process all complete messages in buffer
  while (buf.length >= 4) {
    const len = buf.readUInt32BE(0);
    if (buf.length < 4 + len) break; // incomplete message

    const input = buf.toString("utf8", 4, 4 + len);
    // Copy remaining bytes to a NEW buffer to release the old one.
    // Buffer.slice/subarray creates a view that retains the entire
    // underlying ArrayBuffer, causing unbounded memory growth.
    const remaining = buf.length - (4 + len);
    if (remaining > 0) {
      const newBuf = Buffer.allocUnsafe(remaining);
      buf.copy(newBuf, 0, 4 + len);
      buf = newBuf;
    } else {
      buf = Buffer.alloc(0);
    }

    // Periodic GC hint
    if (_hasGC && ++_gcCounter >= _GC_EVERY) {
      _gcCounter = 0;
      global.gc();
    }

    let output = "";
    let exitCode = 0;

    // Guard: reject inputs that can hang XML parsers (entity expansion, huge input)
    const skip = input.length > 100000 ||
      (input.includes("<!DOCTYPE") && /<!DOCTYPE[^>]*\[/.test(input));

    if (skip) {
      exitCode = 1;
      sendResponse(output, exitCode);
    } else {
      try {
        if (useProcess) {
          const result = mod.process(input);
          // Support async process() returning a Promise
          if (result && typeof result.then === "function") {
            result.then(
              (r) => sendResponse(r.output || "", r.exitCode || 0),
              (err) => {
                process.stderr.write(`Error: ${err.message}\n`);
                sendResponse("", 1);
              }
            );
            continue;
          }
          output = result.output || "";
          exitCode = result.exitCode || 0;
        } else {
          output = mod.sanitize(input);
        }
      } catch (err) {
        output = "";
        exitCode = 1;
        process.stderr.write(`Error: ${err.message}\n`);
      }
      sendResponse(output, exitCode);
    }
  }
});

stdin.on("end", () => {
  process.exit(0);
});
