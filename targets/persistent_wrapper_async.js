/**
 * Async persistent wrapper for fuzzing target modules.
 *
 * Same binary protocol as persistent_wrapper.js but supports
 * async module.sanitize(input) for Playwright-based targets.
 *
 *   Request:  [4-byte BE length][input bytes]
 *   Response: [4-byte BE length][output bytes][4-byte BE exit code]
 *
 * Usage: node persistent_wrapper_async.js ./module_path.js
 */
"use strict";

const path = require("path");

const modulePath = process.argv[2];
if (!modulePath) {
  process.stderr.write("Usage: node persistent_wrapper_async.js <module_path>\n");
  process.exit(1);
}

const mod = require(path.resolve(modulePath));
const useSanitize = typeof mod.sanitize === "function";
const useProcess = typeof mod.process === "function";
if (!useSanitize && !useProcess) {
  process.stderr.write(`Module ${modulePath} must export sanitize(input) or process(input)\n`);
  process.exit(1);
}

const stdin = process.stdin;
const stdout = process.stdout;

// Periodic GC
const _hasGC = typeof global.gc === "function";
const _GC_EVERY = 500;
let _gcCounter = 0;

let buf = Buffer.alloc(0);
let processing = false;
const queue = [];

function writeResponse(output, exitCode) {
  const outBuf = Buffer.from(output, "utf8");
  const resp = Buffer.alloc(4 + outBuf.length + 4);
  resp.writeUInt32BE(outBuf.length, 0);
  outBuf.copy(resp, 4);
  resp.writeUInt32BE(exitCode, 4 + outBuf.length);
  stdout.write(resp);
}

async function processMessage(input) {
  if (_hasGC && ++_gcCounter >= _GC_EVERY) {
    _gcCounter = 0;
    global.gc();
  }

  // Guard: reject huge inputs or entity expansion
  const skip = input.length > 100000 ||
    (input.includes("<!DOCTYPE") && /<!DOCTYPE[^>]*\[/.test(input));

  if (skip) {
    writeResponse("", 1);
    return;
  }

  try {
    let output = "";
    let exitCode = 0;

    if (useProcess) {
      const result = await mod.process(input);
      output = result.output || "";
      exitCode = result.exitCode || 0;
    } else {
      output = await mod.sanitize(input);
    }

    writeResponse(output, exitCode);
  } catch (err) {
    process.stderr.write(`Error: ${err.message}\n`);
    writeResponse("", 1);
  }
}

async function processQueue() {
  if (processing) return;
  processing = true;

  while (queue.length > 0) {
    const input = queue.shift();
    await processMessage(input);
  }

  processing = false;
}

stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);

  while (buf.length >= 4) {
    const len = buf.readUInt32BE(0);
    if (buf.length < 4 + len) break;

    const input = buf.slice(4, 4 + len).toString("utf8");
    buf = buf.slice(4 + len);
    queue.push(input);
  }

  processQueue();
});

stdin.on("end", async () => {
  // Process remaining messages
  while (queue.length > 0) {
    await processQueue();
  }
  if (mod.cleanup) await mod.cleanup();
  process.exit(0);
});

// Graceful shutdown
process.on("SIGTERM", async () => {
  if (mod.cleanup) await mod.cleanup();
  process.exit(0);
});
