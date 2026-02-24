/**
 * Persistent wrapper for fuzzing target modules.
 *
 * Keeps Node.js process alive and reuses loaded modules.
 * Protocol: length-prefixed binary over stdin/stdout.
 *
 *   Request:  [4-byte BE length][input bytes]
 *   Response: [4-byte BE length][output bytes][4-byte BE exit code]
 *
 * Supported module interfaces:
 *   - sanitize(input) → string (exit code always 0; throws → exit code 1)
 *   - process(input)  → {output: string, exitCode: number}
 *
 * Usage: node persistent_wrapper.js ./module_path.js
 */
"use strict";

const path = require("path");

const modulePath = process.argv[2];
if (!modulePath) {
  process.stderr.write("Usage: node persistent_wrapper.js <module_path>\n");
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

let buf = Buffer.alloc(0);

stdin.on("data", (chunk) => {
  buf = Buffer.concat([buf, chunk]);

  // Process all complete messages in buffer
  while (buf.length >= 4) {
    const len = buf.readUInt32BE(0);
    if (buf.length < 4 + len) break; // incomplete message

    const input = buf.slice(4, 4 + len).toString("utf8");
    buf = buf.slice(4 + len);

    let output = "";
    let exitCode = 0;
    try {
      if (useProcess) {
        const result = mod.process(input);
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

    const outBuf = Buffer.from(output, "utf8");
    // Single write: [4-byte len][output][4-byte exit code]
    const resp = Buffer.alloc(4 + outBuf.length + 4);
    resp.writeUInt32BE(outBuf.length, 0);
    outBuf.copy(resp, 4);
    resp.writeUInt32BE(exitCode, 4 + outBuf.length);
    stdout.write(resp);
  }
});

stdin.on("end", () => {
  process.exit(0);
});
