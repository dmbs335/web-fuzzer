/**
 * Probe: Buffer.from encoding edge cases across JWT libraries.
 *
 * Tests whether base64url decoding differences between libraries
 * can cause signature verification divergence (accept vs reject).
 *
 * Attack vectors:
 *   1. base64 standard chars (+/) vs base64url chars (-_)
 *   2. Non-base64 chars silently ignored vs rejected
 *   3. Whitespace/control chars in base64url segments
 *   4. Padding tolerance (=, ==, no pad)
 *   5. High bytes (>0x7F) in signature segment
 */
"use strict";

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { createVerifier, createSigner } = require("fast-jwt");
const jose = require("jose");

const SECRET = Buffer.from("secret", "utf8");

// ── helpers ──────────────────────────────────────────────────────

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function makeValidToken(payload = { sub: "admin", role: "admin" }) {
  const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const sigInput = header + "." + body;
  const sig = b64url(
    crypto.createHmac("sha256", SECRET).update(sigInput).digest()
  );
  return { header, body, sig, full: sigInput + "." + sig };
}

// ── library testers ─────────────────────────────────────────────

function testJsonwebtoken(token) {
  try {
    jwt.verify(token, SECRET, { algorithms: ["HS256", "HS384", "HS512"] });
    return "ACCEPT";
  } catch (e) {
    return "REJECT:" + e.message.slice(0, 80);
  }
}

function testFastjwt(token) {
  try {
    const v = createVerifier({
      key: SECRET,
      algorithms: ["HS256"],
      clockTolerance: 999999999,
      ignoreExpiration: true,
      ignoreNotBefore: true,
    });
    v(token);
    return "ACCEPT";
  } catch (e) {
    return "REJECT:" + (e.message || "").slice(0, 80);
  }
}

async function testJose(token) {
  try {
    const key = await jose.importJWK(
      { kty: "oct", k: b64url(SECRET) },
      "HS256"
    );
    await jose.jwtVerify(token, key, { algorithms: ["HS256"] });
    return "ACCEPT";
  } catch (e) {
    return "REJECT:" + (e.message || "").slice(0, 80);
  }
}

// ── Buffer.from behavior probes ─────────────────────────────────

function probeBufferFrom() {
  console.log("\n=== Buffer.from base64 vs base64url behavior ===\n");

  // Test: does Buffer.from('base64') accept base64url chars?
  const urlsafe = "abc-def_gh";
  const standard = "abc+def/gh";

  const b1 = Buffer.from(urlsafe, "base64");
  const b2 = Buffer.from(standard, "base64");
  const b3 = Buffer.from(urlsafe, "base64url");
  const b4 = Buffer.from(standard, "base64url");

  console.log("base64url str → base64 decode :", b1.toString("hex"));
  console.log("standard  str → base64 decode :", b2.toString("hex"));
  console.log("base64url str → base64url decode:", b3.toString("hex"));
  console.log("standard  str → base64url decode:", b4.toString("hex"));
  console.log(
    "base64 accepts both?",
    b1.toString("hex") === b3.toString("hex") ? "YES (identical)" : "NO (different!)"
  );

  // Test: non-base64 chars
  console.log("\n--- Non-base64 char handling ---");
  const withSpaces = "eyJh bGci OiJI UzI1 NiJ9";
  const clean = "eyJhbGciOiJIUzI1NiJ9";
  const b5 = Buffer.from(withSpaces, "base64");
  const b6 = Buffer.from(clean, "base64");
  const b7 = Buffer.from(withSpaces, "base64url");
  const b8 = Buffer.from(clean, "base64url");
  console.log("spaces base64    :", b5.toString("hex"));
  console.log("clean  base64    :", b6.toString("hex"));
  console.log("spaces base64url :", b7.toString("hex"));
  console.log("clean  base64url :", b8.toString("hex"));
  console.log(
    "base64 ignores spaces?",
    b5.toString("hex") === b6.toString("hex") ? "YES" : "NO"
  );
  console.log(
    "base64url ignores spaces?",
    b7.toString("hex") === b8.toString("hex") ? "YES" : "NO"
  );

  // Test: newlines, tabs, null bytes
  console.log("\n--- Control char handling ---");
  for (const [name, char] of [
    ["tab", "\t"],
    ["newline", "\n"],
    ["CR", "\r"],
    ["null", "\0"],
    ["CRLF", "\r\n"],
  ]) {
    const injected = "eyJhbGci" + char + "OiJIUzI1NiJ9";
    const b = Buffer.from(injected, "base64");
    const bu = Buffer.from(injected, "base64url");
    const match64 = b.toString("hex") === b6.toString("hex");
    const matchUrl = bu.toString("hex") === b8.toString("hex");
    console.log(
      `${name.padEnd(8)} base64=${match64 ? "ignored" : "CHANGED"} base64url=${matchUrl ? "ignored" : "CHANGED"}`
    );
  }
}

// ── JWT mutation tests ──────────────────────────────────────────

async function testMutations() {
  const valid = makeValidToken();
  console.log("\n=== JWT library differential: signature mutations ===\n");
  console.log("Valid token sig:", valid.sig.slice(0, 20) + "...");

  // First verify the valid token works
  const jwtR = testJsonwebtoken(valid.full);
  const fjR = testFastjwt(valid.full);
  const joseR = await testJose(valid.full);
  console.log(`\nBaseline (valid): jwt=${jwtR} fast=${fjR} jose=${joseR}`);

  const mutations = [];

  // 1. Replace - with + (base64url → standard base64)
  if (valid.sig.includes("-")) {
    mutations.push(["sig:-→+", valid.sig.replace(/-/g, "+")]);
  }
  // 2. Replace _ with / (base64url → standard base64)
  if (valid.sig.includes("_")) {
    mutations.push(["sig:_→/", valid.sig.replace(/_/g, "/")]);
  }

  // 3. Add spaces in signature
  mutations.push([
    "sig:spaces",
    valid.sig.slice(0, 10) + " " + valid.sig.slice(10),
  ]);

  // 4. Add tab in signature
  mutations.push([
    "sig:tab",
    valid.sig.slice(0, 10) + "\t" + valid.sig.slice(10),
  ]);

  // 5. Add newline in signature
  mutations.push([
    "sig:newline",
    valid.sig.slice(0, 10) + "\n" + valid.sig.slice(10),
  ]);

  // 6. Add \r in signature
  mutations.push([
    "sig:CR",
    valid.sig.slice(0, 10) + "\r" + valid.sig.slice(10),
  ]);

  // 7. Add null byte in signature
  mutations.push([
    "sig:null",
    valid.sig.slice(0, 10) + "\0" + valid.sig.slice(10),
  ]);

  // 8. Add padding to signature
  mutations.push(["sig:pad=", valid.sig + "="]);
  mutations.push(["sig:pad==", valid.sig + "=="]);

  // 9. Add spaces in header segment
  mutations.push([
    "hdr:space",
    valid.header.slice(0, 5) + " " + valid.header.slice(5) + "." + valid.body + "." + valid.sig,
  ]);

  // 10. Add spaces in payload segment
  mutations.push([
    "body:space",
    valid.header + "." + valid.body.slice(0, 5) + " " + valid.body.slice(5) + "." + valid.sig,
  ]);

  // 11. Trailing whitespace on whole token
  mutations.push(["token:trailing_space", valid.full + " "]);
  mutations.push(["token:trailing_tab", valid.full + "\t"]);
  mutations.push(["token:trailing_newline", valid.full + "\n"]);

  // 12. Unicode whitespace (NBSP, zero-width space, etc.)
  mutations.push(["sig:NBSP", valid.sig.slice(0, 10) + "\u00A0" + valid.sig.slice(10)]);
  mutations.push(["sig:ZWSP", valid.sig.slice(0, 10) + "\u200B" + valid.sig.slice(10)]);
  mutations.push(["sig:FEFF", valid.sig.slice(0, 10) + "\uFEFF" + valid.sig.slice(10)]);

  // 13. Mixed base64/base64url in signature
  // Convert some chars to standard base64 equivalents mid-sig
  const sigChars = valid.sig.split("");
  for (let i = 0; i < sigChars.length; i++) {
    if (sigChars[i] === "-") {
      const mixed = [...sigChars];
      mixed[i] = "+";
      mutations.push([`sig:mixed_pos${i}_-→+`, mixed.join("")]);
      break; // just first occurrence
    }
  }
  for (let i = 0; i < sigChars.length; i++) {
    if (sigChars[i] === "_") {
      const mixed = [...sigChars];
      mixed[i] = "/";
      mutations.push([`sig:mixed_pos${i}_→/`, mixed.join("")]);
      break;
    }
  }

  // 14. Header base64/base64url confusion: what if header has + or /?
  // Re-encode header with standard base64
  const headerStd = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64");
  if (headerStd !== valid.header) {
    const stdToken = headerStd + "." + valid.body + "." +
      b64url(crypto.createHmac("sha256", SECRET).update(headerStd + "." + valid.body).digest());
    mutations.push(["hdr:base64_std_resigned", stdToken]);
    // Same sig (not resigned) — should break
    mutations.push(["hdr:base64_std_oldsig", headerStd + "." + valid.body + "." + valid.sig]);
  }

  // 15. Percent-encoded chars in base64url
  mutations.push([
    "sig:%20",
    valid.sig.slice(0, 10) + "%20" + valid.sig.slice(10),
  ]);

  // Run all mutations
  console.log(`\nRunning ${mutations.length} mutations...\n`);
  console.log("Mutation".padEnd(35), "jsonwebtoken".padEnd(15), "fast-jwt".padEnd(15), "jose".padEnd(15), "DIFF?");
  console.log("-".repeat(95));

  const diffs = [];

  for (const [name, mutSig] of mutations) {
    let token;
    if (name.startsWith("hdr:") || name.startsWith("body:") || name.startsWith("token:")) {
      // Full token already constructed
      token = name.startsWith("token:") ? mutSig : mutSig;
    } else {
      token = valid.header + "." + valid.body + "." + mutSig;
    }

    const r1 = testJsonwebtoken(token);
    const r2 = testFastjwt(token);
    const r3 = await testJose(token);

    const results = [r1.startsWith("ACCEPT"), r2.startsWith("ACCEPT"), r3.startsWith("ACCEPT")];
    const allSame = results.every((r) => r === results[0]);
    const marker = allSame ? "" : "*** DIFFERENTIAL ***";

    if (!allSame) {
      diffs.push({ name, token, r1, r2, r3 });
    }

    console.log(
      name.padEnd(35),
      (r1.startsWith("ACCEPT") ? "ACCEPT" : "REJECT").padEnd(15),
      (r2.startsWith("ACCEPT") ? "ACCEPT" : "REJECT").padEnd(15),
      (r3.startsWith("ACCEPT") ? "ACCEPT" : "REJECT").padEnd(15),
      marker
    );
  }

  if (diffs.length > 0) {
    console.log(`\n\n🔥 FOUND ${diffs.length} DIFFERENTIALS:\n`);
    for (const d of diffs) {
      console.log(`--- ${d.name} ---`);
      console.log(`Token: ${d.token}`);
      console.log(`  jsonwebtoken: ${d.r1}`);
      console.log(`  fast-jwt:     ${d.r2}`);
      console.log(`  jose:         ${d.r3}`);
      console.log();
    }
  } else {
    console.log("\nNo differentials found in this batch.");
  }
}

// ── main ────────────────────────────────────────────────────────

async function main() {
  probeBufferFrom();
  await testMutations();
}

main().catch(console.error);
