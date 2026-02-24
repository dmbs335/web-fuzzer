"use strict";
const fs = require("fs");
const { JSDOM } = require("jsdom");
const window = new JSDOM("").window;
const DOMPurify = require("dompurify")(window);

const input = fs.readFileSync("../results/xss_enhanced/findings/0001_high_xss/input", "utf8");
const output = DOMPurify.sanitize(input);

console.log("=== DOMPurify OUTPUT ===");
console.log(output);

console.log("\n=== <style> 태그별 CSS 분석 ===");
const dom = new JSDOM(output);
const styles = dom.window.document.querySelectorAll("style");
styles.forEach((s, i) => {
  console.log(`\n<style #${i}>:`);
  console.log(s.textContent);

  // Check each dangerous pattern
  const css = s.textContent;
  if (/@import\s+url\s*\(\s*['"]?\s*javascript/i.test(css))
    console.log("  >>> DANGEROUS: @import url(javascript:...) detected!");
  if (/url\s*\(\s*['"]?\s*javascript/i.test(css))
    console.log("  >>> DANGEROUS: url(javascript:...) detected!");
  if (/expression\s*\(/i.test(css))
    console.log("  >>> DANGEROUS: expression() detected!");
});

// Check if <base> was stripped
console.log("\n=== <base> 태그 확인 ===");
const bases = dom.window.document.querySelectorAll("base");
console.log(`<base> 태그 수: ${bases.length} (input에는 <base target="fatyry"> 있었음)`);

console.log("\n=== 판정 ===");
const hasJsImport = output.includes('@import url("javascript:');
console.log(`@import url("javascript:...") 통과 여부: ${hasJsImport}`);
if (hasJsImport) {
  console.log("VERDICT: REAL - DOMPurify가 <style> 내 @import url(\"javascript:void(0)\")를 통과시킴");
  console.log("  이는 수동 테스트에서 확인한 CSS injection 취약점과 동일한 근본 원인");
} else {
  console.log("VERDICT: FALSE POSITIVE");
}
