# Sanitizer Fuzzing - Comprehensive Verification Report

**Date:** 2026-02-22
**Targets:** DOMPurify 3.3.1 (JSDOM), sanitize-html, js-xss
**Sessions:** 6 fuzzing sessions, 13 findings total

---

## All Sessions Overview

| Session | Executions | Findings | Notable |
|---------|-----------|----------|---------|
| xss_sanitizer_diff | 230 | 2 | javascript: URI (FP) |
| xss_sanitizer_long | 913 | 1 | differential only |
| xss_enhanced | 459 | 2 | **CSS @import javascript: bypass (GENUINE)** |
| mxss_taxonomy (v1) | 1,075 | 4 | DoS candidate (not reproducible) |
| mxss_taxonomy_v2 (v2) | 2,075 | 2 | xmlns onload (conditional risk) |
| mxss_taxonomy_v3 (v3) | 3,200 | 2 | attribute value FP |

---

## Verification Summary

| # | Finding | Session | Oracle | Severity | Verdict |
|---|---------|---------|--------|----------|---------|
| 1 | CSS @import javascript: URI bypass | xss_enhanced | xss | high | **GENUINE BYPASS** |
| 2 | xmlns onload injection | v2 | xss | critical | **CONDITIONAL RISK** |
| 3 | javascript: URI in base href | xss_sanitizer_diff | xss | critical | **FALSE POSITIVE** |
| 4 | SVG onfocus text escape | v1 | xss | critical | **FALSE POSITIVE** |
| 5 | `<set onbegin=` in option value | v1 | xss | critical | **FALSE POSITIVE** |
| 6 | `<a name=` onmessageerror | v3 | xss | critical | **FALSE POSITIVE** |
| 7 | DOMPurify hang (exit -9) | v1 | differential | high | **NOT REPRODUCIBLE** |
| 8-13 | Output mismatch (6x) | all | differential | medium | **GENUINE** |

---

## Detailed Analysis

### Finding #1: CSS @import javascript: URI Bypass (xss_enhanced 0001_high_xss) ★★★

**Severity:** HIGH — Genuine DOMPurify sanitization bypass
**Affected:** DOMPurify 3.3.1 (confirmed in JSDOM, CDN 3.2.4 pending browser verification)

**Discovery:** The fuzzer found that DOMPurify allows `@import url("javascript:void(0)")`
inside `<style>` tags when the input contains text/elements before the style tag.

**Root Cause:** DOMPurify's CSS URI filtering (for `javascript:`, `-moz-binding`, `url(javascript:)`)
is only applied when `<style>` is parsed in head context. When ANY non-whitespace text or HTML
element precedes the `<style>` tag, the HTML parser treats it as body content and the CSS
filtering is completely bypassed.

**Minimal Reproduction:**
```
BLOCKED: <style>@import url("javascript:alert(1)");</style>
BYPASS:  x<style>@import url("javascript:alert(1)");</style>
```

**Bypass conditions (verified):**
| Prefix | Result |
|--------|--------|
| (none) | BLOCKED |
| Whitespace (space, \n, \t) | BLOCKED |
| HTML comment | BLOCKED |
| `<title>` | BLOCKED |
| Single character "x" | **BYPASS** |
| Zero-width space \u200B | **BYPASS** |
| NBSP \xA0 | **BYPASS** |
| BOM \xEF\xBB\xBF | **BYPASS** |
| `<div></div>` | **BYPASS** |
| `<p>text</p>` | **BYPASS** |
| `<br>` | **BYPASS** |
| `<img src="x">` | **BYPASS** |

**Affected CSS patterns (with text prefix):**
| Pattern | Result |
|---------|--------|
| `@import url("javascript:...")` | **BYPASS** |
| `background: url("javascript:...")` | **BYPASS** |
| `-moz-binding: url("javascript:...")` | **BYPASS** |
| `expression(alert(1))` | BLOCKED (still filtered) |
| `@import url("data:...")` | BLOCKED (still filtered) |

**Real-world impact:** In virtually ALL applications, sanitized content is embedded within
existing page structure. The bypass condition (any content before `<style>`) is nearly always
met. While modern browsers don't execute `javascript:` in CSS `@import`, this affects:
- Legacy browsers (IE6-8, old WebKit) — direct JS execution
- Email clients with non-standard CSS handling
- Electron/WebView apps with older rendering engines
- Server-side rendering engines that process CSS

**PoC:** `poc/poc_css_import_javascript_uri.html`

---

### Finding #2: xmlns onload injection (v2 0001_critical_xss) ★★

**Severity:** CONDITIONAL RISK
**Affected:** DOMPurify 3.x

**Input:** `<math xmlns="http://www.w3.org/1998/Mat' onload='h/MathML">`
**DOMPurify Output:** Preserves the xmlns attribute with embedded `onload` pattern
**Verification (JSDOM):** NOT exploitable — double quotes contain the entire value
**Verification (Browser):** NOT exploitable in standard innerHTML round-trip
**Conditional Exploit:** If any downstream processing converts double quotes to single quotes:
```
SAFE:   <math xmlns="...Mat' onload='h/MathML">   (onload inside value)
DANGER: <math xmlns='...Mat' onload='h/MathML'>   (onload as separate attr!)
```

**Verdict:** CONDITIONAL RISK — DOMPurify should not allow xmlns values containing
embedded event handler patterns. Exploitable when:
- Server-side template engine re-quotes attributes
- HTML pretty-printer normalizes to single quotes
- SSR framework re-renders with different serialization
- Custom proxy/middleware modifies quoting

**PoC:** `poc/poc_xmlns_onload_mxss.html`

---

### Finding #3: javascript: URI in base href (xss_sanitizer_diff 0001_critical_xss)

**Input:** Malformed HTML with `<base href="javascript:void(0)" target="_self">`
**DOMPurify Output:** The entire content including `<base href="javascript:void(0)">` is
trapped inside a `<title>` tag as entity-encoded text:
```html
<title>bfoLISRABr1V&gt;
...
&lt;base href="javascript:void(0)" target="_self"&gt;
...</title>
```
**Verification:** The `javascript:` URI is NOT a DOM attribute — it's entity-encoded text
content inside `<title>`. The malformed HTML causes JSDOM to swallow everything into the
title element.
**Verdict:** FALSE POSITIVE — XSS oracle matched text pattern, not actual DOM structure

---

### Finding #4: SVG onfocus text escape (v1 0001_critical_xss)

**Input:** HTML with `<svg inert>` and trailing `\"autofocus onfocus=\"` text
**DOMPurify Output:** SVG element preserved, `onfocus` appears as plain text node
**Verification:** `onfocus` is NOT a DOM attribute — it's unescaped text content outside any tag
**Verdict:** FALSE POSITIVE — XSS oracle matched text pattern, not actual DOM attribute

---

### Finding #5: set onbegin in option value (v1 0002_critical_xss)

**Input:** `<option value="9d0stei<svg><set onbegin=RSZ7YcKNlm7mTTrjOQS`
**DOMPurify Output:** Event handler pattern inside double-quoted `value` attribute
**Verification:** Browser parses `<set onbegin=...` as part of the attribute value string
**Verdict:** FALSE POSITIVE — content trapped inside double-quoted attribute value

---

### Finding #6: Attribute value onmessageerror (v3 0001_critical_xss)

**Input:** `<a name="kfeisdy onmessageerror="console.log(1)">`
**DOMPurify Output:** `name="kfeisdy onmessageerror="` (event handler inside quoted value)
**Verification:** Browser treats entire string as `name` attribute value
**Verdict:** FALSE POSITIVE — same quote-containment pattern as #5

---

### Finding #7: DOMPurify hang / DoS (v1 0001_high_differential)

**Input:** 189-byte simple HTML document
**Original behavior:** DOMPurify/JSDOM hung for 3,467 seconds (~57 min), killed with SIGKILL
**Reference (sanitize-html):** Completed in 7.2 seconds
**Re-verification:** DOMPurify completes within 15 seconds
**Verdict:** NOT REPRODUCIBLE — may have been caused by system-specific conditions
(memory pressure, other processes). Could be a non-deterministic ReDoS or memory issue.

---

### Findings #8-13: Differential output mismatches (all sessions, medium)

**Pattern:** DOMPurify preserves structural HTML (math, SVG, details, hgroup, form elements)
while sanitize-html strips everything to text and js-xss entity-encodes all tags.

**Consistent across all 6 sessions** — same fingerprint `fd368fa057eb7f9e`.

**Verdict:** GENUINE behavioral differences — not vulnerabilities per se, but
demonstrate different sanitizer philosophies and attack surface implications.

**PoC:** `poc/poc_differential_sanitizer_behavior.html`

---

## Files

| File | Description |
|------|-------------|
| `poc/poc_css_import_javascript_uri.html` | Interactive PoC for CSS @import javascript: bypass with comprehensive test matrix |
| `poc/poc_xmlns_onload_mxss.html` | Interactive PoC for xmlns onload injection with quote-conversion test |
| `poc/poc_differential_sanitizer_behavior.html` | Sanitizer behavior comparison demonstration |
| `targets/verify_browser.html` | Browser-based round-trip verification for mXSS taxonomy XSS findings |
| `targets/verify_mxss.js` | Node.js/JSDOM verification script |
| `targets/test_css_import5.js` | Comprehensive CSS bypass condition analysis script |

---

## Recommendations

1. **DOMPurify Bug Report:** CSS URI filtering should be applied regardless of whether `<style>`
   is in head or body context. The text-prefix bypass (Finding #1) is a genuine sanitizer bug.
2. **DOMPurify:** Should sanitize `xmlns` attribute values containing event handler patterns
3. **Application developers:** Use `FORBID_TAGS: ['style']` in DOMPurify config if inline CSS
   is not needed, or add `uponSanitizeElement` hook to filter CSS content
4. **Application developers:** Never re-serialize DOMPurify output with different quoting conventions
5. **Defense-in-depth:** Always pair sanitization with Content-Security-Policy headers:
   `style-src 'self'; script-src 'self'`
6. **Fuzzer improvement:** XSS oracle should verify findings against actual DOM tree,
   not just regex pattern matching on serialized output. CSS-based XSS vectors need
   separate oracle logic beyond event handler attribute checking.
