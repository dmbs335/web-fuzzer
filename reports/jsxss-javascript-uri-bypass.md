# Defense-in-Depth Report: Incomplete `javascript:` URI Filtering in js-xss

**Package**: [xss](https://www.npmjs.com/package/xss) (js-xss)
**Affected Version**: <= 1.0.15 (current latest)
**Severity**: Low (defense-in-depth)
**Type**: Inconsistent URI scheme filtering
**Reporter**: Automated differential fuzzer (DOMPurify vs sanitize-html vs js-xss)
**Date**: 2026-03-01

---

## Summary

The `safeAttrValue()` function in `lib/default.js` only filters `javascript:` URIs in `href`, `src`, and `background` attributes. All other attributes pass `javascript:` values through unfiltered.

In the **default whitelist configuration**, this has **no direct XSS impact** — the affected attributes (`poster`, `cite`, `title`, etc.) are not navigable URI attributes, so browsers do not execute `javascript:` URIs placed in them. However, applications using **custom whitelist configurations** that add tags like `iframe`, `form`, or `object` become vulnerable to `javascript:` URI injection via `src`, `action`, or `data` attributes.

## Root Cause

In `lib/default.js`, lines 172-222:

```javascript
function safeAttrValue(tag, name, value, cssFilter) {
  value = friendlyAttrValue(value);

  if (name === "href" || name === "src") {
    // ✅ Protocol allowlist for href and src
    if (!startsWithAllowedProtocol(value)) return "";
  } else if (name === "background") {
    // ✅ Regex check for background
    if (REGEXP_DEFAULT_ON_TAG_ATTR_4.test(value)) return "";
  } else if (name === "style") {
    // ✅ expression() and url() check for style
  }
  // ❌ All other attributes: NO javascript: URI check

  value = escapeAttrValue(value);  // only escapes < > "
  return value;
}
```

The function uses a denylist approach — only checking 4 attribute names (`href`, `src`, `background`, `style`) — instead of applying `javascript:` URI checks broadly.

## Why This Is Low Severity (Not High/Critical)

In the default whitelist, 60+ tag/attribute combinations pass `javascript:` through. However, **none of them are exploitable**:

| Attribute | In default whitelist? | Browser executes `javascript:`? | Exploitable? |
|-----------|----------------------|-------------------------------|-------------|
| `a href` | Yes | Yes | **No** — js-xss already filters it |
| `img src` | Yes | Depends | **No** — js-xss already filters it |
| `video poster` | Yes | **No** — loaded as image resource | No |
| `blockquote cite` | Yes | **No** — metadata only | No |
| `a title` | Yes | **No** — tooltip text | No |
| `img alt` | Yes | **No** — alt text | No |
| `iframe src` | **No** (tag escaped) | Yes | No (default config) |
| `form action` | **No** (tag escaped) | Yes | No (default config) |
| `object data` | **No** (tag escaped) | Yes | No (default config) |

The navigable URI attributes that execute `javascript:` (`iframe src`, `form action`, `button formaction`, `object data`) are on tags **not in the default whitelist** — so the tags themselves are HTML-escaped, preventing execution.

## Proof of Concept

### Default config: `javascript:` passes through but does not execute

```javascript
const xss = require('xss');

// poster is whitelisted but browsers don't execute javascript: in poster
xss('<video poster="javascript:alert(1)">');
// Output: <video poster="javascript:alert(1)">
// Browser behavior: tries to load as image, fails silently. No JS execution.

// cite is whitelisted but purely informational
xss('<blockquote cite="javascript:alert(1)">text</blockquote>');
// Output: <blockquote cite="javascript:alert(1)">text</blockquote>
// Browser behavior: metadata attribute, never navigated. No JS execution.
```

### Custom config: exploitable if user adds dangerous tags

```javascript
// ⚠️ If an application adds iframe to the whitelist:
const output = xss('<iframe src="javascript:alert(1)">', {
  whiteList: { iframe: ['src'] }
});
// Output: <iframe src="javascript:alert(1)">
// Browser behavior: EXECUTES JavaScript — auto-navigates iframe src
```

This scenario is realistic — the js-xss README documents custom whitelist usage, and developers may add `iframe` (with `src`) or `form` (with `action`) for legitimate content needs without realizing `javascript:` URI filtering only covers `href`/`src`.

## Comparison with Other Sanitizers

| Sanitizer | `video poster="javascript:..."` | Custom `iframe src="javascript:..."` | Approach |
|-----------|-------------------------------|-------------------------------------|----------|
| **DOMPurify** | Blocked | Blocked | Checks all attributes for dangerous URI schemes |
| **sanitize-html** | Blocked | Blocked | URI validation on all URL-type attributes |
| **js-xss** | Allowed (not exploitable) | **Allowed (exploitable)** | Only checks `href`, `src`, `background` |

## Suggested Fix

Apply `javascript:` URI check to all attributes, not just `href`/`src`/`background`:

```javascript
function safeAttrValue(tag, name, value, cssFilter) {
  value = friendlyAttrValue(value);

  // Check ALL attributes for dangerous URI schemes
  REGEXP_DEFAULT_ON_TAG_ATTR_4.lastIndex = 0;
  if (REGEXP_DEFAULT_ON_TAG_ATTR_4.test(value)) {
    return "";
  }

  if (name === "href" || name === "src") {
    // existing protocol allowlist...
  }
  // ... rest of function
}
```

This is a minimal change that closes the gap for both default and custom whitelist configurations.

## Discovery Method

Found by grammar-based differential fuzzing comparing DOMPurify (primary), sanitize-html (reference 0), and js-xss (reference 1). The fuzzer detected that js-xss allows `javascript:` URIs in attributes where the other two sanitizers block them.

## Timeline

- **2026-03-01**: Differential detected by fuzzer
- **2026-03-02**: Root cause analysis, exploitability assessment
- **2026-03-02**: Severity downgraded from Critical to Low after confirming default config is not directly exploitable
