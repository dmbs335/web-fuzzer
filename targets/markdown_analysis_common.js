"use strict";

const JS_URI_RE = /^\s*javascript\s*:/i;
const DATA_HTML_RE = /^\s*data\s*:\s*text\/html/i;
const DATA_URI_RE = /^\s*data\s*:/i;
const VBSCRIPT_RE = /^\s*vbscript\s*:/i;
const EVENT_HANDLER_RE = /\bon([a-z]+)\s*=/gi;
const EVENT_HANDLER_BOOL_RE = /\bon[a-z]+\s*=/i;

function analyzeRenderedHtml(html) {
  if (!html || !html.trim()) {
    return {
      html: "",
      has_raw_html: false,
      has_script: false,
      has_event_handler: false,
      has_javascript_uri: false,
      has_data_uri: false,
      has_iframe: false,
      has_link: false,
      link_hrefs: [],
      has_image: false,
      image_srcs: [],
      autolinks_found: 0,
      html_blocks_preserved: 0,
      link_count: 0,
      image_count: 0,
      element_set_hash: "",
      dangerous_link_count: 0,
      dangerous_scheme_set: "",
      event_handler_set: "",
      tag_category_set: "",
      link_context_set: "",
      has_form: false,
      has_object_embed: false,
      has_foreign_ns: false,
      has_base_meta: false,
      empty_output: true,
      error: null,
    };
  }

  // Use regex-based analysis (markdown output is relatively simple HTML)
  const tagRe = /<([a-z][a-z0-9]*)/gi;
  const tags = new Set();
  let m;
  while ((m = tagRe.exec(html)) !== null) tags.add(m[1].toLowerCase());

  // Extract link hrefs
  const hrefRe = /href\s*=\s*["']([^"']*)["']/gi;
  const hrefs = [];
  while ((m = hrefRe.exec(html)) !== null) hrefs.push(m[1]);

  // Extract image srcs
  const srcRe = /<img[^>]+src\s*=\s*["']([^"']*)["']/gi;
  const imgSrcs = [];
  while ((m = srcRe.exec(html)) !== null) imgSrcs.push(m[1]);

  // Autolinks: count <a> tags that were likely auto-generated
  const autolinkRe = /<a\s[^>]*href\s*=\s*["'](https?:\/\/[^"']*)["'][^>]*>\1<\/a>/gi;
  let autolinks = 0;
  while (autolinkRe.exec(html) !== null) autolinks++;

  // HTML blocks preserved (non-markdown-generated HTML like <div>, <section>, <table> in output)
  const htmlBlockRe = /<(div|section|article|header|footer|nav|aside|main|details|summary|figure)\b/gi;
  let htmlBlocks = 0;
  while (htmlBlockRe.exec(html) !== null) htmlBlocks++;

  const allUris = hrefs.concat(imgSrcs);
  const hasJsUri = allUris.some(h => JS_URI_RE.test(h));
  const hasDataUri = allUris.some(h => DATA_HTML_RE.test(h));

  // ── Semantic signals (break boolean ceiling) ──

  // Dangerous URI scheme classification per-link
  const dangerousSchemes = new Set();
  let dangerousLinkCount = 0;
  for (const u of allUris) {
    const lower = u.trim().toLowerCase();
    if (JS_URI_RE.test(lower)) { dangerousSchemes.add("javascript"); dangerousLinkCount++; }
    else if (DATA_HTML_RE.test(lower)) { dangerousSchemes.add("data_html"); dangerousLinkCount++; }
    else if (DATA_URI_RE.test(lower)) { dangerousSchemes.add("data"); dangerousLinkCount++; }
    else if (VBSCRIPT_RE.test(lower)) { dangerousSchemes.add("vbscript"); dangerousLinkCount++; }
  }

  // Event handler type classification
  const eventHandlerTypes = new Set();
  EVENT_HANDLER_RE.lastIndex = 0;
  let ehm;
  while ((ehm = EVENT_HANDLER_RE.exec(html)) !== null) {
    eventHandlerTypes.add(ehm[1].toLowerCase());
  }

  // HTML tag security categories
  const tagCats = new Set();
  const _CAT_MAP = {
    script: "exec", style: "exec", link: "exec",
    iframe: "embed", object: "embed", embed: "embed", applet: "embed",
    form: "form", input: "form", button: "form", textarea: "form", select: "form",
    a: "link",
    img: "media", video: "media", audio: "media", source: "media",
    svg: "foreign", math: "foreign",
    div: "block", span: "inline", p: "block", table: "block",
    base: "meta", meta: "meta",
  };
  for (const tag of tags) {
    if (_CAT_MAP[tag]) tagCats.add(_CAT_MAP[tag]);
  }

  // Link context detection
  const linkContexts = new Set();
  if (/<a\s[^>]*href/i.test(html)) linkContexts.add("a_href");
  if (/<img\s[^>]*src/i.test(html)) linkContexts.add("img_src");
  if (/<iframe\s[^>]*src/i.test(html)) linkContexts.add("iframe_src");
  if (autolinks > 0) linkContexts.add("autolink");
  if (/<form\s[^>]*action/i.test(html)) linkContexts.add("form_action");
  if (/<object\s[^>]*data/i.test(html)) linkContexts.add("object_data");

  return {
    html: html.substring(0, 2000),
    has_raw_html: tags.has("div") || tags.has("iframe") || tags.has("script") || tags.has("style") || tags.has("object") || tags.has("embed") || tags.has("form"),
    has_script: tags.has("script"),
    has_event_handler: EVENT_HANDLER_BOOL_RE.test(html),
    has_javascript_uri: hasJsUri,
    has_data_uri: hasDataUri,
    has_iframe: tags.has("iframe"),
    has_link: hrefs.length > 0,
    link_hrefs: hrefs.slice(0, 20),
    has_image: imgSrcs.length > 0,
    image_srcs: imgSrcs.slice(0, 20),
    autolinks_found: autolinks,
    html_blocks_preserved: htmlBlocks,
    link_count: hrefs.length,
    image_count: imgSrcs.length,
    element_set_hash: [...tags].sort().join(","),
    // Semantic signals
    dangerous_link_count: dangerousLinkCount,
    dangerous_scheme_set: [...dangerousSchemes].sort().join(","),
    event_handler_set: [...eventHandlerTypes].sort().join(","),
    tag_category_set: [...tagCats].sort().join(","),
    link_context_set: [...linkContexts].sort().join(","),
    has_form: tags.has("form") || tags.has("input"),
    has_object_embed: tags.has("object") || tags.has("embed") || tags.has("applet"),
    has_foreign_ns: tags.has("svg") || tags.has("math"),
    has_base_meta: tags.has("base") || tags.has("meta"),
    empty_output: false,
    error: null,
  };
}

module.exports = { analyzeRenderedHtml };
