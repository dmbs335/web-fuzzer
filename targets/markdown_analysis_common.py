"""Shared HTML analysis for markdown rendered output."""
import re

_JS_URI_RE = re.compile(r'^\s*javascript\s*:', re.I)
_DATA_HTML_RE = re.compile(r'^\s*data\s*:\s*text/html', re.I)
_DATA_URI_RE = re.compile(r'^\s*data\s*:', re.I)
_VBSCRIPT_RE = re.compile(r'^\s*vbscript\s*:', re.I)
_EVENT_HANDLER_RE = re.compile(r'\bon[a-z]+\s*=', re.I)
_EVENT_HANDLER_TYPES_RE = re.compile(r'\bon([a-z]+)\s*=', re.I)
_TAG_RE = re.compile(r'<([a-z][a-z0-9]*)', re.I)
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']*)["\']', re.I)
_IMG_SRC_RE = re.compile(r'<img[^>]+src\s*=\s*["\']([^"\']*)["\']', re.I)
_AUTOLINK_RE = re.compile(r'<a\s[^>]*href\s*=\s*["\'](https?://[^"\']*)["\'][^>]*>\1</a>', re.I)
_HTML_BLOCK_RE = re.compile(r'<(div|section|article|header|footer|nav|aside|main|details|summary|figure)\b', re.I)

_RAW_HTML_TAGS = frozenset({"div", "iframe", "script", "style", "object", "embed", "form"})

_TAG_CAT_MAP = {
    "script": "exec", "style": "exec", "link": "exec",
    "iframe": "embed", "object": "embed", "embed": "embed", "applet": "embed",
    "form": "form", "input": "form", "button": "form", "textarea": "form", "select": "form",
    "a": "link",
    "img": "media", "video": "media", "audio": "media", "source": "media",
    "svg": "foreign", "math": "foreign",
    "div": "block", "span": "inline", "p": "block", "table": "block",
    "base": "meta", "meta": "meta",
}

def analyze_rendered_html(html: str) -> dict:
    if not html or not html.strip():
        return {
            "html": "",
            "has_raw_html": False,
            "has_script": False,
            "has_event_handler": False,
            "has_javascript_uri": False,
            "has_data_uri": False,
            "has_iframe": False,
            "has_link": False,
            "link_hrefs": [],
            "has_image": False,
            "image_srcs": [],
            "autolinks_found": 0,
            "html_blocks_preserved": 0,
            "link_count": 0,
            "image_count": 0,
            "element_set_hash": "",
            "dangerous_link_count": 0,
            "dangerous_scheme_set": "",
            "event_handler_set": "",
            "tag_category_set": "",
            "link_context_set": "",
            "has_form": False,
            "has_object_embed": False,
            "has_foreign_ns": False,
            "has_base_meta": False,
            "empty_output": True,
            "error": None,
        }

    tags = {m.group(1).lower() for m in _TAG_RE.finditer(html)}
    hrefs = [m.group(1) for m in _HREF_RE.finditer(html)]
    img_srcs = [m.group(1) for m in _IMG_SRC_RE.finditer(html)]
    autolinks = len(_AUTOLINK_RE.findall(html))
    html_blocks = len(_HTML_BLOCK_RE.findall(html))

    all_uris = hrefs + img_srcs
    has_js_uri = any(_JS_URI_RE.match(h) for h in all_uris)
    has_data_uri = any(_DATA_HTML_RE.match(h) for h in all_uris)

    # ── Semantic signals (break boolean ceiling) ──
    dangerous_schemes: set[str] = set()
    dangerous_link_count = 0
    for u in all_uris:
        lower = u.strip().lower()
        if _JS_URI_RE.match(lower):
            dangerous_schemes.add("javascript"); dangerous_link_count += 1
        elif _DATA_HTML_RE.match(lower):
            dangerous_schemes.add("data_html"); dangerous_link_count += 1
        elif _DATA_URI_RE.match(lower):
            dangerous_schemes.add("data"); dangerous_link_count += 1
        elif _VBSCRIPT_RE.match(lower):
            dangerous_schemes.add("vbscript"); dangerous_link_count += 1

    event_handler_types = {m.group(1).lower() for m in _EVENT_HANDLER_TYPES_RE.finditer(html)}
    tag_cats = {_TAG_CAT_MAP[t] for t in tags if t in _TAG_CAT_MAP}

    link_contexts: set[str] = set()
    if re.search(r'<a\s[^>]*href', html, re.I): link_contexts.add("a_href")
    if re.search(r'<img\s[^>]*src', html, re.I): link_contexts.add("img_src")
    if re.search(r'<iframe\s[^>]*src', html, re.I): link_contexts.add("iframe_src")
    if autolinks > 0: link_contexts.add("autolink")
    if re.search(r'<form\s[^>]*action', html, re.I): link_contexts.add("form_action")
    if re.search(r'<object\s[^>]*data', html, re.I): link_contexts.add("object_data")

    return {
        "html": html[:2000],
        "has_raw_html": bool(tags & _RAW_HTML_TAGS),
        "has_script": "script" in tags,
        "has_event_handler": bool(_EVENT_HANDLER_RE.search(html)),
        "has_javascript_uri": has_js_uri,
        "has_data_uri": has_data_uri,
        "has_iframe": "iframe" in tags,
        "has_link": len(hrefs) > 0,
        "link_hrefs": hrefs[:20],
        "has_image": len(img_srcs) > 0,
        "image_srcs": img_srcs[:20],
        "autolinks_found": autolinks,
        "html_blocks_preserved": html_blocks,
        "link_count": len(hrefs),
        "image_count": len(img_srcs),
        "element_set_hash": ",".join(sorted(tags)),
        # Semantic signals
        "dangerous_link_count": dangerous_link_count,
        "dangerous_scheme_set": ",".join(sorted(dangerous_schemes)),
        "event_handler_set": ",".join(sorted(event_handler_types)),
        "tag_category_set": ",".join(sorted(tag_cats)),
        "link_context_set": ",".join(sorted(link_contexts)),
        "has_form": "form" in tags or "input" in tags,
        "has_object_embed": bool(tags & {"object", "embed", "applet"}),
        "has_foreign_ns": bool(tags & {"svg", "math"}),
        "has_base_meta": bool(tags & {"base", "meta"}),
        "empty_output": False,
        "error": None,
    }
