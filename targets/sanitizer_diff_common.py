"""Shared analysis utilities for sanitizer differential fuzzing targets.

Extracts security-relevant signals from sanitized HTML output
and produces a standardized JSON schema for cross-library comparison.

Python port of sanitizer_diff_common.js — uses html.parser (stdlib).
"""
from __future__ import annotations

import json
import re
from html.parser import HTMLParser

EVENT_HANDLER_RE = re.compile(r"^on[a-z]", re.IGNORECASE)
JS_URI_RE = re.compile(r"^\s*javascript\s*:", re.IGNORECASE)
DATA_HTML_RE = re.compile(r"^\s*data\s*:\s*text/html", re.IGNORECASE)

URI_ATTRS = frozenset({"href", "src", "action", "formaction", "poster", "data", "codebase"})


class _SignalCollector(HTMLParser):
    """Walk HTML and collect security signals."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.elements: set[str] = set()
        self.attributes: set[str] = set()
        self.has_script = False
        self.has_event_handler = False
        self.has_javascript_uri = False
        self.has_data_uri = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        self.elements.add(tag)
        if tag == "script":
            self.has_script = True
        for name, value in attrs:
            name = name.lower()
            self.attributes.add(name)
            if EVENT_HANDLER_RE.match(name):
                self.has_event_handler = True
            if name in URI_ATTRS and value:
                if JS_URI_RE.match(value):
                    self.has_javascript_uri = True
                if DATA_HTML_RE.match(value):
                    self.has_data_uri = True

    handle_startendtag = handle_starttag


def analyze_html(html: str) -> dict:
    """Analyze sanitized HTML and return security signals."""
    if not html or not html.strip():
        return {
            "elements": [],
            "attributes": [],
            "has_script": False,
            "has_event_handler": False,
            "has_javascript_uri": False,
            "has_data_uri": False,
            "has_svg": False,
            "has_math": False,
            "has_style": False,
            "has_form": False,
            "has_base": False,
            "has_iframe": False,
            "has_object_embed": False,
            "has_noscript": False,
        }

    collector = _SignalCollector()
    try:
        collector.feed(html)
    except Exception:
        pass

    elems = collector.elements
    return {
        "elements": sorted(elems),
        "attributes": sorted(collector.attributes),
        "has_script": collector.has_script,
        "has_event_handler": collector.has_event_handler,
        "has_javascript_uri": collector.has_javascript_uri,
        "has_data_uri": collector.has_data_uri,
        "has_svg": "svg" in elems,
        "has_math": "math" in elems,
        "has_style": "style" in elems,
        "has_form": "form" in elems,
        "has_base": "base" in elems,
        "has_iframe": "iframe" in elems,
        "has_object_embed": bool(elems & {"object", "embed", "applet"}),
        "has_noscript": "noscript" in elems,
    }


def build_result(sanitized: str) -> dict:
    """Build the standardized JSON output from sanitized HTML."""
    analysis = analyze_html(sanitized)
    return {
        "sanitized": sanitized[:2000],
        "elements_kept": analysis["elements"],
        "attributes_kept": analysis["attributes"],
        "has_script": analysis["has_script"],
        "has_event_handler": analysis["has_event_handler"],
        "has_javascript_uri": analysis["has_javascript_uri"],
        "has_data_uri": analysis["has_data_uri"],
        "has_svg": analysis["has_svg"],
        "has_math": analysis["has_math"],
        "has_style": analysis["has_style"],
        "has_form": analysis["has_form"],
        "has_base": analysis["has_base"],
        "has_iframe": analysis["has_iframe"],
        "has_object_embed": analysis["has_object_embed"],
        "has_noscript": analysis["has_noscript"],
        "empty_output": not sanitized or not sanitized.strip(),
        "error": None,
    }
