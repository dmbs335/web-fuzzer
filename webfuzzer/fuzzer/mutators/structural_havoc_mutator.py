"""Web-structure-aware havoc mutator.

Replaces blind AFL-style byte mutations with mutations that understand
HTML tag boundaries, attribute syntax, encoding schemes, and delimiter
semantics. Produces mutations that survive HTML parsing while exploring
edge cases in parser behavior.

Strategies:
  1. encoding_transform       — HTML entity, percent, Unicode transforms
  2. tag_boundary_mutate      — mutate within tag boundaries
  3. namespace_attr_inject    — inject xmlns, encoding attributes
  4. quote_delimiter_mutate   — switch/break attribute quote types
  5. whitespace_inject        — null bytes, VT, FF, BOM between tag parts
  6. attribute_boundary_break — break attribute boundaries
  7. content_type_confuse     — inject charset manipulation
  8. pi_and_cdata_inject      — processing instructions and CDATA
"""

from __future__ import annotations

import random
import re
import unicodedata
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

# ── Regex patterns ────────────────────────────────────────────────

TAG_RE = re.compile(rb"</?[a-zA-Z][^>]*/??>")
ATTR_RE = re.compile(rb"""(\w+)\s*=\s*(["'])([^"']*?)\2""")
OPEN_TAG_RE = re.compile(rb"<([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>")

# ── Namespace attributes ─────────────────────────────────────────

NAMESPACE_ATTRS = [
    b' xmlns="http://www.w3.org/1999/xhtml"',
    b' xmlns="http://www.w3.org/2000/svg"',
    b' xmlns="http://www.w3.org/1998/Math/MathML"',
    b' xmlns:xlink="http://www.w3.org/1999/xlink"',
    b' xml:lang="en"',
    b' xml:space="preserve"',
]

# ── Interesting whitespace and control characters ─────────────────

INTERESTING_WHITESPACE = [
    b"\x00",              # null byte
    b"\x09",              # horizontal tab
    b"\x0a",              # line feed
    b"\x0d",              # carriage return
    b"\x0c",              # form feed
    b"\x0b",              # vertical tab (NOT HTML5 whitespace)
    b"\xc2\xa0",          # non-breaking space (UTF-8)
    b"\xe2\x80\x83",      # em space
    b"\xe2\x80\x8b",      # zero-width space
    b"\xef\xbb\xbf",      # BOM
    b"\xe2\x80\xae",      # right-to-left override
    b"\xc2\x85",          # NEL (next line)
]

# ── Injected attributes for tag mutation ──────────────────────────

INJECTED_ATTRS = [
    b" id=x",
    b" name=x",
    b" class=x",
    b" style=x",
    b" tabindex=0",
    b" autofocus",
    b" contenteditable",
    b" draggable=true",
    b" hidden",
    b" is=x",
    b" slot=x",
]

# ── Charset confusion payloads ────────────────────────────────────

CHARSET_INJECTIONS = [
    b'<meta charset="UTF-7">',
    b'<meta charset="ISO-2022-JP">',
    b'<meta charset="windows-1252">',
    b'<meta http-equiv="Content-Type" content="text/html; charset=UTF-7">',
    b'<?xml version="1.0" encoding="UTF-7"?>',
    b'<?xml version="1.0" encoding="ISO-2022-JP"?>',
]

# ── Processing instruction / CDATA payloads ───────────────────────

PI_CDATA_INJECTIONS = [
    b'<?xml version="1.0"?>',
    b"<![CDATA[",
    b"]]>",
    b'<?import namespace="svg"?>',
    b"<![CDATA[<script>alert(1)</script>]]>",
    b"<![CDATA[<img src=x onerror=alert(1)>]]>",
    b"<?xml-stylesheet type=\"text/xsl\" href=\"data:,\">",
]

# ── Encoding transform helpers ────────────────────────────────────

HTML_NAMED_ENTITIES = {
    "<": "&lt;", ">": "&gt;", "&": "&amp;",
    '"': "&quot;", "'": "&#39;",
}

UNICODE_CONFUSABLES = {
    "<": "\uff1c",  # fullwidth <
    ">": "\uff1e",  # fullwidth >
    "/": "\u2215",  # division slash
    "'": "\u2019",  # right single quotation
    '"': "\u201d",  # right double quotation
}


class StructuralHavocMutator:
    """Web-structure-aware byte mutation.

    Understands HTML tag boundaries, attribute syntax, and encoding
    schemes. Produces mutations that are more likely to survive HTML
    parsing than blind byte flips while still exploring edge cases.
    """

    name = "structural"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self._strategies = [
            self._encoding_transform,
            self._tag_boundary_mutate,
            self._namespace_attr_inject,
            self._quote_delimiter_mutate,
            self._whitespace_inject,
            self._attribute_boundary_break,
            self._content_type_confuse,
            self._pi_and_cdata_inject,
        ]
        self._weights = [15, 20, 12, 15, 10, 10, 8, 10]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = bytearray(inp.data)
        if not data:
            data = bytearray(b"<div>test</div>")

        # Apply 1-3 stacked strategies
        num_ops = self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        for _ in range(num_ops):
            strategy = self.rng.choices(
                self._strategies, weights=self._weights, k=1
            )[0]
            data = strategy(data)

        return Input(
            data=bytes(data),
            metadata={**inp.metadata, "mutator": self.name},
        )

    # ── Strategy implementations ─────────────────────────────────

    def _encoding_transform(self, data: bytearray) -> bytearray:
        """Apply encoding transforms to a portion of the input."""
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return data

        if len(text) < 2:
            return data

        # Select a substring to transform
        start = self.rng.randint(0, len(text) - 1)
        end = min(start + self.rng.randint(1, 20), len(text))
        fragment = text[start:end]

        transform = self.rng.choice([
            "html_entity",
            "numeric_entity",
            "hex_entity",
            "percent_encode",
            "unicode_confusable",
            "double_encode",
        ])

        transformed = self._apply_encoding(fragment, transform)
        result = text[:start] + transformed + text[end:]
        return bytearray(result.encode("utf-8", errors="replace"))

    def _apply_encoding(self, fragment: str, transform: str) -> str:
        if transform == "html_entity":
            return "".join(
                HTML_NAMED_ENTITIES.get(c, c) for c in fragment
            )
        if transform == "numeric_entity":
            return "".join(f"&#{ord(c)};" for c in fragment)
        if transform == "hex_entity":
            return "".join(f"&#x{ord(c):X};" for c in fragment)
        if transform == "percent_encode":
            return "".join(
                f"%{b:02X}" for b in fragment.encode("utf-8")
            )
        if transform == "unicode_confusable":
            return "".join(
                UNICODE_CONFUSABLES.get(c, c) for c in fragment
            )
        if transform == "double_encode":
            # First pass: entity encode
            first = "".join(
                HTML_NAMED_ENTITIES.get(c, c) for c in fragment
            )
            # Second pass: encode the ampersands
            return first.replace("&", "&amp;")
        return fragment

    def _tag_boundary_mutate(self, data: bytearray) -> bytearray:
        """Find HTML tags and mutate within their boundaries."""
        matches = list(TAG_RE.finditer(bytes(data)))
        if not matches:
            return data

        match = self.rng.choice(matches)
        tag = match.group(0)

        mutation = self.rng.choice([
            "case_swap",
            "add_attribute",
            "null_in_tag",
            "whitespace_in_tag",
            "duplicate_close",
            "add_slash",
        ])

        mutated_tag = self._mutate_tag(tag, mutation)
        return bytearray(
            bytes(data[: match.start()]) + mutated_tag + bytes(data[match.end() :])
        )

    def _mutate_tag(self, tag: bytes, mutation: str) -> bytes:
        if mutation == "case_swap":
            result = bytearray()
            for b in tag:
                if 0x41 <= b <= 0x5A:  # A-Z
                    result.append(b + 32 if self.rng.random() < 0.5 else b)
                elif 0x61 <= b <= 0x7A:  # a-z
                    result.append(b - 32 if self.rng.random() < 0.5 else b)
                else:
                    result.append(b)
            return bytes(result)

        if mutation == "add_attribute":
            attr = self.rng.choice(INJECTED_ATTRS)
            # Insert before closing >
            if tag.endswith(b"/>"):
                return tag[:-2] + attr + b"/>"
            if tag.endswith(b">"):
                return tag[:-1] + attr + b">"
            return tag + attr

        if mutation == "null_in_tag":
            pos = self.rng.randint(1, max(len(tag) - 2, 1))
            return tag[:pos] + b"\x00" + tag[pos:]

        if mutation == "whitespace_in_tag":
            ws = self.rng.choice(INTERESTING_WHITESPACE)
            pos = self.rng.randint(1, max(len(tag) - 2, 1))
            return tag[:pos] + ws + tag[pos:]

        if mutation == "duplicate_close":
            # Duplicate the tag's closing >
            return tag + b">"

        if mutation == "add_slash":
            # Add or remove self-closing slash
            if tag.endswith(b"/>"):
                return tag[:-2] + b">"
            if tag.endswith(b">"):
                return tag[:-1] + b"/>"
            return tag

        return tag

    def _namespace_attr_inject(self, data: bytearray) -> bytearray:
        """Inject namespace-related attributes into existing tags."""
        matches = list(OPEN_TAG_RE.finditer(bytes(data)))
        if not matches:
            return data

        match = self.rng.choice(matches)
        attr = self.rng.choice(NAMESPACE_ATTRS)
        insert_pos = match.end() - 1  # before closing >
        return bytearray(
            bytes(data[:insert_pos]) + attr + bytes(data[insert_pos:])
        )

    def _quote_delimiter_mutate(self, data: bytearray) -> bytearray:
        """Manipulate quote types and delimiters in attributes."""
        matches = list(ATTR_RE.finditer(bytes(data)))
        if not matches:
            return data

        match = self.rng.choice(matches)
        attr_name = match.group(1)
        quote = match.group(2)
        value = match.group(3)

        mutation = self.rng.choice([
            "swap_quote",
            "remove_quote",
            "backtick_quote",
            "missing_close",
            "embed_opposite",
        ])

        if mutation == "swap_quote":
            new_quote = b"'" if quote == b'"' else b'"'
            replacement = attr_name + b"=" + new_quote + value + new_quote
        elif mutation == "remove_quote":
            replacement = attr_name + b"=" + value
        elif mutation == "backtick_quote":
            replacement = attr_name + b"=`" + value + b"`"
        elif mutation == "missing_close":
            replacement = attr_name + b"=" + quote + value
        elif mutation == "embed_opposite":
            opp = b"'" if quote == b'"' else b'"'
            mid = len(value) // 2
            replacement = (
                attr_name + b"=" + quote
                + value[:mid] + opp + value[mid:]
                + quote
            )
        else:
            return data

        return bytearray(
            bytes(data[: match.start()])
            + replacement
            + bytes(data[match.end() :])
        )

    def _whitespace_inject(self, data: bytearray) -> bytearray:
        """Inject unusual whitespace/control characters between tag parts."""
        matches = list(TAG_RE.finditer(bytes(data)))
        if not matches:
            # Inject at random position
            ws = self.rng.choice(INTERESTING_WHITESPACE)
            pos = self.rng.randint(0, max(len(data) - 1, 0))
            return bytearray(bytes(data[:pos]) + ws + bytes(data[pos:]))

        match = self.rng.choice(matches)
        tag = match.group(0)
        ws = self.rng.choice(INTERESTING_WHITESPACE)

        # Inject whitespace at a tag-internal boundary
        pos = self.rng.randint(1, max(len(tag) - 2, 1))
        mutated = tag[:pos] + ws + tag[pos:]
        return bytearray(
            bytes(data[: match.start()]) + mutated + bytes(data[match.end() :])
        )

    def _attribute_boundary_break(self, data: bytearray) -> bytearray:
        """Break attribute boundaries to test parser error recovery."""
        matches = list(ATTR_RE.finditer(bytes(data)))
        if not matches:
            return data

        match = self.rng.choice(matches)
        attr_name = match.group(1)
        quote = match.group(2)
        value = match.group(3)

        mutation = self.rng.choice([
            "remove_close_quote",
            "inject_gt",
            "inject_lt",
            "double_equal",
        ])

        if mutation == "remove_close_quote":
            # Remove closing quote — value bleeds into next attribute
            replacement = attr_name + b"=" + quote + value
        elif mutation == "inject_gt":
            # Inject > inside value — premature tag close
            mid = max(len(value) // 2, 1)
            replacement = (
                attr_name + b"=" + quote
                + value[:mid] + b">" + value[mid:]
                + quote
            )
        elif mutation == "inject_lt":
            # Inject < inside value — nested tag start
            mid = max(len(value) // 2, 1)
            replacement = (
                attr_name + b"=" + quote
                + value[:mid] + b"<img src=x onerror=alert(1)>" + value[mid:]
                + quote
            )
        elif mutation == "double_equal":
            replacement = attr_name + b"==" + quote + value + quote
        else:
            return data

        return bytearray(
            bytes(data[: match.start()])
            + replacement
            + bytes(data[match.end() :])
        )

    def _content_type_confuse(self, data: bytearray) -> bytearray:
        """Inject charset/content-type manipulation."""
        injection = self.rng.choice(CHARSET_INJECTIONS)
        # Prepend charset manipulation
        return bytearray(injection + bytes(data))

    def _pi_and_cdata_inject(self, data: bytearray) -> bytearray:
        """Inject processing instructions and CDATA sections."""
        injection = self.rng.choice(PI_CDATA_INJECTIONS)
        pos = self.rng.randint(0, max(len(data) - 1, 0))
        return bytearray(
            bytes(data[:pos]) + injection + bytes(data[pos:])
        )
