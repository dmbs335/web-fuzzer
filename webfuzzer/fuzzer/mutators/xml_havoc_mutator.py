"""XML-structure-aware havoc mutator for SAML and XML-DSig inputs.

Constrains AFL-style byte mutations to XML-safe zones: text content
and attribute values.  Never mutates structural bytes (<, >, /, =, "
in tags), preserving well-formedness so targets don't reject at the
XML parse boundary.

Falls back to standard havoc if the input doesn't look like XML.

Strategies applied within safe zones:
  - Byte flip / set / arithmetic (ops 0-5 from havoc)
  - Interesting values (ops 6-8)
  - Block delete / insert / overwrite within zones
  - Cross-zone splice (copy text from one zone to another)
  - XML-semantic injections (comments, PIs, CDATA, entities)
"""

from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

# ── Safe zone detection ──────────────────────────────────────────

# Matches attribute values: name="value" or name='value'
_ATTR_VAL_RE = re.compile(rb"""(\w[\w:\-.]*)(\s*=\s*)(["'])(.+?)\3""", re.DOTALL)

# Matches text content between tags: >text<
_TEXT_RE = re.compile(rb">([^<]+)<")

# Quick XML sniff: starts with < and has at least one closing >
_XML_SNIFF = re.compile(rb"^\s*<")


def _find_safe_zones(data: bytes) -> list[tuple[int, int]]:
    """Return (start, end) byte ranges that are safe to mutate.

    Safe zones are:
      - Attribute values (between quotes)
      - Text content (between > and <)
    """
    zones: list[tuple[int, int]] = []

    # Attribute values
    for m in _ATTR_VAL_RE.finditer(data):
        # Group 4 is the value content (between quotes)
        start = m.start(4)
        end = m.end(4)
        if end > start:
            zones.append((start, end))

    # Text content
    for m in _TEXT_RE.finditer(data):
        start = m.start(1)
        end = m.end(1)
        # Skip whitespace-only text nodes
        if data[start:end].strip():
            zones.append((start, end))

    # Sort by start position and merge overlapping
    zones.sort()
    merged: list[tuple[int, int]] = []
    for s, e in zones:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], e))
        else:
            merged.append((s, e))

    return merged


# ── XML-semantic injection payloads ──────────────────────────────

_COMMENT_PAYLOADS = [
    b"<!---->",
    b"<!-- -->",
    b"<!--\x00-->",
    b"<!----->",
    b"<!-- -- -->",
]

_PI_PAYLOADS = [
    b"<?xml version='1.0'?>",
    b"<?xsl:stylesheet?>",
    b"<?pi ?>",
]

_CDATA_PAYLOADS = [
    b"<![CDATA[]]>",
    b"<![CDATA[test]]>",
    b"<![CDATA[<script>]]>",
]

_ENTITY_PAYLOADS = [
    b"&#x0;",
    b"&#0;",
    b"&amp;",
    b"&lt;",
    b"&#x61;&#x64;&#x6d;&#x69;&#x6e;",  # "admin" in hex entities
    b"&#97;&#100;&#109;&#105;&#110;",      # "admin" in decimal entities
]

_NAMESPACE_INJECTIONS = [
    b' xmlns="urn:oasis:names:tc:SAML:1.0:assertion"',
    b' xmlns:evil="http://evil.com"',
    b' xmlns=""',
    b' xmlns:saml="http://www.w3.org/2000/09/xmldsig#"',
]

# Interesting text values for SAML context
_INTERESTING_TEXT = [
    b"admin",
    b"admin@evil.com",
    b"*",
    b"admin\x00@victim.com",
    b"admin<!---->@evil.com",
    b"",
    b" ",
    b"\t",
    b"none",
    b"None",
    b"NONE",
]

# AFL interesting byte values (reused from havoc)
_INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]


class XmlHavocMutator:
    """XML-structure-aware havoc mutator.

    Identifies safe zones (text content + attribute values) in XML and
    constrains byte-level mutations to those zones.  Also injects
    XML-semantic payloads (comments, PIs, CDATA, entities) at safe
    positions within text nodes.

    Falls back to standard byte-level havoc on non-XML inputs.
    """

    name = "xml_havoc"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = bytearray(inp.data)
        if not data:
            data = bytearray(b"<root/>")

        # Check if input looks like XML
        if not _XML_SNIFF.match(bytes(data)):
            # Non-XML: fall back to zone-free byte mutation
            return self._fallback_mutate(data, inp, corpus)

        zones = _find_safe_zones(bytes(data))
        if not zones:
            # No safe zones found: try XML-semantic injection only
            data = self._inject_semantic(data)
            return Input(
                data=bytes(data),
                metadata={**inp.metadata, "mutator": self.name},
            )

        # Number of stacked mutations: 2^(1 + rng(4)) = 2..32
        # Fewer than standard havoc since each op is more targeted
        num_ops = 1 << (1 + self.rng.randint(0, 4))

        for _ in range(num_ops):
            op = self.rng.randint(0, 12)
            data = self._apply_zone_op(op, data, zones, corpus)
            # Recompute zones after structural changes
            if op >= 7:
                zones = _find_safe_zones(bytes(data))
                if not zones:
                    break

        return Input(
            data=bytes(data),
            metadata={**inp.metadata, "mutator": self.name},
        )

    def _apply_zone_op(
        self, op: int, data: bytearray,
        zones: list[tuple[int, int]], corpus: list[Seed],
    ) -> bytearray:
        """Apply a mutation operation constrained to safe zones."""
        if not zones:
            return data

        # Pick a random zone
        zs, ze = self.rng.choice(zones)
        # Clamp to actual data length (zones may be stale after resize)
        zs = min(zs, len(data))
        ze = min(ze, len(data))
        zone_len = ze - zs
        if zone_len <= 0:
            return data

        if op == 0:  # bit flip within zone
            pos = zs + self.rng.randint(0, zone_len - 1)
            bit = self.rng.randint(0, 7)
            data[pos] ^= 1 << bit

        elif op == 1:  # byte set random within zone
            pos = zs + self.rng.randint(0, zone_len - 1)
            # Avoid setting to structural XML bytes
            val = self.rng.randint(0, 255)
            while val in (ord("<"), ord(">"), ord("/")):
                val = self.rng.randint(0, 255)
            data[pos] = val

        elif op == 2:  # arithmetic 8-bit within zone
            pos = zs + self.rng.randint(0, zone_len - 1)
            delta = self.rng.randint(1, 35)
            if self.rng.random() < 0.5:
                data[pos] = (data[pos] + delta) & 0xFF
            else:
                data[pos] = (data[pos] - delta) & 0xFF

        elif op == 3:  # interesting byte within zone
            pos = zs + self.rng.randint(0, zone_len - 1)
            data[pos] = self.rng.choice(_INTERESTING_8) & 0xFF

        elif op == 4:  # replace zone with interesting text
            replacement = self.rng.choice(_INTERESTING_TEXT)
            data[zs:ze] = replacement

        elif op == 5:  # inject entity within zone
            entity = self.rng.choice(_ENTITY_PAYLOADS)
            pos = zs + self.rng.randint(0, zone_len)
            data[pos:pos] = entity

        elif op == 6:  # inject comment/PI within text zone
            if self.rng.random() < 0.5:
                payload = self.rng.choice(_COMMENT_PAYLOADS)
            else:
                payload = self.rng.choice(_PI_PAYLOADS)
            pos = zs + self.rng.randint(0, zone_len)
            data[pos:pos] = payload

        elif op == 7:  # inject CDATA within text zone
            payload = self.rng.choice(_CDATA_PAYLOADS)
            pos = zs + self.rng.randint(0, zone_len)
            data[pos:pos] = payload

        elif op == 8:  # delete partial zone content
            if zone_len > 2:
                del_len = self.rng.randint(1, min(zone_len // 2, 16))
                pos = zs + self.rng.randint(0, zone_len - del_len)
                del data[pos:pos + del_len]

        elif op == 9:  # cross-zone splice
            if len(zones) >= 2:
                src_zone = self.rng.choice(zones)
                src_s, src_e = src_zone
                if src_e > src_s:
                    splice_len = min(src_e - src_s, 32)
                    src_pos = src_s + self.rng.randint(0, src_e - src_s - splice_len)
                    snippet = bytes(data[src_pos:src_pos + splice_len])
                    dst_pos = zs + self.rng.randint(0, zone_len)
                    data[dst_pos:dst_pos] = snippet

        elif op == 10:  # inject namespace attribute on nearest tag
            injection = self.rng.choice(_NAMESPACE_INJECTIONS)
            # Find the opening tag that contains this zone
            tag_end = data.rfind(b">", 0, zs)
            if tag_end > 0:
                # Insert before the >
                data[tag_end:tag_end] = injection

        elif op == 11:  # duplicate a zone's content after itself
            content = bytes(data[zs:ze])
            data[ze:ze] = content

        elif op == 12:  # splice from corpus (within zone)
            if corpus:
                other = self.rng.choice(corpus)
                other_data = other.input.data
                if other_data:
                    other_zones = _find_safe_zones(other_data)
                    if other_zones:
                        os_, oe = self.rng.choice(other_zones)
                        snippet = other_data[os_:oe]
                        data[zs:ze] = snippet

        return data

    def _inject_semantic(self, data: bytearray) -> bytearray:
        """Inject XML-semantic payload at a random position between tags."""
        positions = [m.start() for m in re.finditer(rb"><", bytes(data))]
        if not positions:
            return data
        pos = self.rng.choice(positions) + 1  # after >
        payloads = _COMMENT_PAYLOADS + _PI_PAYLOADS + _CDATA_PAYLOADS
        payload = self.rng.choice(payloads)
        data[pos:pos] = payload
        return data

    def _fallback_mutate(
        self, data: bytearray, inp: Input, corpus: list[Seed],
    ) -> Input:
        """Standard byte-level havoc for non-XML inputs."""
        num_ops = 1 << (1 + self.rng.randint(0, 4))
        for _ in range(num_ops):
            if not data:
                break
            pos = self.rng.randint(0, len(data) - 1)
            op = self.rng.randint(0, 3)
            if op == 0:
                data[pos] ^= 1 << self.rng.randint(0, 7)
            elif op == 1:
                data[pos] = self.rng.randint(0, 255)
            elif op == 2:
                delta = self.rng.randint(1, 35)
                data[pos] = (data[pos] + delta) & 0xFF
            elif op == 3:
                data[pos] = self.rng.choice(_INTERESTING_8) & 0xFF

        return Input(
            data=bytes(data),
            metadata={**inp.metadata, "mutator": self.name},
        )
