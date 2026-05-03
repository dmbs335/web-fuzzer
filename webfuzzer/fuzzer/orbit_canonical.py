"""Orbit-canonical input normalization shared by runtime dedup and offline E6.

A *transform* is a pure function ``bytes -> bytes`` that applies one element
``g`` of the acting group ``G`` to an input. Two inputs ``x, y`` lie in the
same orbit iff ``y`` can be reached from ``x`` by a finite word in ``G``.

For dedup we don't need the full group action — we only need a deterministic
*canonical form* reachable by composing the transforms once. Two inputs with
the same canonical form are orbit-equivalent and should share a bug report.

Used by:
- ``webfuzzer/fuzzer/finding_pipeline.py`` — annotates each finding with
  ``orbit_canonical_key``, downgrades severity on orbit-duplicates so the
  bug-bounty operator sees each distinct bug only once at full severity.
- ``experiments/fuzzing_formal_research/e6_symmetry/`` — offline orbit analysis
  re-exports these helpers.

Design choices
--------------
- We never parse XML with ElementTree because the fuzzer intentionally
  produces malformed inputs; a lenient byte-level regex pipeline handles
  well-formed and malformed inputs uniformly.
- Transforms are idempotent — applying the chain twice yields the same
  result as applying it once.
- The SAML chain is conservative: only symmetries we're confident do not
  cross oracle decision boundaries are included. The full stabilizer /
  fixing-ratio measurement (Stage B) will empirically validate additional
  transforms.

References
----------
- Ganter / Wille "Formal Concept Analysis" §2.2 — canonical-form dedup.
- Serra 1982 "Image Analysis and Mathematical Morphology" — idempotent
  closure operators ≡ canonical form reachability.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Callable


# ── XML / SAML transforms ─────────────────────────────────────────

# ``>  \n  <``  →  ``><``. Only between tags, so text content is untouched.
_INTER_TAG_WS_RE = re.compile(rb">\s+<")

# ``<!--  ... -->`` across lines (DOTALL).
_XML_COMMENT_RE = re.compile(rb"<!--.*?-->", re.DOTALL)

# ``<name attr="v" attr2='x' ...>`` — capture the attribute list portion.
# We match a conservative open-tag pattern and hand the attribute list to
# ``_rewrite_attributes`` which sorts them. Self-closing and end tags pass
# through unchanged.
_OPEN_TAG_RE = re.compile(
    rb"<([A-Za-z_][\w:.\-]*)((?:\s+[^<>]*?)?)(/?)>",
)

# Within a tag's attribute region, match ``name="..."`` or ``name='...'``.
_ATTR_RE = re.compile(
    rb"""([A-Za-z_][\w:.\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')""",
)


def xml_whitespace_collapse(data: bytes) -> bytes:
    """Collapse inter-element whitespace runs between ``>`` and ``<``.

    Whitespace inside text nodes (e.g. ``<foo>hello   world</foo>``) is
    preserved, because it can be semantically significant. Only the gap
    *between* a close-bracket and the next open-bracket is squeezed.
    """
    return _INTER_TAG_WS_RE.sub(b"><", data)


def xml_comment_strip(data: bytes) -> bytes:
    """Remove XML ``<!-- ... -->`` comments (non-greedy, multiline)."""
    return _XML_COMMENT_RE.sub(b"", data)


def _rewrite_attributes(attr_region: bytes) -> bytes:
    """Sort ``name="value"`` pairs in ``attr_region`` lexicographically."""
    matches = list(_ATTR_RE.finditer(attr_region))
    if not matches:
        return attr_region

    parts: list[tuple[bytes, bytes]] = []
    for m in matches:
        name = m.group(1)
        if m.group(2) is not None:
            rendered = b'%s="%s"' % (name, m.group(2))
        else:
            rendered = b"%s='%s'" % (name, m.group(3) or b"")
        parts.append((name, rendered))

    parts.sort(key=lambda kv: kv[0])
    return b" " + b" ".join(p[1] for p in parts)


def xml_attribute_sort(data: bytes) -> bytes:
    """Rewrite each ``<tag ...>`` with its attributes sorted by name."""
    def _sub(match: re.Match[bytes]) -> bytes:
        name = match.group(1)
        attrs = match.group(2) or b""
        slash = match.group(3) or b""
        new_attrs = _rewrite_attributes(attrs) if attrs.strip() else b""
        return b"<" + name + new_attrs + slash + b">"

    return _OPEN_TAG_RE.sub(_sub, data)


# ``xmlns:prefix="uri"``
_XMLNS_DECL_RE = re.compile(rb"""xmlns:([A-Za-z_][\w.\-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


def xml_ns_prefix_normalize(data: bytes) -> bytes:
    """Rename ``xmlns:prefix`` declarations to stable ``ns0``, ``ns1``... .

    Prefixes are assigned in the order they first appear (left-to-right
    scan). After the mapping is built we rewrite both the declarations
    themselves and every ``prefix:local`` qualified name in the document.
    Prefixes used without declaration are left alone — renaming them
    blindly would change semantics.
    """
    mapping: dict[bytes, bytes] = {}
    for m in _XMLNS_DECL_RE.finditer(data):
        prefix = m.group(1)
        if prefix not in mapping:
            mapping[prefix] = b"ns%d" % len(mapping)
    if not mapping:
        return data

    def _decl_sub(match: re.Match[bytes]) -> bytes:
        prefix = match.group(1)
        new = mapping.get(prefix, prefix)
        if match.group(2) is not None:
            return b'xmlns:%s="%s"' % (new, match.group(2))
        return b"xmlns:%s='%s'" % (new, match.group(3) or b"")

    out = _XMLNS_DECL_RE.sub(_decl_sub, data)

    for old_prefix, new_prefix in mapping.items():
        pat = re.compile(
            rb"(?P<lead>[<\s/\"'=])" + re.escape(old_prefix) + rb":"
        )
        out = pat.sub(lambda m: m.group("lead") + new_prefix + b":", out)

    return out


# ── Generic byte-level transforms ─────────────────────────────────

_TRAILING_WS_RE = re.compile(rb"[ \t]+(\r?\n)")
_WS_RUN_RE = re.compile(rb"[ \t\r\n]+")


def trailing_ws_strip(data: bytes) -> bytes:
    """Remove trailing ``\\t`` / space at end of each line."""
    return _TRAILING_WS_RE.sub(rb"\1", data)


def whitespace_crunch(data: bytes) -> bytes:
    """Collapse every run of ASCII whitespace into a single ``\\x20``.

    Aggressive; only use for non-XML / byte-level canonicalization, since
    it destroys text-content whitespace.
    """
    return _WS_RUN_RE.sub(b" ", data)


def _trim_outer_ws(data: bytes) -> bytes:
    """Strip leading/trailing ASCII whitespace from the whole blob."""
    return data.strip()


# ── Transform catalogs ────────────────────────────────────────────

SAML_CANONICAL_CHAIN: tuple = (
    xml_whitespace_collapse,
    xml_comment_strip,
    xml_ns_prefix_normalize,
    xml_attribute_sort,
    _trim_outer_ws,
)

GENERIC_CANONICAL_CHAIN: tuple = (
    trailing_ws_strip,
    whitespace_crunch,
)


# ── Canonical form composition ────────────────────────────────────

Transform = Callable[[bytes], bytes]


def _looks_like_xml(data: bytes) -> bool:
    """Cheap XML detection — check for a leading ``<?xml`` or first-tag byte."""
    stripped = data.lstrip()
    if not stripped:
        return False
    return stripped[:5] == b"<?xml" or stripped[:1] == b"<"


def select_chain(data: bytes) -> tuple[Transform, ...]:
    """Pick the transform chain appropriate for this input family."""
    return SAML_CANONICAL_CHAIN if _looks_like_xml(data) else GENERIC_CANONICAL_CHAIN


def apply_chain(data: bytes, chain: Iterable[Transform]) -> bytes:
    """Fold a transform chain over an input to produce its canonical form."""
    out = data
    for transform in chain:
        out = transform(out)
    return out


def canonical_bytes(data: bytes) -> bytes:
    """Produce the canonical form of ``data`` using the auto-selected chain."""
    return apply_chain(data, select_chain(data))


def canonical_key(data: bytes) -> str:
    """SHA-256 of the canonical form, truncated to 16 hex chars (64 bits).

    16 hex = 64 bits: collision-free at 10⁶ findings, multiple orders of
    magnitude above any realistic bug-bounty campaign.
    """
    canonical = canonical_bytes(data)
    return hashlib.sha256(canonical).hexdigest()[:16]


def canonical_key_for_path(path: str | Path) -> str | None:
    """Load ``path`` as bytes and return its canonical key.

    Returns None if the path is missing or unreadable — the caller decides
    whether to drop the finding or fall back to fingerprint.
    """
    try:
        data = Path(path).read_bytes()
    except (OSError, ValueError):
        return None
    return canonical_key(data)
