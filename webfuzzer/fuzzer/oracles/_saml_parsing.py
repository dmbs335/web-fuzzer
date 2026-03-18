"""Shared SAML output parsing used by oracle and strategy modules."""

from __future__ import annotations

import json


def parse_saml_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a SAML target.  Returns None on failure.

    Uses a bounded LRU-style cache to avoid redundant json.loads calls
    when multiple oracle strategies parse the same output within one
    iteration (~10 strategies × 9 refs = 90 calls per iter, most redundant).
    """
    if not stdout:
        return None

    # Fast path: check value-based cache
    h = hash(stdout)
    cached = _parse_cache.get(h)
    if cached is not None:
        return cached if cached is not _NONE else None

    # Parse
    result = None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and (
            "signature_valid" in data or "subject" in data
        ):
            result = data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass

    # Bounded cache: clear when too large (enough for one iteration)
    if len(_parse_cache) > 64:
        _parse_cache.clear()
    _parse_cache[h] = result if result is not None else _NONE
    return result


_NONE = object()
_parse_cache: dict[int, object] = {}
