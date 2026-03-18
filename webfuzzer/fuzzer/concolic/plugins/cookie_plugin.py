"""Cookie domain plugin for property-learning concolic layer.

Extracts ~25 structural properties from Set-Cookie / Cookie header strings
and provides perturbation operators.
"""

from __future__ import annotations

import math
import random
import re
from collections import Counter

from ..domain_plugin import DomainPlugin
from ..property_vector import PropertyVector

NUM_COOKIE_PROPERTIES = 25

COOKIE_PROPERTY_NAMES: tuple[str, ...] = (
    # Size (3)
    "total_bytes",           # 0
    "cookie_count",          # 1 — number of ; separated parts
    "name_value_ratio",      # 2 — name length / total length
    # Name (4)
    "has_prefix_host",       # 3 — __Host- prefix
    "has_prefix_secure",     # 4 — __Secure- prefix
    "name_has_special",      # 5 — non-alphanumeric in name
    "name_is_empty",         # 6 — nameless cookie
    # Value (4)
    "value_has_quotes",      # 7 — quoted value
    "value_has_semicolon",   # 8 — embedded ; in value
    "value_has_equals",      # 9 — embedded = in value
    "value_has_unicode",     # 10 — non-ASCII bytes
    # Attributes (8)
    "has_domain",            # 11
    "has_path",              # 12
    "has_expires",           # 13
    "has_maxage",            # 14
    "has_secure",            # 15
    "has_httponly",          # 16
    "has_samesite",          # 17
    "attr_count",            # 18 — total attribute count
    # Structure (4)
    "has_rfc2109_version",   # 19 — $Version=
    "has_comma_separator",   # 20 — RFC2109 comma separation
    "has_crlf",              # 21 — embedded CRLF
    "has_control_chars",     # 22 — control characters
    # Encoding (2)
    "has_percent_encoding",  # 23 — %xx
    "byte_entropy",          # 24
)

assert len(COOKIE_PROPERTY_NAMES) == NUM_COOKIE_PROPERTIES


class CookiePlugin(DomainPlugin):
    """Cookie-specific property extraction and perturbation."""

    def extract(self, data: bytes) -> PropertyVector:
        v = [0.0] * NUM_COOKIE_PROPERTIES
        text = data.strip()

        # Size
        v[0] = min(len(text) / 4096.0, 1.0)
        parts = text.split(b";")
        v[1] = min(len(parts) / 10.0, 1.0)

        # Name/value split
        eq_pos = text.find(b"=")
        if eq_pos > 0:
            name = text[:eq_pos]
            v[2] = len(name) / max(len(text), 1)
        else:
            name = text.split(b";")[0]

        # Name properties
        v[3] = 1.0 if name.lower().startswith(b"__host-") else 0.0
        v[4] = 1.0 if name.lower().startswith(b"__secure-") else 0.0
        v[5] = 1.0 if re.search(rb"[^a-zA-Z0-9_\-]", name) else 0.0
        v[6] = 1.0 if eq_pos == 0 or not name.strip() else 0.0

        # Value properties
        value = text[eq_pos + 1:].split(b";")[0] if eq_pos >= 0 else b""
        v[7] = 1.0 if value.startswith(b'"') else 0.0
        v[8] = 1.0 if b";" in value.strip(b'"') else 0.0
        v[9] = 1.0 if b"=" in value else 0.0
        v[10] = 1.0 if any(b > 127 for b in value) else 0.0

        # Attributes (case-insensitive)
        lower = text.lower()
        v[11] = 1.0 if b"domain=" in lower else 0.0
        v[12] = 1.0 if b"path=" in lower else 0.0
        v[13] = 1.0 if b"expires=" in lower else 0.0
        v[14] = 1.0 if b"max-age=" in lower else 0.0
        v[15] = 1.0 if b"secure" in lower else 0.0
        v[16] = 1.0 if b"httponly" in lower else 0.0
        v[17] = 1.0 if b"samesite=" in lower else 0.0
        attrs = [b"domain=", b"path=", b"expires=", b"max-age=",
                 b"secure", b"httponly", b"samesite="]
        v[18] = min(sum(1 for a in attrs if a in lower) / 7.0, 1.0)

        # Structure
        v[19] = 1.0 if b"$version=" in lower or b"$Version=" in text else 0.0
        v[20] = 1.0 if b"," in text else 0.0
        v[21] = 1.0 if b"\r\n" in data or b"\r" in data or b"\n" in data else 0.0
        v[22] = 1.0 if any(b < 32 and b not in (9, 10, 13) for b in data) else 0.0

        # Encoding
        v[23] = 1.0 if b"%" in text and re.search(rb"%[0-9a-fA-F]{2}", text) else 0.0
        v[24] = _byte_entropy(text)

        return PropertyVector(tuple(v))

    @property
    def property_names(self) -> tuple[str, ...]:
        return COOKIE_PROPERTY_NAMES

    @property
    def num_properties(self) -> int:
        return NUM_COOKIE_PROPERTIES

    def perturb(self, data: bytes, prop_idx: int, rng: random.Random) -> list[bytes]:
        fn_list = _COOKIE_PERTURBATIONS.get(prop_idx, [])
        results: list[bytes] = []
        for fn in fn_list:
            try:
                mutated = fn(data, rng)
                results.extend(m for m in mutated if m and m != data)
            except Exception:
                pass
        return results

    @property
    def excluded_output_fields(self) -> frozenset[str]:
        return frozenset({"duration_ms"})

    @property
    def mutation_name_to_prop_index(self) -> dict[str, int]:
        return {
            "host_prefix": 3, "secure_prefix": 4, "empty_name": 6,
            "quoted_value": 7, "domain": 11, "path": 12,
            "maxage": 14, "samesite": 17,
            "rfc2109": 19, "comma": 20, "crlf": 21,
            "control_chars": 22, "percent_encoding": 23,
            # Aliases from AST analyzer
            "tag_count": 1, "encoding_decl": 23,
            "assertion_count": 1, "issuer": 11,
            "audience": 11, "conditions": 14,
        }


def _byte_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = Counter(buf)
    n = len(buf)
    entropy = sum(-((f / n) * math.log2(f / n)) for f in counts.values())
    return entropy / 8.0


# ── Perturbation functions ─────────────────────────────────────────

def _perturb_host_prefix(data: bytes, rng: random.Random) -> list[bytes]:
    name_end = data.find(b"=")
    if name_end < 0:
        return []
    return [b"__Host-test" + data[name_end:]]


def _perturb_secure_prefix(data: bytes, rng: random.Random) -> list[bytes]:
    name_end = data.find(b"=")
    if name_end < 0:
        return []
    return [b"__Secure-test" + data[name_end:]]


def _perturb_empty_name(data: bytes, rng: random.Random) -> list[bytes]:
    name_end = data.find(b"=")
    if name_end < 0:
        return [b"=value; Path=/"]
    return [data[name_end:]]  # remove name, keep =value;attrs


def _perturb_quoted_value(data: bytes, rng: random.Random) -> list[bytes]:
    eq = data.find(b"=")
    if eq < 0:
        return []
    semi = data.find(b";", eq)
    if semi < 0:
        semi = len(data)
    value = data[eq + 1:semi]
    if value.startswith(b'"'):
        return [data[:eq + 1] + value.strip(b'"') + data[semi:]]
    return [data[:eq + 1] + b'"' + value + b'"' + data[semi:]]


def _perturb_domain(data: bytes, rng: random.Random) -> list[bytes]:
    domains = [b".example.com", b"example.com", b"", b".evil.com",
               b"example.com.", b" .example.com"]
    d = rng.choice(domains)
    if b"domain=" in data.lower():
        return [re.sub(rb"(?i)domain=[^;]*", b"Domain=" + d, data, count=1)]
    return [data.rstrip() + b"; Domain=" + d]


def _perturb_path(data: bytes, rng: random.Random) -> list[bytes]:
    paths = [b"/", b"/admin", b"", b"/;", b"/%2e%2e/admin"]
    p = rng.choice(paths)
    if b"path=" in data.lower():
        return [re.sub(rb"(?i)path=[^;]*", b"Path=" + p, data, count=1)]
    return [data.rstrip() + b"; Path=" + p]


def _perturb_maxage(data: bytes, rng: random.Random) -> list[bytes]:
    values = [b"0", b"-1", b"999999999", b"0xff", b"1.5"]
    v = rng.choice(values)
    if b"max-age=" in data.lower():
        return [re.sub(rb"(?i)max-age=[^;]*", b"Max-Age=" + v, data, count=1)]
    return [data.rstrip() + b"; Max-Age=" + v]


def _perturb_samesite(data: bytes, rng: random.Random) -> list[bytes]:
    values = [b"Strict", b"Lax", b"None", b"none", b"", b"invalid"]
    v = rng.choice(values)
    if b"samesite=" in data.lower():
        return [re.sub(rb"(?i)samesite=[^;]*", b"SameSite=" + v, data, count=1)]
    return [data.rstrip() + b"; SameSite=" + v]


def _perturb_rfc2109(data: bytes, rng: random.Random) -> list[bytes]:
    return [b"$Version=1; " + data]


def _perturb_comma(data: bytes, rng: random.Random) -> list[bytes]:
    return [data + b", extra=value"]


def _perturb_crlf(data: bytes, rng: random.Random) -> list[bytes]:
    eq = data.find(b"=")
    if eq < 0:
        return []
    semi = data.find(b";", eq)
    if semi < 0:
        semi = len(data)
    return [data[:semi] + b"\r\nInjected: header" + data[semi:]]


def _perturb_control_chars(data: bytes, rng: random.Random) -> list[bytes]:
    chars = [b"\x00", b"\x01", b"\x7f", b"\t"]
    c = rng.choice(chars)
    eq = data.find(b"=")
    if eq < 0:
        return []
    return [data[:eq + 1] + c + data[eq + 1:]]


def _perturb_percent_encoding(data: bytes, rng: random.Random) -> list[bytes]:
    eq = data.find(b"=")
    if eq < 0:
        return []
    # Encode value
    return [data[:eq + 1] + b"%3B%3D%20" + data[eq + 1:]]


def _perturb_special_name(data: bytes, rng: random.Random) -> list[bytes]:
    eq = data.find(b"=")
    if eq < 0:
        return []
    specials = [b"name with space", b"name\twith\ttab", b"name.with.dots",
                b"(name)", b"name@domain"]
    return [rng.choice(specials) + data[eq:]]


# ── Registry ──────────────────────────────────────────────────────

_COOKIE_PERTURBATIONS: dict[int, list] = {
    3:  [_perturb_host_prefix],
    4:  [_perturb_secure_prefix],
    5:  [_perturb_special_name],
    6:  [_perturb_empty_name],
    7:  [_perturb_quoted_value],
    11: [_perturb_domain],
    12: [_perturb_path],
    14: [_perturb_maxage],
    17: [_perturb_samesite],
    19: [_perturb_rfc2109],
    20: [_perturb_comma],
    21: [_perturb_crlf],
    22: [_perturb_control_chars],
    23: [_perturb_percent_encoding],
}
