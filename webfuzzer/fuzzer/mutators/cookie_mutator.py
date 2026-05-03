"""Cookie parsing taxonomy-driven mutator — differential parsing edition.

Encodes structural attack patterns from cookie parsing research and local
campaign experience into a semantic-level mutator. Each strategy targets a
specific parsing differential or bypass category that should be validated
against the selected target set.

Taxonomy sections mapped to strategies:
  C1   Attribute & Flag Manipulation  -> samesite_*, httponly_bypass, prefix_*
  C2   Parsing Differentials          -> rfc2109_*, quoted_*, encoding_*
  C3   Scope Exploitation             -> domain_*, path_*
  C4   Value Manipulation             -> null_byte, crlf_inject, special_chars
  C5   Cookie Jar Attacks             -> overflow, tossing, ordering
  C6   Transport & Header Injection   -> header_inject, cookie_bomb

References:
  - RFC 6265bis (Cookies: HTTP State Management Mechanism)
  - RFC 2109 (legacy cookie spec)
  - PortSwigger "Cookie Chaos" (2025) — $Version parsing differentials
  - Cookie Crumbles (USENIX Security 2023) — 12 CVEs across 13 frameworks
  - CVE-2024-47764 (npm cookie <0.7.0) — out-of-bounds character injection
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

# ── Regex patterns for locating Set-Cookie components ──────────────

_RE_NAME_VALUE = re.compile(rb"^([^=;]+)=(.*?)(?:;|$)", re.DOTALL)
_RE_SEMICOLON = re.compile(rb";\s*")
_RE_DOMAIN_ATTR = re.compile(
    rb"(;\s*[Dd]omain\s*=\s*)([^;]*)", re.IGNORECASE
)
_RE_PATH_ATTR = re.compile(
    rb"(;\s*[Pp]ath\s*=\s*)([^;]*)", re.IGNORECASE
)
_RE_EXPIRES_ATTR = re.compile(
    rb"(;\s*[Ee]xpires\s*=\s*)([^;]*)", re.IGNORECASE
)
_RE_MAXAGE_ATTR = re.compile(
    rb"(;\s*[Mm]ax-[Aa]ge\s*=\s*)([^;]*)", re.IGNORECASE
)
_RE_SAMESITE_ATTR = re.compile(
    rb"(;\s*[Ss]ame[Ss]ite\s*=\s*)([^;]*)", re.IGNORECASE
)
_RE_SECURE_FLAG = re.compile(rb";\s*[Ss]ecure\b", re.IGNORECASE)
_RE_HTTPONLY_FLAG = re.compile(rb";\s*[Hh]ttp[Oo]nly\b", re.IGNORECASE)

# ── C1: SameSite bypass payloads ──────────────────────────────────

SAMESITE_BYPASS_VALUES = [
    b"None",       # requires Secure; omitting Secure is a diff trigger
    b"none",       # lowercase — casing differential
    b"NONE",       # uppercase
    b"Lax",
    b"lax",
    b"Strict",
    b"strict",
    b"Invalid",    # unknown value — default behavior varies
    b"",           # empty — default handling differs
    b"None; Secure",  # attribute injection via SameSite value
    b"Lax; Path=/evil",  # smuggling additional attribute
]

# ── C1: Cookie prefix bypass payloads ──────────────────────────────

PREFIX_MUTATIONS = [
    (b"__Host-", b"__host-"),          # lowercase bypass attempt
    (b"__Host-", b"__HOST-"),          # uppercase
    (b"__Host-", b"__Host"),           # missing hyphen
    (b"__Host-", b"__H\xc2\xadost-"), # soft hyphen Unicode normalization
    (b"__Host-", b"__\u0048ost-"),     # Unicode escape
    (b"__Secure-", b"__secure-"),      # lowercase
    (b"__Secure-", b"__SECURE-"),      # uppercase
    (b"__Secure-", b"__Secure"),       # missing hyphen
]

# ── C2: RFC 2109 legacy payloads ──────────────────────────────────

RFC2109_PAYLOADS = [
    b'$Version=1; ',                   # trigger RFC 2109 mode
    b'$Version="1"; ',                 # quoted version
    b'$Version=0; ',                   # version 0
]

RFC2109_QUOTED_PATHS = [
    b'; Path="/"',
    b'; Path="/; evil=injected"',      # semicolon inside quoted path
    b'; Path="/\\"',                   # backslash escape in path
]

RFC2109_OCTAL_ESCAPES = [
    b"\\074script\\076",              # <script> via octal
    b"\\074img src=x\\076",           # <img> via octal
    b"\\047OR 1=1--",                 # ' OR SQL injection via octal
]

# ── C2: Quoted-value parsing payloads ─────────────────────────────

QUOTED_VALUE_PAYLOADS = [
    b'"value; JSESSIONID=secret"',     # cookie sandwich
    b'"value; Path=/admin"',           # attribute injection via quote
    b'"',                              # unmatched opening quote
    b'"abc\\"def"',                    # backslash escape
    b'"abc\\076def"',                  # octal in quoted string
    b'""',                             # empty quoted
    b'"value with spaces"',            # spaces in quoted value
    b'"value\x00null"',               # null in quoted string
]

# ── C2: Encoding payloads ─────────────────────────────────────────

ENCODING_PAYLOADS = [
    b"%00",                            # null byte truncation
    b"%3B",                            # encoded semicolon
    b"%3D",                            # encoded equals
    b"%0D%0A",                         # CRLF
    b"%C0%AF",                         # overlong UTF-8 slash
    b"\xef\xbb\xbf",                  # UTF-8 BOM prefix
    b"\xc0\xbc",                       # overlong < (C0 encoding)
]

UNICODE_NORMALIZATION_NAMES = [
    b"\xef\xbc\xbf\xef\xbc\xbf\xef\xbc\xa8ost-",  # fullwidth __Host-
    b"se\xcc\x81ssion",               # combining acute accent
    b"\xc0\xf3\xf3kie",              # overlong encoding
]

# ── §1-3: Unicode whitespace prefix bypass (Cookie Crumbles 2023) ──
# Django str.strip() / ASP.NET trimming normalizes these away,
# so browser sets non-prefixed cookie but server reads __Host-
UNICODE_WHITESPACE_PREFIXES = [
    b"\xc2\x85",                       # U+0085 NEL (Safari-compatible)
    b"\xc2\xa0",                       # U+00A0 NBSP (Safari-compatible)
    b"\xe1\x9a\x80",                   # U+1680 Ogham Space Mark
    b"\xe2\x80\x80",                   # U+2000 En Quad
    b"\xe2\x80\x81",                   # U+2001 Em Quad
    b"\xe2\x80\x82",                   # U+2002 En Space
    b"\xe2\x80\x83",                   # U+2003 Em Space
    b"\xe2\x80\x84",                   # U+2004 Three-Per-Em Space
    b"\xe2\x80\x85",                   # U+2005 Four-Per-Em Space
    b"\xe2\x80\x86",                   # U+2006 Six-Per-Em Space
    b"\xe2\x80\x87",                   # U+2007 Figure Space
    b"\xe2\x80\x88",                   # U+2008 Punctuation Space
    b"\xe2\x80\x89",                   # U+2009 Thin Space
    b"\xe2\x80\x8a",                   # U+200A Hair Space
    b"\xe2\x80\xa8",                   # U+2028 Line Separator
    b"\xe2\x80\xa9",                   # U+2029 Paragraph Separator
    b"\xe2\x80\xaf",                   # U+202F Narrow No-Break Space
    b"\xe2\x81\x9f",                   # U+205F Medium Mathematical Space
    b"\xe3\x80\x80",                   # U+3000 Ideographic Space
]

# ── §1-3: PHP cookie name normalization characters ──────────────
# PHP $_COOKIE converts dots/spaces to underscores in cookie names
PHP_NORMALIZATION_CHARS = [
    (b"_", b"."),                       # dot → underscore (CVE-2022-31629)
    (b"_", b" "),                       # space → underscore
    (b"-", b"."),                       # dot instead of hyphen
]

# ── §2-3: Percent-encoded cookie name prefixes ──────────────────
PERCENT_ENCODED_NAMES = [
    b"%5F%5FHost-",                     # __Host- (CVE-2022-36032 ReactPHP)
    b"%5F%5FSecure-",                   # __Secure-
    b"%5f%5fHost-",                     # lowercase hex
    b"__%48ost-",                       # partial encoding
    b"__%53ecure-",                     # partial encoding
]

# ── C3: Domain scope payloads ─────────────────────────────────────

EVIL_DOMAINS = [
    b".com",                           # TLD-only (PSL bypass)
    b".co.uk",                         # eTLD
    b".",                              # bare dot
    b"",                               # empty domain
    b".localhost",                     # localhost wildcard
    b"192.168.1.1",                    # IP address
    b"[::1]",                          # IPv6 loopback
    b".example.com",                   # leading dot (RFC 6265 interpretation varies)
    b"example.com",                    # no leading dot
    b"evil.example.com",              # subdomain
    b"example.com\x00.evil.com",      # null byte domain injection
    b".Example.COM",                   # mixed case
]

EVIL_PATHS = [
    b"/../../etc/passwd",              # traversal
    b"/..",
    b"//",
    b"/",
    b"",                               # empty path
    b"/admin;",                        # path parameter
    b"/path?query=1",                  # query in path
    b"/\x00/admin",                   # null byte in path
    b"/path/../../../",               # deep traversal
]

# ── C4: Special character injection ───────────────────────────────

SPECIAL_CHAR_INJECTIONS = [
    b"\x00",                           # null byte
    b"\r\n",                           # CRLF
    b"\r",                             # bare CR
    b"\n",                             # bare LF
    b"\x0b",                           # vertical tab
    b"\x0c",                           # form feed
    b"\t",                             # horizontal tab
    b"\x7f",                           # DEL
    b"\x01",                           # SOH
    b"\xff",                           # high byte
    b"\xc2\xa0",                       # UTF-8 NBSP
]

CRLF_INJECTION_VALUES = [
    b"abc\r\nSet-Cookie: evil=injected",
    b"abc\r\nX-Injected: true",
    b"abc\r\n\r\n<script>alert(1)</script>",
    b"abc%0d%0aSet-Cookie: evil=injected",
    b"abc%0d%0a%0d%0a<script>alert(1)</script>",
]

# ── C5: Cookie overflow & tossing ─────────────────────────────────

# Generate a cookie bomb: very large value to exceed size limits
def _make_cookie_bomb(rng: random.Random, size: int = 4096) -> bytes:
    name = b"bomb"
    value = bytes(rng.choices(b"abcdefghijklmnopqrstuvwxyz0123456789", k=size))
    return name + b"=" + value + b"; Path=/"


# ── C6: Duplicate/conflicting attribute payloads ──────────────────

DUPLICATE_ATTR_COMBOS = [
    b"; Path=/; Path=/admin",
    b"; Domain=a.example.com; Domain=b.example.com",
    b"; SameSite=Strict; SameSite=None",
    b"; Secure; Secure",
    b"; Max-Age=3600; Max-Age=0",
    b"; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Expires=Fri, 31 Dec 9999 23:59:59 GMT",
]

# ── Whitespace manipulation ───────────────────────────────────────

WHITESPACE_VARIANTS = [
    (b"; ", b";"),                      # no space after semicolon
    (b"; ", b";  "),                    # double space
    (b"; ", b";\t"),                    # tab separator
    (b"; ", b" ; "),                    # space before semicolon
    (b"; ", b";\r\n "),                # CRLF continuation
    (b"; ", b";\x0b"),                 # vertical tab
]

MAX_OUTPUT_SIZE = 10_000

# ── $Version focused attack payloads (Finding #0020/#0034 derivatives) ──

VERSION_QUOTED_SEMICOLON_PAYLOADS = [
    # quoted value absorbs semicolons → phantom attribute injection
    b'$Version=1; {name}="val; JSESSIONID=secret"',
    b'$Version=1; {name}="val; HttpOnly"',
    b'$Version=1; {name}="session_data; Path=/evil; Domain=.evil.com"',
    b'$Version=1; {name}="val; Secure; HttpOnly; SameSite=None"',
]

VERSION_COMMA_SEPARATOR_PAYLOADS = [
    # RFC 2109 comma-separated cookies — parser split differential
    b'$Version=1, {name}=first, {name}=second',
    b'$Version=1, session=abc, admin=true, lang=en',
    b'$Version="1", {name}="quoted", evil="injected"',
    b'$Version=1, {name}=a; Path="/", evil=b; Path="/"',
]

VERSION_QUOTED_PATH_INJECT_PAYLOADS = [
    # quoted Path with injection — attribute scope confusion
    b'$Version=1; {name}="b"; Path="/evil"',
    b'$Version=1; {name}="b"; Path="/; evil=1"',
    b'$Version=1; {name}="b"; $Path="/admin"',
    b'$Version=1; {name}="b"; $Domain=".evil.com"',
]


class CookieMutator:
    """Cookie parsing taxonomy-driven mutator.

    Targets weaknesses in Set-Cookie header parsing across libraries:
    Python http.cookies, Node.js set-cookie-parser, tough-cookie,
    cookie (npm), Ruby WEBrick.
    """

    name = "cookie"

    # Micro-havoc probability: after structured mutation, apply
    # 1-3 random byte-level ops to explore nearby parse states.
    _MICRO_HAVOC_PROB = 0.10

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self._strategies: list = [
            # ── C1: Attribute & Flag Manipulation ──
            self._samesite_bypass,                  # 0
            self._samesite_casing,                  # 1
            self._httponly_strip,                    # 2
            self._secure_strip,                     # 3
            self._prefix_case_bypass,               # 4
            self._prefix_domain_violation,          # 5
            self._prefix_no_secure,                 # 6
            # ── C2: Parsing Differentials ──
            self._rfc2109_version_inject,           # 7
            self._rfc2109_quoted_path,              # 8
            self._rfc2109_octal_escape,             # 9
            self._quoted_value_semicolon,           # 10
            self._unmatched_quote,                  # 11
            self._backslash_escape_inject,          # 12
            self._encoding_percent_inject,          # 13
            self._unicode_normalization,            # 14
            self._whitespace_manipulation,          # 15
            # ── C3: Scope Exploitation ──
            self._domain_tld_only,                  # 16
            self._domain_leading_dot_toggle,        # 17
            self._domain_ip_address,                # 18
            self._domain_null_byte,                 # 19
            self._path_traversal,                   # 20
            self._path_parameter_inject,            # 21
            # ── C4: Value Manipulation ──
            self._null_byte_value,                  # 22
            self._crlf_injection_value,             # 23
            self._special_char_inject,              # 24
            self._control_char_name,                # 25
            self._very_long_value,                  # 26
            # ── C5: Cookie Jar Attacks ──
            self._cookie_bomb,                      # 27
            self._duplicate_attrs,                  # 28
            self._conflicting_expiry,               # 29
            # ── C6: Comma-separated injection ──
            self._comma_separated_inject,           # 30
            self._semicolon_in_attr_value,          # 31
            # ── C7: Cookie Crumbles / Cookie Chaos (2023-2025) ──
            self._unicode_whitespace_prefix,        # 32
            self._nameless_cookie,                  # 33
            self._php_name_normalization,            # 34
            self._safari_comma_split,               # 35
            self._phantom_attr_injection,           # 36
            self._leading_equals_strip,             # 37
            self._percent_decode_name,              # 38
            self._cookie_tossing_multi,             # 39
            self._cookie_jar_overflow,              # 40
            self._cookie_ordering,                  # 41
            # ── C8: $Version focused (Finding #0020/#0034 derivatives) ──
            self._version_quoted_semicolon,         # 42
            self._version_comma_separator,          # 43
            self._version_quoted_path_inject,       # 44
            # ── C9: RFC Gap Strategies (RFC 6265/6265bis compliance gaps) ──
            self._ctl_in_value,                     # 45
            self._ctl_in_attr,                      # 46
            self._name_value_length_boundary,       # 47
            self._attr_value_length_boundary,       # 48
            self._maxage_nonstandard,               # 49
            self._expires_delimiter_confusion,      # 50
            self._maxage_400day_boundary,           # 51
            self._host_prefix_empty_domain,         # 52
            self._attr_whitespace_inject,           # 53
            self._extension_av_special,             # 54
            self._duplicate_cookie_paths,           # 55
        ]
        self._strategy_names: list[str] = [
            fn.__name__.lstrip("_") for fn in self._strategies
        ]
        self._base_weights: list[int] = [
            # C1: Attribute manipulation
            8, 6, 5, 5, 9, 8, 7,
            # C2: Parsing differentials (high weight — core differential targets)
            10, 9, 8, 10, 9, 7, 8, 7, 6,
            # C3: Scope exploitation
            7, 8, 6, 8, 7, 6,
            # C4: Value manipulation
            7, 9, 7, 8, 4,
            # C5: Cookie jar
            3, 7, 5,
            # C6: Injection
            8, 7,
            # C7: Cookie Crumbles / Cookie Chaos (§1-3, §2-1, §2-2, §2-3, §3-2, §5)
            10, 9, 8, 7, 10, 9, 9, 6, 3, 7,
            # C8: $Version focused (highest yield from S169 postmortem)
            12, 10, 10,
            # C9: RFC gap strategies (RFC 6265/6265bis compliance boundaries)
            10, 10, 9, 8, 9, 8, 7, 10, 7, 6, 6,
        ]
        # Dynamic weights — adjusted by feedback()
        self._weights: list[int] = list(self._base_weights)
        # Tracking for dynamic adjustment
        self._strategy_finds: list[int] = [0] * len(self._strategies)
        self._strategy_cov: list[int] = [0] * len(self._strategies)
        self._total_feedback_calls = 0
        assert len(self._strategies) == len(self._weights), (
            f"strategies={len(self._strategies)} weights={len(self._weights)}"
        )

    # ── Public API ────────────────────────────────────────────────

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = bytearray(inp.data)
        if len(data) < 3:
            data = bytearray(b"session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")

        num_ops = self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        applied: list[str] = []
        for _ in range(num_ops):
            idx = self.rng.choices(
                range(len(self._strategies)), weights=self._weights, k=1
            )[0]
            strategy = self._strategies[idx]
            result = strategy(data)
            if result is not None and len(result) > 0:
                data = result
                applied.append(self._strategy_names[idx])

        # Micro-havoc: 10% chance to apply 1-3 byte-level ops after
        # structured mutation, exploring nearby parse states that
        # structured strategies can't reach.
        if self.rng.random() < self._MICRO_HAVOC_PROB and len(data) > 2:
            data = self._micro_havoc(data)
            applied.append("micro_havoc")

        if len(data) > MAX_OUTPUT_SIZE:
            data = data[:MAX_OUTPUT_SIZE]

        return Input(
            data=bytes(data),
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
            },
        )

    def feedback(self, strategy_name: str, signal: str) -> None:
        """Receive feedback from engine about strategy effectiveness.

        Args:
            strategy_name: Name of the strategy that produced the result.
            signal: "finding", "stage_up", or "coverage".
        """
        try:
            idx = self._strategy_names.index(strategy_name)
        except ValueError:
            return

        self._total_feedback_calls += 1

        if signal == "finding":
            self._strategy_finds[idx] += 1
            # Boost weight by 25% (capped at 3x base)
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 4, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "stage_up":
            self._strategy_cov[idx] += 1
            # Boost weight by 15% (between finding 25% and coverage 10%)
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] * 15 // 100, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "coverage":
            self._strategy_cov[idx] += 1
            # Boost weight by 10%
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 10, 1),
                self._base_weights[idx] * 3,
            )

        # Periodic decay: every 1000 feedback calls, decay strategies
        # that have never produced a finding (min 1 weight)
        if self._total_feedback_calls % 1000 == 0:
            for i in range(len(self._strategies)):
                if self._strategy_finds[i] == 0 and self._strategy_cov[i] == 0:
                    self._weights[i] = max(self._weights[i] - 1, 1)

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset dynamic weights — called by engine on stall detection.

        If boost_zero_finds is True, strategies that have NEVER produced
        a finding get a 2x boost (explore untested strategies).
        Strategies that already produced findings get reset to base.
        """
        for i in range(len(self._strategies)):
            if boost_zero_finds and self._strategy_finds[i] == 0:
                # Boost unexplored strategies to 2x base
                self._weights[i] = self._base_weights[i] * 2
            else:
                # Reset productive strategies to base
                self._weights[i] = self._base_weights[i]
        logger.info(
            "Stall reset: boosted %d zero-find strategies to 2x",
            sum(1 for i in range(len(self._strategies))
                if self._strategy_finds[i] == 0),
        )

    def _micro_havoc(self, data: bytearray) -> bytearray:
        """Apply 1-3 random byte-level mutations."""
        ops = self.rng.randint(1, 3)
        for _ in range(ops):
            if len(data) < 2:
                break
            op = self.rng.choice(["flip", "insert", "delete", "replace"])
            pos = self.rng.randint(0, len(data) - 1)
            if op == "flip":
                bit = 1 << self.rng.randint(0, 7)
                data[pos] ^= bit
            elif op == "insert":
                data.insert(pos, self.rng.randint(0, 255))
            elif op == "delete" and len(data) > 3:
                del data[pos]
            elif op == "replace":
                data[pos] = self.rng.randint(0, 255)
        return data

    # ══════════════════════════════════════════════════════════════
    # C1: Attribute & Flag Manipulation
    # ══════════════════════════════════════════════════════════════

    def _samesite_bypass(self, data: bytearray) -> bytearray | None:
        """Replace SameSite value with bypass payload."""
        m = _RE_SAMESITE_ATTR.search(data)
        if m:
            payload = self.rng.choice(SAMESITE_BYPASS_VALUES)
            return bytearray(data[:m.start(2)] + payload + data[m.end(2):])
        # No SameSite found — add one with edge-case value
        payload = self.rng.choice(SAMESITE_BYPASS_VALUES)
        return bytearray(data + b"; SameSite=" + payload)

    def _samesite_casing(self, data: bytearray) -> bytearray | None:
        """Mutate SameSite attribute name casing."""
        variants = [b"samesite", b"SAMESITE", b"SameSite", b"sameSite", b"Samesite"]
        m = _RE_SAMESITE_ATTR.search(data)
        if not m:
            return None
        prefix = m.group(1)
        # Replace the "SameSite" part in the prefix
        new_prefix = re.sub(rb"[Ss]ame[Ss]ite", self.rng.choice(variants), prefix)
        return bytearray(data[:m.start(1)] + new_prefix + data[m.end(1):])

    def _httponly_strip(self, data: bytearray) -> bytearray | None:
        """Remove HttpOnly flag to test enforcement."""
        m = _RE_HTTPONLY_FLAG.search(data)
        if not m:
            return None
        return bytearray(data[:m.start()] + data[m.end():])

    def _secure_strip(self, data: bytearray) -> bytearray | None:
        """Remove Secure flag to test enforcement."""
        m = _RE_SECURE_FLAG.search(data)
        if not m:
            return None
        return bytearray(data[:m.start()] + data[m.end():])

    def _prefix_case_bypass(self, data: bytearray) -> bytearray | None:
        """Mutate __Host-/__Secure- prefix casing."""
        for original, replacement in PREFIX_MUTATIONS:
            if original in data:
                return bytearray(data.replace(original, replacement, 1))
        # If no prefix, add one with wrong casing
        m = _RE_NAME_VALUE.match(data)
        if m:
            name = m.group(1)
            prefix = self.rng.choice([b"__host-", b"__HOST-", b"__Host"])
            return bytearray(prefix + data)
        return None

    def _prefix_domain_violation(self, data: bytearray) -> bytearray | None:
        """Add Domain attribute to __Host- cookie (should be rejected)."""
        if b"__Host-" not in data and b"__host-" not in data:
            return None
        if _RE_DOMAIN_ATTR.search(data):
            return None  # already has Domain
        return bytearray(data + b"; Domain=example.com")

    def _prefix_no_secure(self, data: bytearray) -> bytearray | None:
        """Remove Secure from __Host-/__Secure- cookie (violation)."""
        if b"__Host-" not in data and b"__Secure-" not in data:
            return None
        m = _RE_SECURE_FLAG.search(data)
        if not m:
            return None
        return bytearray(data[:m.start()] + data[m.end():])

    # ══════════════════════════════════════════════════════════════
    # C2: Parsing Differentials
    # ══════════════════════════════════════════════════════════════

    def _rfc2109_version_inject(self, data: bytearray) -> bytearray | None:
        """Prepend $Version=1 to trigger RFC 2109 parsing mode.

        Tomcat, Jetty <=10.0.x switch to RFC 2109 mode when they see
        $Version in Cookie header, enabling comma-separated cookies and
        octal escape sequences.
        """
        prefix = self.rng.choice(RFC2109_PAYLOADS)
        return bytearray(prefix + data)

    def _rfc2109_quoted_path(self, data: bytearray) -> bytearray | None:
        """Replace Path attribute with RFC 2109 quoted path.

        Quoted paths can contain semicolons, enabling cookie injection
        on servers that support RFC 2109 quoted-string parsing.
        """
        m = _RE_PATH_ATTR.search(data)
        payload = self.rng.choice(RFC2109_QUOTED_PATHS)
        if m:
            return bytearray(data[:m.start()] + payload + data[m.end():])
        return bytearray(data + payload)

    def _rfc2109_octal_escape(self, data: bytearray) -> bytearray | None:
        """Inject octal escape sequence in cookie value.

        RFC 2109 quoted-pair allows \\NNN octal escapes. Servers that
        interpret these can receive decoded payloads (e.g., <script>)
        that bypass WAFs checking for literal patterns.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        payload = self.rng.choice(RFC2109_OCTAL_ESCAPES)
        # Wrap in quotes for RFC 2109 mode
        return bytearray(name + b'="' + payload + b'"' + data[m.end():])

    def _quoted_value_semicolon(self, data: bytearray) -> bytearray | None:
        """Replace value with quoted string containing semicolons.

        Cookie sandwich attack: Jetty/Undertow parse past semicolons
        inside quoted values, merging HttpOnly cookie values into the
        readable non-HttpOnly cookie's quoted string.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        payload = self.rng.choice(QUOTED_VALUE_PAYLOADS)
        rest = data[m.end():]
        return bytearray(name + b"=" + payload + rest)

    def _unmatched_quote(self, data: bytearray) -> bytearray | None:
        """Inject unmatched opening quote in cookie value.

        An opening DQUOTE without closing absorbs the rest of the header
        in some parsers, causing divergent interpretation of subsequent
        attributes.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        rest = data[m.end():]
        return bytearray(name + b'="unmatched_value' + rest)

    def _backslash_escape_inject(self, data: bytearray) -> bytearray | None:
        """Inject backslash escape sequences in value."""
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        escapes = [b'"abc\\"def"', b'"val\\;more"', b'"x\\\\y"', b'"\\075"']
        payload = self.rng.choice(escapes)
        rest = data[m.end():]
        return bytearray(name + b"=" + payload + rest)

    def _encoding_percent_inject(self, data: bytearray) -> bytearray | None:
        """Inject percent-encoded characters in name or value.

        Server decodes cookies while browsers send raw bytes.
        %3Cscript%3E passes validation, decoded to <script> on server.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        payload = self.rng.choice(ENCODING_PAYLOADS)
        pos = self.rng.choice(["name", "value"])
        if pos == "name":
            return bytearray(m.group(1) + payload + b"=" + m.group(2) + data[m.end():])
        return bytearray(m.group(1) + b"=" + payload + m.group(2) + data[m.end():])

    def _unicode_normalization(self, data: bytearray) -> bytearray | None:
        """Replace cookie name with Unicode normalization variant.

        NFC/NFKC normalization changes cookie names after processing.
        Fullwidth characters become ASCII after normalization, causing
        different names to resolve to the same cookie.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        payload = self.rng.choice(UNICODE_NORMALIZATION_NAMES)
        return bytearray(payload + b"=" + m.group(2) + data[m.end():])

    def _whitespace_manipulation(self, data: bytearray) -> bytearray | None:
        """Mutate whitespace around semicolons."""
        old, new = self.rng.choice(WHITESPACE_VARIANTS)
        if old in data:
            return bytearray(data.replace(old, new))
        return None

    # ══════════════════════════════════════════════════════════════
    # C3: Scope Exploitation
    # ══════════════════════════════════════════════════════════════

    def _domain_tld_only(self, data: bytearray) -> bytearray | None:
        """Set Domain to TLD-only value (PSL bypass attempt)."""
        m = _RE_DOMAIN_ATTR.search(data)
        domain = self.rng.choice([b".com", b".co.uk", b".org", b"."])
        if m:
            return bytearray(data[:m.start(2)] + domain + data[m.end(2):])
        return bytearray(data + b"; Domain=" + domain)

    def _domain_leading_dot_toggle(self, data: bytearray) -> bytearray | None:
        """Toggle leading dot in Domain attribute.

        RFC 6265 says leading dots should be stripped, but implementations
        differ on whether .example.com == example.com for scope.
        """
        m = _RE_DOMAIN_ATTR.search(data)
        if not m:
            return None
        domain = m.group(2)
        if domain.startswith(b"."):
            new_domain = domain[1:]  # strip dot
        else:
            new_domain = b"." + domain  # add dot
        return bytearray(data[:m.start(2)] + new_domain + data[m.end(2):])

    def _domain_ip_address(self, data: bytearray) -> bytearray | None:
        """Replace Domain with IP address."""
        m = _RE_DOMAIN_ATTR.search(data)
        ip = self.rng.choice([b"127.0.0.1", b"192.168.1.1", b"[::1]", b"0.0.0.0"])
        if m:
            return bytearray(data[:m.start(2)] + ip + data[m.end(2):])
        return bytearray(data + b"; Domain=" + ip)

    def _domain_null_byte(self, data: bytearray) -> bytearray | None:
        """Inject null byte in Domain value (CVE-2023-46218 pattern)."""
        m = _RE_DOMAIN_ATTR.search(data)
        if not m:
            return bytearray(data + b"; Domain=example.com\x00.evil.com")
        domain = m.group(2)
        injected = domain + b"\x00.evil.com"
        return bytearray(data[:m.start(2)] + injected + data[m.end(2):])

    def _path_traversal(self, data: bytearray) -> bytearray | None:
        """Replace Path with traversal payload."""
        m = _RE_PATH_ATTR.search(data)
        path = self.rng.choice(EVIL_PATHS)
        if m:
            return bytearray(data[:m.start(2)] + path + data[m.end(2):])
        return bytearray(data + b"; Path=" + path)

    def _path_parameter_inject(self, data: bytearray) -> bytearray | None:
        """Inject semicolon parameter or query string in Path."""
        m = _RE_PATH_ATTR.search(data)
        payload = self.rng.choice([
            b"/admin;param=value",
            b"/path?query=1&evil=2",
            b"/path#fragment",
            b"/path%00/admin",
        ])
        if m:
            return bytearray(data[:m.start(2)] + payload + data[m.end(2):])
        return bytearray(data + b"; Path=" + payload)

    # ══════════════════════════════════════════════════════════════
    # C4: Value Manipulation
    # ══════════════════════════════════════════════════════════════

    def _null_byte_value(self, data: bytearray) -> bytearray | None:
        """Inject null byte in cookie value.

        C-based parsers truncate at \\x00 while others keep full value.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        value = m.group(2)
        pos = self.rng.randint(0, max(len(value) - 1, 0))
        new_value = value[:pos] + b"\x00" + value[pos:]
        return bytearray(name + b"=" + new_value + data[m.end():])

    def _crlf_injection_value(self, data: bytearray) -> bytearray | None:
        """Inject CRLF sequence in cookie value for header injection."""
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        payload = self.rng.choice(CRLF_INJECTION_VALUES)
        return bytearray(name + b"=" + payload + data[m.end():])

    def _special_char_inject(self, data: bytearray) -> bytearray | None:
        """Inject special/control characters in cookie value.

        CVE-2024-47764: npm cookie <0.7.0 allows control characters
        and delimiters in name/path/domain.
        """
        char = self.rng.choice(SPECIAL_CHAR_INJECTIONS)
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        target = self.rng.choice(["name", "value"])
        if target == "name":
            name = m.group(1)
            pos = self.rng.randint(0, max(len(name) - 1, 0))
            new_name = name[:pos] + char + name[pos:]
            return bytearray(new_name + b"=" + m.group(2) + data[m.end():])
        else:
            name = m.group(1)
            value = m.group(2)
            pos = self.rng.randint(0, max(len(value) - 1, 0))
            new_value = value[:pos] + char + value[pos:]
            return bytearray(name + b"=" + new_value + data[m.end():])

    def _control_char_name(self, data: bytearray) -> bytearray | None:
        """Inject control characters in cookie name.

        Tests RFC 6265bis token validation across implementations.
        Some parsers reject, others silently accept.
        """
        chars = [b"\x01", b"\x7f", b"(", b")", b"<", b">", b"@",
                 b",", b";", b"\\", b'"', b"/", b"[", b"]",
                 b"?", b"=", b"{", b"}"]
        char = self.rng.choice(chars)
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        return bytearray(name + char + b"=" + m.group(2) + data[m.end():])

    def _very_long_value(self, data: bytearray) -> bytearray | None:
        """Generate extremely long cookie value."""
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        length = self.rng.choice([4096, 8192, 16384])
        long_val = bytes(self.rng.choices(
            b"abcdefghijklmnopqrstuvwxyz0123456789", k=length
        ))
        return bytearray(name + b"=" + long_val + data[m.end():])

    # ══════════════════════════════════════════════════════════════
    # C5: Cookie Jar Attacks
    # ══════════════════════════════════════════════════════════════

    def _cookie_bomb(self, data: bytearray) -> bytearray | None:
        """Generate cookie bomb (oversized header for DoS)."""
        return bytearray(_make_cookie_bomb(self.rng, size=4096))

    def _duplicate_attrs(self, data: bytearray) -> bytearray | None:
        """Add duplicate/conflicting attributes.

        When the same attribute appears twice, parsers differ on which
        value they keep (first, last, or error).
        """
        combo = self.rng.choice(DUPLICATE_ATTR_COMBOS)
        return bytearray(data + combo)

    def _conflicting_expiry(self, data: bytearray) -> bytearray | None:
        """Set both Expires and Max-Age with conflicting values.

        RFC 6265 says Max-Age takes precedence, but implementations
        differ when values conflict.
        """
        conflict = b"; Max-Age=0; Expires=Fri, 31 Dec 9999 23:59:59 GMT"
        if b"Max-Age" in data or b"max-age" in data:
            return bytearray(data + b"; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        if b"Expires" in data or b"expires" in data:
            return bytearray(data + b"; Max-Age=999999")
        return bytearray(data + conflict)

    # ══════════════════════════════════════════════════════════════
    # C6: Comma-separated & injection
    # ══════════════════════════════════════════════════════════════

    def _comma_separated_inject(self, data: bytearray) -> bytearray | None:
        """Inject comma-separated cookie (RFC 2109 extension).

        RFC 2109 allows cookies separated by commas. Some parsers
        split on commas, creating injection opportunity.
        """
        payloads = [
            b", evil=injected; Path=/",
            b", admin=true; Path=/; Secure",
            b",role=admin",
        ]
        return bytearray(data + self.rng.choice(payloads))

    def _semicolon_in_attr_value(self, data: bytearray) -> bytearray | None:
        """Inject semicolon inside attribute value.

        Tests whether parsers correctly handle semicolons that appear
        inside quoted or encoded attribute values vs. treating them
        as attribute delimiters.
        """
        m = _RE_DOMAIN_ATTR.search(data)
        if m:
            domain = m.group(2)
            injected = domain + b";evil=injected"
            return bytearray(data[:m.start(2)] + injected + data[m.end(2):])
        m = _RE_PATH_ATTR.search(data)
        if m:
            path = m.group(2)
            injected = path + b";evil=injected"
            return bytearray(data[:m.start(2)] + injected + data[m.end(2):])
        return None

    # ══════════════════════════════════════════════════════════════
    # C7: Cookie Crumbles / Cookie Chaos (2023-2025 research)
    # ══════════════════════════════════════════════════════════════

    def _unicode_whitespace_prefix(self, data: bytearray) -> bytearray | None:
        """Prepend Unicode whitespace before __Host-/__Secure- prefix.

        Browser sets non-prefixed cookie (no restrictions enforced),
        but server-side str.strip() normalizes away the whitespace,
        interpreting the name as __Host-xxx.  Safari only accepts
        \\x85 and \\xA0; Chrome/Firefox accept all Unicode whitespace.
        (Cookie Crumbles, USENIX Security 2023)
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        ws = self.rng.choice(UNICODE_WHITESPACE_PREFIXES)
        prefix = self.rng.choice([b"__Host-", b"__Secure-"])
        # Replace the name with ws + prefix + base name
        base = name
        for p in (b"__Host-", b"__host-", b"__Secure-", b"__secure-"):
            if name.startswith(p):
                base = name[len(p):]
                break
        if not base:
            base = b"session"
        new_name = ws + prefix + base
        return bytearray(new_name + b"=" + m.group(2) + data[m.end():])

    def _nameless_cookie(self, data: bytearray) -> bytearray | None:
        """Generate nameless cookie (empty name before =).

        Nameless cookies cause serialization collisions: `=value`
        serializes to `=value` in Cookie header, which some parsers
        interpret as name='' value='value' while others see name='=value'.
        CVE-2022-2860 (Chrome), CVE-2022-40958 (Firefox).
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        value = m.group(2) or b"abc123"
        rest = data[m.end():]
        return bytearray(b"=" + value + rest)

    def _php_name_normalization(self, data: bytearray) -> bytearray | None:
        """Replace underscores/hyphens in cookie name with dots/spaces.

        PHP's $_COOKIE normalizes dots and spaces to underscores.
        __Host.session → __Host_session in PHP, bypassing prefix check.
        CVE-2022-31629.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        old, new = self.rng.choice(PHP_NORMALIZATION_CHARS)
        if old in name:
            new_name = name.replace(old, new, 1)
            return bytearray(new_name + b"=" + m.group(2) + data[m.end():])
        # Force a __Host- name with dot normalization
        return bytearray(
            b"__Host.session=" + m.group(2) + data[m.end():]
        )

    def _safari_comma_split(self, data: bytearray) -> bytearray | None:
        """Inject comma-separated Set-Cookie for Safari splitting.

        Safari splits Set-Cookie header values on commas in certain
        contexts, treating each part as a separate cookie.  Other
        browsers treat the comma as part of the value.
        """
        payloads = [
            b", evil=injected",
            b", admin=true; Path=/; Secure",
            b", __Host-session=hijacked; Path=/; Secure",
            b",session=overwritten",
        ]
        m = _RE_NAME_VALUE.match(data)
        if m:
            # Insert comma after value, before attributes
            name = m.group(1)
            value = m.group(2)
            rest = data[m.end():]
            payload = self.rng.choice(payloads)
            return bytearray(name + b"=" + value + payload + rest)
        return bytearray(data + self.rng.choice(payloads))

    def _phantom_attr_injection(self, data: bytearray) -> bytearray | None:
        """Inject phantom attributes via $Version=1 quoted-value parsing.

        In RFC 2109 mode, a quoted cookie value containing semicolons
        causes the text after the closing quote to be parsed as attributes
        of the *next* cookie, not the current one.  This allows injecting
        arbitrary attributes (Path, Domain) into a cookie that didn't
        originally have them.
        (PortSwigger Cookie Chaos, 2025)
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        # Construct: $Version=1; name="value; Path=/evil"; target=secret
        injected_attrs = self.rng.choice([
            b'; Path=/evil"',
            b'; Domain=.evil.com"',
            b'; Path=/admin; Domain=.evil.com"',
            b'; Secure"',
        ])
        return bytearray(
            b'$Version=1; ' + name + b'="payload'
            + injected_attrs + b'; session=secret'
        )

    def _leading_equals_strip(self, data: bytearray) -> bytearray | None:
        """Prepend = to cookie name for leading-equals stripping bypass.

        Werkzeug ≤2.2.2 strips the leading = from nameless cookies,
        turning =__Host-session=value into __Host-session=value.
        CVE-2023-23934.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        # If already has a prefix, prepend = to create bypass
        for prefix in (b"__Host-", b"__Secure-"):
            if name.startswith(prefix):
                return bytearray(b"=" + data)
        # Otherwise, create a =__Host- bypass
        base = name.decode("ascii", errors="replace").strip("_-")
        if not base:
            base = "session"
        return bytearray(
            b"=__Host-" + base.encode("ascii", errors="replace")
            + b"=" + m.group(2) + data[m.end():]
        )

    def _percent_decode_name(self, data: bytearray) -> bytearray | None:
        """Percent-encode cookie name prefix for decoding bypass.

        Some frameworks (ReactPHP) URL-decode cookie names before
        processing.  %5F%5FHost-session → __Host-session after decode.
        CVE-2022-36032.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        encoded_prefix = self.rng.choice(PERCENT_ENCODED_NAMES)
        name = m.group(1)
        # Strip existing prefix if any
        base = name
        for p in (b"__Host-", b"__Secure-", b"__host-", b"__secure-"):
            if name.startswith(p):
                base = name[len(p):]
                break
        if not base:
            base = b"session"
        return bytearray(
            encoded_prefix + base + b"=" + m.group(2) + data[m.end():]
        )

    def _cookie_tossing_multi(self, data: bytearray) -> bytearray | None:
        """Generate multiple Set-Cookie headers for tossing attack.

        Same cookie name set from different domain scopes.  The more
        specific subdomain cookie can override the parent domain cookie.
        Tests which cookie the parser picks when duplicates exist.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        value = m.group(2) or b"original"
        domains = self.rng.sample([
            b".example.com",
            b"sub.example.com",
            b".sub.example.com",
            b"example.com",
        ], k=2)
        # Generate two Set-Cookie lines separated by \r\n
        line1 = name + b"=" + value + b"; Domain=" + domains[0] + b"; Path=/"
        line2 = name + b"=tossed; Domain=" + domains[1] + b"; Path=/"
        return bytearray(line1 + b"\r\n" + line2)

    def _cookie_jar_overflow(self, data: bytearray) -> bytearray | None:
        """Generate many cookies to trigger jar overflow eviction.

        Browsers limit cookies per domain (~180 for Chrome).  Flooding
        with new cookies evicts existing ones, including security-critical
        cookies like CSRF tokens.
        """
        lines = []
        for i in range(self.rng.randint(50, 200)):
            name = f"overflow{i}".encode()
            value = bytes(self.rng.choices(
                b"abcdefghijklmnopqrstuvwxyz0123456789", k=8
            ))
            lines.append(name + b"=" + value + b"; Path=/")
        return bytearray(b"\r\n".join(lines))

    def _cookie_ordering(self, data: bytearray) -> bytearray | None:
        """Generate Cookie header with duplicate names in different order.

        When multiple cookies share the same name, parsers differ on
        which value they use: first-wins (RFC 6265 recommendation),
        last-wins, or error.  This is exploitable for session fixation
        when combined with cookie tossing.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        value1 = m.group(2) or b"first"
        value2 = bytes(self.rng.choices(
            b"abcdefghijklmnopqrstuvwxyz0123456789", k=16
        ))
        rest = data[m.end():]
        # Cookie header style: name=first; name=second
        return bytearray(
            name + b"=" + value1 + b"; " + name + b"=" + value2 + rest
        )

    # ══════════════════════════════════════════════════════════════
    # C8: $Version Focused Strategies (S169 postmortem-derived)
    # ══════════════════════════════════════════════════════════════

    def _version_quoted_semicolon(self, data: bytearray) -> bytearray | None:
        """$Version=1 + quoted value with embedded semicolons.

        Directly targets the #0034 CRITICAL finding pattern: Python
        parses past semicolons inside quotes while Node splits at them,
        causing name confusion and phantom attribute injection.
        """
        m = _RE_NAME_VALUE.match(data)
        name = m.group(1).decode("ascii", errors="replace") if m else "token"
        template = self.rng.choice(VERSION_QUOTED_SEMICOLON_PAYLOADS)
        return bytearray(template.replace(b"{name}", name.encode("ascii", errors="replace")))

    def _version_comma_separator(self, data: bytearray) -> bytearray | None:
        """$Version=1 + comma-separated cookies (RFC 2109).

        Directly targets the #0020 CRITICAL finding pattern: Python
        treats $Version as a cookie name while Node parses the comma-
        separated list and extracts the real cookie name.
        """
        m = _RE_NAME_VALUE.match(data)
        name = m.group(1).decode("ascii", errors="replace") if m else "session"
        template = self.rng.choice(VERSION_COMMA_SEPARATOR_PAYLOADS)
        return bytearray(template.replace(b"{name}", name.encode("ascii", errors="replace")))

    def _version_quoted_path_inject(self, data: bytearray) -> bytearray | None:
        """$Version=1 + quoted Path/Domain for scope injection.

        RFC 2109 allows quoted attribute values.  Parsers that enter
        2109 mode accept Path="/evil" while others keep literal quotes.
        Combined with $Domain this enables scope confusion.
        """
        m = _RE_NAME_VALUE.match(data)
        name = m.group(1).decode("ascii", errors="replace") if m else "session"
        template = self.rng.choice(VERSION_QUOTED_PATH_INJECT_PAYLOADS)
        return bytearray(template.replace(b"{name}", name.encode("ascii", errors="replace")))

    # ══════════════════════════════════════════════════════════════
    # C9: RFC Gap Strategies (RFC 6265/6265bis compliance gaps)
    # ══════════════════════════════════════════════════════════════

    def _ctl_in_value(self, data: bytearray) -> bytearray | None:
        """Inject CTL characters in cookie value.

        RFC 6265 §4.1.1: cookie-octet excludes CTL (0x00-0x1F, 0x7F).
        RFC 6265bis §5.5 adds explicit CTL rejection.  Some parsers
        silently accept CTL bytes in values while others reject or
        truncate, creating differential behavior.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        value = m.group(2)
        if not value:
            value = b"abc123"
        ctl = bytes([self.rng.choice(
            list(range(0x00, 0x20)) + [0x7F]
        )])
        pos = self.rng.randint(0, len(value))
        new_value = value[:pos] + ctl + value[pos:]
        return bytearray(name + b"=" + new_value + data[m.end():])

    def _ctl_in_attr(self, data: bytearray) -> bytearray | None:
        """Inject CTL characters in cookie attribute values.

        RFC 6265bis §5.5: reject cookies with CTL in attr-value.
        Tests Domain, Path, Expires attributes for CTL acceptance.
        """
        ctl = bytes([self.rng.choice(
            list(range(0x00, 0x20)) + [0x7F]
        )])
        attr_re = self.rng.choice([_RE_DOMAIN_ATTR, _RE_PATH_ATTR, _RE_EXPIRES_ATTR])
        m = attr_re.search(data)
        if m:
            attr_val = m.group(2)
            pos = self.rng.randint(0, max(len(attr_val) - 1, 0))
            new_val = attr_val[:pos] + ctl + attr_val[pos:]
            return bytearray(data[:m.start(2)] + new_val + data[m.end(2):])
        # No matching attr — append Domain with CTL
        return bytearray(data + b"; Domain=.exam" + ctl + b"ple.com")

    def _name_value_length_boundary(self, data: bytearray) -> bytearray | None:
        """Generate cookie at name+value 4096-byte boundary.

        RFC 6265bis §5.6: "name+value > 4096 octets SHOULD be rejected."
        Tests boundary ±1 to find parsers that accept/reject differently.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        rest = data[m.end():]
        # Target total name+value lengths around 4096
        target = self.rng.choice([4094, 4095, 4096, 4097, 4098])
        needed = target - len(name) - 1  # -1 for '='
        if needed < 1:
            needed = target
            name = b"s"
        pad = bytes(self.rng.choices(b"abcdefghijklmnopqrstuvwxyz0123456789", k=needed))
        return bytearray(name + b"=" + pad + rest)

    def _attr_value_length_boundary(self, data: bytearray) -> bytearray | None:
        """Generate cookie attribute value at 1024-byte boundary.

        RFC 6265bis §5.6: "attr-value > 1024 octets SHOULD be rejected."
        Tests Domain/Path attributes at the boundary.
        """
        target = self.rng.choice([1022, 1023, 1024, 1025, 1026])
        attr_type = self.rng.choice(["domain", "path"])
        if attr_type == "domain":
            # Build a long subdomain chain
            pad = b"a" * (target - 4)  # leave room for ".com"
            attr_val = pad + b".com"
            attr_re = _RE_DOMAIN_ATTR
            attr_name = b"; Domain=."
        else:
            pad = b"a" * (target - 1)  # leave room for "/"
            attr_val = b"/" + pad
            attr_re = _RE_PATH_ATTR
            attr_name = b"; Path="
        m = attr_re.search(data)
        if m:
            return bytearray(data[:m.start(2)] + attr_val + data[m.end(2):])
        return bytearray(data + attr_name + attr_val)

    def _maxage_nonstandard(self, data: bytearray) -> bytearray | None:
        """Set Max-Age to non-standard format.

        RFC 6265 §5.2.2: Max-Age must be digits only.  Tests hex,
        octal, float, and whitespace-padded formats that some parsers
        accept while others reject or misinterpret.
        """
        formats = [
            b"0x0E10",       # hex 3600
            b"03600",        # leading zero (octal?)
            b"3600.5",       # float
            b" 3600",        # leading space
            b"+3600",        # explicit positive
            b"3,600",        # thousands separator
            b"3600 ",        # trailing space
            b"36e2",         # scientific notation
        ]
        payload = self.rng.choice(formats)
        m = _RE_MAXAGE_ATTR.search(data)
        if m:
            return bytearray(data[:m.start(2)] + payload + data[m.end(2):])
        return bytearray(data + b"; Max-Age=" + payload)

    def _expires_delimiter_confusion(self, data: bytearray) -> bytearray | None:
        """Mutate Expires date delimiters.

        RFC 6265 §5.1.1: date-tokens separated by delimiters (any char
        that is not DIGIT, ALPHA, or ':').  Tests non-standard delimiters
        that parsers may or may not recognize.
        """
        date_variants = [
            b"Thu 01-Jan-2026 00:00:00 GMT",       # hyphen-separated
            b"Thu\t01\tJan\t2026\t00:00:00\tGMT",  # tab-separated
            b"Thursday, 01-Jan-26 00:00:00 GMT",    # full day + 2-digit year
            b"01 Jan 2026 00:00:00 GMT",            # no day-of-week
            b"Thu, 01 Jan 2026 00:00:00 +0000",     # +0000 instead of GMT
            b"Thu, 01 Jan 2026 00:00:00 UTC",       # UTC instead of GMT
            b"Thu, 01 Jan 2026 00:00:00",           # no timezone
        ]
        payload = self.rng.choice(date_variants)
        m = _RE_EXPIRES_ATTR.search(data)
        if m:
            return bytearray(data[:m.start(2)] + payload + data[m.end(2):])
        return bytearray(data + b"; Expires=" + payload)

    def _maxage_400day_boundary(self, data: bytearray) -> bytearray | None:
        """Set Max-Age at RFC 6265bis 400-day cap boundary.

        RFC 6265bis caps cookie lifetime at 400 days (34560000 seconds).
        Tests boundary values where compliant parsers should clamp but
        non-compliant ones pass through the raw value.
        """
        values = [
            b"34559999",     # 400 days - 1 second
            b"34560000",     # exactly 400 days
            b"34560001",     # 400 days + 1 second
            b"99999999",     # well over cap
            b"315360000",    # 10 years
        ]
        payload = self.rng.choice(values)
        m = _RE_MAXAGE_ATTR.search(data)
        if m:
            return bytearray(data[:m.start(2)] + payload + data[m.end(2):])
        return bytearray(data + b"; Max-Age=" + payload)

    def _host_prefix_empty_domain(self, data: bytearray) -> bytearray | None:
        """Set __Host- cookie with empty/whitespace Domain attribute.

        RFC 6265bis §5.5: __Host- cookies "MUST NOT contain a Domain
        attribute."  Tests whether an empty Domain= is treated as
        "present" (reject) or "absent" (accept) by different parsers.
        """
        empty_domains = [
            b"; Domain=",           # empty value
            b'; Domain=""',         # empty quoted
            b"; Domain= ",          # whitespace only
            b"; Domain=\t",         # tab only
        ]
        domain_payload = self.rng.choice(empty_domains)
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        # Ensure __Host- prefix
        for p in (b"__Host-", b"__host-", b"__Secure-", b"__secure-"):
            if name.startswith(p):
                name = name[len(p):]
                break
        if not name or name == b"__Host-":
            name = b"session"
        return bytearray(
            b"__Host-" + name + b"=" + (m.group(2) or b"val")
            + b"; Secure; Path=/" + domain_payload
        )

    def _attr_whitespace_inject(self, data: bytearray) -> bytearray | None:
        """Inject non-standard whitespace around attribute separators.

        RFC 6265 §4.1.1 uses OWS (optional whitespace) around
        separators.  Tests tabs, CRLF folding, and extra spaces in
        positions where parsers may differ.
        """
        replacements = [
            (b"; ", b";\t"),         # tab after semicolon
            (b"; ", b";\r\n "),      # CRLF folding
            (b"; ", b" ;\t"),        # space+tab
            (b"=", b" = "),          # spaces around first equals
            (b"; ", b";\x0b"),       # vertical tab
            (b"; ", b";\x0c"),       # form feed
        ]
        old, new = self.rng.choice(replacements)
        if old in data:
            # Replace only first occurrence for =, all for ;
            if old == b"=":
                return bytearray(data.replace(old, new, 1))
            return bytearray(data.replace(old, new))
        return None

    def _extension_av_special(self, data: bytearray) -> bytearray | None:
        """Add unknown extension attribute with special characters.

        RFC 6265 §4.1.1: "extension-av = <any CHAR except CTL or ';'>".
        Tests how parsers handle unrecognized attributes with values
        containing quotes, equals, and other special characters.
        """
        extensions = [
            b"; X-Custom=val;ue",           # semicolon in extension value
            b'; X-Test="quoted"',           # quoted extension value
            b"; Priority=Critical",         # Chrome Priority attribute
            b"; X-Foo=a=b=c",              # multiple equals
            b"; Partitioned",              # partitioned flag (6265bis)
            b"; X-Evil=val\tmore",         # tab in extension value
        ]
        return bytearray(data + self.rng.choice(extensions))

    def _duplicate_cookie_paths(self, data: bytearray) -> bytearray | None:
        """Generate duplicate cookie names with different Path attributes.

        RFC 6265 §5.4: cookies sorted by path specificity.  When same
        cookie name appears with different paths, parsers differ on
        which value to use — creates scope confusion.
        """
        m = _RE_NAME_VALUE.match(data)
        if not m:
            return None
        name = m.group(1)
        value1 = m.group(2) or b"admin"
        value2 = bytes(self.rng.choices(
            b"abcdefghijklmnopqrstuvwxyz0123456789", k=12
        ))
        paths = self.rng.sample([b"/", b"/api", b"/admin", b"/api/v1"], k=2)
        line1 = name + b"=" + value1 + b"; Path=" + paths[0]
        line2 = name + b"=" + value2 + b"; Path=" + paths[1]
        return bytearray(line1 + b"\r\n" + line2)
