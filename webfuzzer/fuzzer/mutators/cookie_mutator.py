"""Cookie parsing taxonomy-driven mutator — differential parsing edition.

Encodes structural attack patterns from the cookie vulnerability taxonomy
(the-map) into a semantic-level mutator.  Each strategy targets a specific
parsing differential or bypass category proven to cause divergence across
real-world cookie implementations.

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

import random
import re
from typing import TYPE_CHECKING

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


class CookieMutator:
    """Cookie parsing taxonomy-driven mutator.

    Targets weaknesses in Set-Cookie header parsing across libraries:
    Python http.cookies, Node.js set-cookie-parser, tough-cookie,
    cookie (npm), Ruby WEBrick.
    """

    name = "cookie"

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
        ]
        self._strategy_names: list[str] = [
            fn.__name__.lstrip("_") for fn in self._strategies
        ]
        self._weights: list[int] = [
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
        ]
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
