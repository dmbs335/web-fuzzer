"""OAuth differential fuzzing mutator.

O1  redirect_uri URI normalization  → port add/remove, case change, encoding
O2  redirect_uri attack vectors     → path traversal, fragment injection, backslash, null byte
O3  scope whitespace/parsing        → double space, tab, newline, empty, reorder
O4  scope semantic manipulation     → hierarchic prefix, wildcard, duplicate, case
O5  type switching                  → redirect_uri ↔ scope
O6  redirect_uri Unicode/encoding   → full-width chars, zero-width space, overlong UTF-8,
                                      IP encoding (hex/octal/decimal), double encoding
                                      (derived from URL diff fuzzing sessions S53-S54)
O7  PKCE challenge/verifier         → length, padding, method, charset, corruption,
                                      downgrade, presence/absence (RFC 7636 §4.2)
O10 token exchange redirect_uri     → auth vs token redirect_uri normalization diff
                                      (RFC 6749 §4.1.3, ACSAC'23)
O11 DPoP proof JWT                  → htm/htu/ath/iat/jti/nonce/typ/alg mutations
                                      (RFC 9449, CVE-2024-49755)
"""

from __future__ import annotations

import json
import random
import string
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed


class OAuthMutationStrategy:
    """Base class for OAuth mutation strategies."""

    name: str = "oauth_base"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        raise NotImplementedError


class O1_RedirectUriNormStrategy(OAuthMutationStrategy):
    """Mutate redirect_uri to trigger URL normalization differences."""

    name = "oauth_redirect_norm"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "redirect_uri":
            return None

        candidate = str(data.get("candidate", ""))
        if not candidate:
            return None

        mutations = [
            self._add_default_port,
            self._remove_port,
            self._uppercase_scheme,
            self._uppercase_host,
            self._percent_encode_path,
            self._add_trailing_slash,
            self._remove_trailing_slash,
            self._add_dot_segment,
            self._double_slash,
        ]

        fn = random.choice(mutations)
        mutated = fn(candidate)
        if mutated == candidate:
            return None

        data["candidate"] = mutated
        result = json.dumps(data).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None

    @staticmethod
    def _add_default_port(uri: str) -> str:
        if "://" not in uri:
            return uri
        if uri.startswith("http://"):
            parts = uri.split("/", 3)
            if len(parts) >= 3 and ":" not in parts[2]:
                parts[2] = parts[2] + ":80"
                return "/".join(parts)
        elif uri.startswith("https://"):
            parts = uri.split("/", 3)
            if len(parts) >= 3 and ":" not in parts[2]:
                parts[2] = parts[2] + ":443"
                return "/".join(parts)
        return uri

    @staticmethod
    def _remove_port(uri: str) -> str:
        if "://" not in uri:
            return uri
        parts = uri.split("/", 3)
        if len(parts) >= 3 and ":" in parts[2]:
            host_port = parts[2]
            host = host_port.rsplit(":", 1)[0]
            parts[2] = host
            return "/".join(parts)
        return uri

    @staticmethod
    def _uppercase_scheme(uri: str) -> str:
        idx = uri.find("://")
        if idx > 0:
            return uri[:idx].upper() + uri[idx:]
        return uri

    @staticmethod
    def _uppercase_host(uri: str) -> str:
        if "://" not in uri:
            return uri
        scheme_end = uri.index("://") + 3
        rest = uri[scheme_end:]
        slash_idx = rest.find("/")
        if slash_idx < 0:
            return uri[:scheme_end] + rest.upper()
        host = rest[:slash_idx]
        return uri[:scheme_end] + host.upper() + rest[slash_idx:]

    @staticmethod
    def _percent_encode_path(uri: str) -> str:
        if "://" not in uri:
            return uri
        scheme_end = uri.index("://") + 3
        rest = uri[scheme_end:]
        slash_idx = rest.find("/")
        if slash_idx < 0:
            return uri
        path = rest[slash_idx:]
        # Encode a random character in the path
        alpha_positions = [i for i, c in enumerate(path) if c.isalpha()]
        if not alpha_positions:
            return uri
        pos = random.choice(alpha_positions)
        encoded = quote(path[pos], safe="")
        path = path[:pos] + encoded + path[pos + 1:]
        return uri[:scheme_end] + rest[:slash_idx] + path

    @staticmethod
    def _add_trailing_slash(uri: str) -> str:
        if uri.endswith("/"):
            return uri
        return uri + "/"

    @staticmethod
    def _remove_trailing_slash(uri: str) -> str:
        if uri.endswith("/") and not uri.endswith("://"):
            return uri[:-1]
        return uri

    @staticmethod
    def _add_dot_segment(uri: str) -> str:
        if "/" not in uri[8:]:
            return uri
        last_slash = uri.rfind("/")
        segment = uri[last_slash:]
        return uri[:last_slash] + "/dummy/.." + segment

    @staticmethod
    def _double_slash(uri: str) -> str:
        if "://" not in uri:
            return uri
        scheme_end = uri.index("://") + 3
        rest = uri[scheme_end:]
        slash_idx = rest.find("/")
        if slash_idx < 0:
            return uri
        return uri[:scheme_end] + rest[:slash_idx] + "/" + rest[slash_idx:]


class O2_RedirectUriAttackStrategy(OAuthMutationStrategy):
    """Inject attack payloads into redirect_uri candidate."""

    name = "oauth_redirect_attack"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "redirect_uri":
            return None

        registered = data.get("registered", [])
        if not registered:
            return None
        base = registered[0] if isinstance(registered[0], str) else "http://example.com/callback"

        attacks = [
            # Fragment injection
            base + "#evil",
            base + "#access_token=stolen",
            base + "#//evil.com/path",  # S54: fragment + double-slash
            # Path traversal
            base + "/../admin",
            base + "/..%2f..%2fadmin",
            base.replace("/callback", "/..\\..\\evil.com"),  # S54: backslash traversal
            # Userinfo confusion
            base.replace("://", "://evil.com@", 1),
            base.replace("://", "://user@good.com@evil.com@", 1),  # Double @
            # Subdomain prefix
            base.replace("://", "://evil.", 1),
            # Backslash (S54 finding 0000)
            base.replace("/callback", "\\@evil.com/callback"),
            base.replace("://", "://evil.com\\@", 1),  # evil in userinfo
            base.replace("://", "://evil.com\\\\@", 1),  # double backslash
            # Null byte (URL seed 005)
            base + "%00evil",
            base.replace(".com", ".com%00.evil.com"),  # null in host
            # Protocol-relative
            "//" + base.split("://", 1)[-1] if "://" in base else base,
            # Scheme confusion
            "javascript://x%0aalert(1)",
            "data:text/html,<script>alert(1)</script>",
            # Encoded @
            base.replace("@", "%40") if "@" in base else base + "%40evil.com",
            # Open redirect via similar domain
            base.replace("example.com", "example.com.evil.com"),
            # Port confusion
            base.replace("/callback", ":1337/callback"),
            # Control characters (URL S54)
            base.replace(".com", "%0d.evil.com"),  # CR in host
            base.replace(".com", "%0a.evil.com"),  # LF in host
            base.replace(".com", "%09.com"),  # tab in host
            # Semicolon path parameter (URL S54)
            base + ";param=value",
            base.replace("/callback", ";evil.com/callback"),
        ]

        data["candidate"] = random.choice(attacks)
        result = json.dumps(data).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None


class O3_ScopeWhitespaceStrategy(OAuthMutationStrategy):
    """Mutate scope strings to exploit whitespace parsing differences."""

    name = "oauth_scope_whitespace"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "scope":
            return None

        granted = str(data.get("granted", ""))
        if not granted:
            return None

        mutations = [
            # Double space (oauthlib .split(" ") creates empty elements)
            granted.replace(" ", "  ", 1),
            # Triple space
            granted.replace(" ", "   ", 1),
            # Tab separator
            granted.replace(" ", "\t", 1),
            # Newline separator
            granted.replace(" ", "\n", 1),
            # Leading space
            " " + granted,
            # Trailing space
            granted + " ",
            # Multiple separators
            granted.replace(" ", " \t ", 1),
            # All tabs
            granted.replace(" ", "\t"),
        ]

        data["granted"] = random.choice(mutations)
        result = json.dumps(data).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None


class O4_ScopeSemanticStrategy(OAuthMutationStrategy):
    """Mutate scope semantics: hierarchy, duplication, case, special chars."""

    name = "oauth_scope_semantic"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "scope":
            return None

        granted = str(data.get("granted", ""))
        requested = str(data.get("requested", ""))
        scopes = granted.split() if granted else ["openid"]

        mutations = [
            # Duplicate scope
            lambda: (granted + " " + scopes[0], requested),
            # Case variation
            lambda: (granted.upper(), requested),
            # Hierarchic: request parent when child granted
            lambda: (granted, scopes[0].rsplit(".", 1)[0] if "." in scopes[0] else scopes[0]),
            # Hierarchic: request child when parent granted
            lambda: (granted, scopes[0] + ".sub"),
            # Reverse order
            lambda: (" ".join(reversed(scopes)), requested),
            # Add wildcard-like scope
            lambda: (granted + " *", requested),
            # Colon-separated scope
            lambda: (granted.replace(".", ":"), requested.replace(".", ":")),
            # Empty requested
            lambda: (granted, ""),
            # Request non-existent
            lambda: (granted, "admin.nuclear.launch"),
        ]

        fn = random.choice(mutations)
        new_granted, new_requested = fn()
        data["granted"] = new_granted
        data["requested"] = new_requested
        result = json.dumps(data).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None


class O6_UnicodeEncodingStrategy(OAuthMutationStrategy):
    """Apply Unicode/encoding mutations from URL diff fuzzing findings (S53-S54).

    These techniques exploit parser differences in:
    - Unicode normalization (WHATWG vs RFC 3986 vs raw string)
    - Percent-encoding interpretation
    - Overlong UTF-8 handling
    - IP address format recognition
    """

    name = "oauth_unicode_encoding"

    # Unicode replacement characters (from URL S53-S54 findings)
    _UNICODE_DOTS = [
        "\u3002",     # Ideographic period (CJK)
        "\uff0e",     # Full-width period
        "\u2024",     # One dot leader
        "%c0%ae",     # Overlong UTF-8 dot
        "%e2%80%8b.", # Zero-width space + dot
    ]
    _UNICODE_ATS = [
        "%ef%bc%a0",  # Full-width @ (U+FF20) — S53 finding 0002
        "\uff20",     # Full-width @ (raw Unicode)
        "%e2%80%8b@", # Zero-width space + @
    ]
    _UNICODE_SLASHES = [
        "%ef%bc%8f",  # Full-width / (U+FF0F) — S53 finding 0005
        "\uff0f",     # Full-width / (raw Unicode)
        "%c0%af",     # Overlong UTF-8 / — S53 finding 0010
        "%e2%81%84",  # Fraction slash (U+2044)
    ]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "redirect_uri":
            return None

        candidate = str(data.get("candidate", ""))
        if not candidate:
            return None

        mutations = [
            self._unicode_dot_in_host,
            self._unicode_at_injection,
            self._unicode_slash_in_path,
            self._zerowidth_in_host,
            self._overlong_utf8_dot,
            self._double_encode,
            self._ip_encoding,
            self._mixed_case_scheme,
        ]

        fn = random.choice(mutations)
        mutated = fn(candidate)
        if mutated == candidate:
            return None

        data["candidate"] = mutated
        result = json.dumps(data, ensure_ascii=False).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None

    def _unicode_dot_in_host(self, uri: str) -> str:
        """Replace ASCII dot in hostname with Unicode dot variant."""
        if "://" not in uri:
            return uri
        scheme_end = uri.index("://") + 3
        rest = uri[scheme_end:]
        slash_idx = rest.find("/")
        if slash_idx < 0:
            host = rest
            path = ""
        else:
            host = rest[:slash_idx]
            path = rest[slash_idx:]
        if "." not in host:
            return uri
        dot = random.choice(self._UNICODE_DOTS)
        host = host.replace(".", dot, 1)
        return uri[:scheme_end] + host + path

    def _unicode_at_injection(self, uri: str) -> str:
        """Inject Unicode full-width @ to create userinfo confusion (S53)."""
        if "://" not in uri:
            return uri
        scheme_end = uri.index("://") + 3
        rest = uri[scheme_end:]
        at_char = random.choice(self._UNICODE_ATS)
        slash_idx = rest.find("/")
        if slash_idx < 0:
            return uri[:scheme_end] + "evil.com" + at_char + rest
        host = rest[:slash_idx]
        path = rest[slash_idx:]
        return uri[:scheme_end] + "evil.com" + at_char + host + path

    def _unicode_slash_in_path(self, uri: str) -> str:
        """Replace path slash with Unicode slash variant (S53)."""
        if "://" not in uri:
            return uri
        slash = random.choice(self._UNICODE_SLASHES)
        # Replace the last / before path component
        last_slash = uri.rfind("/")
        if last_slash <= 8:
            return uri
        return uri[:last_slash] + slash + uri[last_slash + 1:]

    def _zerowidth_in_host(self, uri: str) -> str:
        """Inject zero-width space in hostname (S53 finding 0004)."""
        if "://" not in uri:
            return uri
        scheme_end = uri.index("://") + 3
        # Insert zero-width space right after ://
        return uri[:scheme_end] + "%e2%80%8b" + uri[scheme_end:]

    def _overlong_utf8_dot(self, uri: str) -> str:
        """Replace dot with overlong UTF-8 encoding (S53 finding 0005)."""
        if "." not in uri[8:]:
            return uri
        # Find a dot in the host portion
        scheme_end = uri.index("://") + 3 if "://" in uri else 0
        rest = uri[scheme_end:]
        dot_pos = rest.find(".")
        if dot_pos < 0:
            return uri
        return uri[:scheme_end + dot_pos] + "%c0%ae" + uri[scheme_end + dot_pos + 1:]

    def _double_encode(self, uri: str) -> str:
        """Apply double percent-encoding to existing encoded chars."""
        # Double-encode existing percent-encoded chars
        if "%" in uri:
            return uri.replace("%", "%25", 1)
        # Or double-encode a dot
        if "." in uri[8:]:
            return uri.replace(".", "%252e", 1)
        return uri

    def _ip_encoding(self, uri: str) -> str:
        """Replace 127.0.0.1 with alternative IP encodings (URL S50-S54)."""
        ip_variants = [
            "0x7f000001",              # Hex IP
            "0177.0.0.1",              # Octal IP
            "2130706433",              # Decimal IP
            "127.1",                   # Compressed IPv4
            "[::ffff:127.0.0.1]",      # IPv6-mapped
            "[::1]",                   # IPv6 loopback
            "0x7f%2e0%2e0%2e1",        # S53: hex + encoded dots
            "%e2%80%8b127.0.0.1",      # S53: zero-width space + IP
        ]
        if "127.0.0.1" in uri:
            return uri.replace("127.0.0.1", random.choice(ip_variants))
        if "localhost" in uri:
            return uri.replace("localhost", random.choice(ip_variants[:6]))
        return uri

    def _mixed_case_scheme(self, uri: str) -> str:
        """Randomize scheme case (S54 finding)."""
        idx = uri.find("://")
        if idx <= 0:
            return uri
        scheme = uri[:idx]
        mixed = "".join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in scheme
        )
        return mixed + uri[idx:]


class O5_TypeSwitchStrategy(OAuthMutationStrategy):
    """Switch between redirect_uri and scope input types."""

    name = "oauth_type_switch"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        if data.get("type") == "redirect_uri":
            # Convert to scope input
            new_data = {
                "type": "scope",
                "granted": "openid profile email",
                "requested": "openid",
            }
        elif data.get("type") == "scope":
            # Convert to redirect_uri input
            new_data = {
                "type": "redirect_uri",
                "registered": ["http://example.com/callback"],
                "candidate": "http://example.com/callback",
            }
        else:
            return None

        result = json.dumps(new_data).encode("utf-8")
        return Input(result, metadata={"strategy": self.name})


class O7_PKCEStrategy(OAuthMutationStrategy):
    """Mutate PKCE inputs to trigger challenge/verifier divergence."""

    name = "oauth_pkce"

    _VERIFIER_CHARS = string.ascii_letters + string.digits + "-._~"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "pkce":
            return None

        new_data = dict(data)
        mutation = random.choice([
            self._mutate_verifier_length,
            self._mutate_challenge_padding,
            self._mutate_method,
            self._mutate_verifier_charset,
            self._mutate_challenge_corrupt,
            self._mutate_downgrade,
            self._mutate_challenge_presence,
            self._mutate_verifier_presence,
            self._mutate_method_empty_vs_absent,
        ])
        mutation(new_data)
        result = json.dumps(new_data).encode("utf-8")
        return Input(result, metadata={"strategy": self.name})

    def _mutate_verifier_length(self, data: dict) -> None:
        """P1: Push verifier length to boundaries."""
        target_len = random.choice([0, 1, 42, 43, 44, 127, 128, 129, 256])
        data["verifier"] = "a" * target_len

    def _mutate_challenge_padding(self, data: dict) -> None:
        """P2: Add/remove base64url padding to challenge."""
        challenge = str(data.get("challenge", ""))
        choice = random.choice(["add_one", "add_two", "strip", "add_plus"])
        if choice == "add_one":
            data["challenge"] = challenge.rstrip("=") + "="
        elif choice == "add_two":
            data["challenge"] = challenge.rstrip("=") + "=="
        elif choice == "strip":
            data["challenge"] = challenge.rstrip("=")
        elif choice == "add_plus":
            # Convert base64url to standard base64
            data["challenge"] = challenge.replace("-", "+").replace("_", "/")

    def _mutate_method(self, data: dict) -> None:
        """P3: Method downgrade/variation."""
        data["method"] = random.choice([
            "S256", "plain", "s256", "PLAIN", "Plain", "S384", "SHA256",
            "none", "None", "", "s 256",
        ])

    def _mutate_verifier_charset(self, data: dict) -> None:
        """P4: Inject invalid chars into verifier."""
        verifier = str(data.get("verifier", "a" * 43))
        if len(verifier) < 2:
            verifier = "a" * 43
        pos = random.randint(0, len(verifier) - 1)
        bad_char = random.choice(["+", "/", "=", " ", "\t", "\n", "\x00", "%", "@"])
        data["verifier"] = verifier[:pos] + bad_char + verifier[pos + 1:]

    def _mutate_challenge_corrupt(self, data: dict) -> None:
        """P5: Corrupt challenge (bit flip, truncate, swap)."""
        challenge = str(data.get("challenge", ""))
        if not challenge:
            return
        choice = random.choice(["flip", "truncate", "swap", "case"])
        if choice == "flip" and challenge:
            pos = random.randint(0, len(challenge) - 1)
            c = challenge[pos]
            if c.isalpha():
                new_c = c.swapcase()
            else:
                new_c = chr((ord(c) + 1) % 128)
            data["challenge"] = challenge[:pos] + new_c + challenge[pos + 1:]
        elif choice == "truncate":
            cut = random.randint(1, max(1, len(challenge) // 2))
            data["challenge"] = challenge[:cut]
        elif choice == "swap" and len(challenge) >= 4:
            i, j = sorted(random.sample(range(len(challenge)), 2))
            lst = list(challenge)
            lst[i], lst[j] = lst[j], lst[i]
            data["challenge"] = "".join(lst)
        elif choice == "case":
            data["challenge"] = challenge.swapcase()

    def _mutate_downgrade(self, data: dict) -> None:
        """P6: PKCE downgrade — set method=plain but keep S256 challenge."""
        choice = random.choice(["plain_with_s256", "verifier_as_challenge"])
        if choice == "plain_with_s256":
            data["method"] = "plain"
            # Keep existing challenge (computed for S256) — library may accept
        else:
            # Set verifier = challenge value (works for plain but not S256)
            challenge = data.get("challenge", "")
            if challenge:
                data["verifier"] = challenge
                data["method"] = "plain"

    def _mutate_challenge_presence(self, data: dict) -> None:
        """P7: Remove challenge key — RFC 7636 §4.2 ambiguity."""
        data.pop("challenge", None)

    def _mutate_verifier_presence(self, data: dict) -> None:
        """P8: Remove verifier key — keep challenge+method only."""
        data.pop("verifier", None)

    def _mutate_method_empty_vs_absent(self, data: dict) -> None:
        """P9: Empty string vs absent method — spec ambiguity."""
        if random.random() < 0.5:
            data["method"] = ""
        else:
            data.pop("method", None)


class O8_TokenRequestStrategy(OAuthMutationStrategy):
    """Mutate token_request inputs to trigger server-side validation divergence.

    Targets: grant_type case/normalization, code format/length, client_id
    special chars, redirect_uri micro-variations, scope expansion.
    """

    name = "oauth_token_request"

    _GRANT_TYPES = [
        "authorization_code", "Authorization_Code", "AUTHORIZATION_CODE",
        "refresh_token", "client_credentials", "password", "",
        "urn:ietf:params:oauth:grant-type:device_code",
        " authorization_code ", "authorization_code ",
    ]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "token_request":
            return None

        mutation = random.choice([
            self._mutate_grant_type,
            self._mutate_code,
            self._mutate_client_id,
            self._mutate_redirect_uri,
            self._mutate_scope,
        ])
        new_data = dict(data)
        mutation(new_data)
        result = json.dumps(new_data, ensure_ascii=False).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None

    def _mutate_grant_type(self, data: dict) -> None:
        """T1: grant_type case/whitespace/unknown variations."""
        gt = str(data.get("grant_type", "authorization_code"))
        if not gt:
            gt = "authorization_code"
        choice = random.choice(["case", "whitespace", "swap", "urn"])
        if choice == "case":
            data["grant_type"] = random.choice([
                gt.upper(), gt.lower(), gt.capitalize(),
                gt.swapcase(), gt[0].upper() + gt[1:],
            ])
        elif choice == "whitespace":
            data["grant_type"] = random.choice([
                " " + gt, gt + " ", " " + gt + " ", "\t" + gt,
            ])
        elif choice == "swap":
            data["grant_type"] = random.choice(self._GRANT_TYPES)
        elif choice == "urn":
            data["grant_type"] = "urn:ietf:params:oauth:grant-type:" + random.choice([
                "device_code", "jwt-bearer", "saml2-bearer", "token-exchange",
            ])

    def _mutate_code(self, data: dict) -> None:
        """T2: code format/length/charset variations."""
        code = str(data.get("code", "abc123"))
        choice = random.choice(["long", "null", "unicode", "urlencode", "empty"])
        if choice == "long":
            data["code"] = "A" * random.choice([2048, 2049, 4096, 65536])
        elif choice == "null":
            pos = random.randint(0, max(0, len(code) - 1))
            data["code"] = code[:pos] + "\x00" + code[pos:]
        elif choice == "unicode":
            data["code"] = code + random.choice(["\u00e9", "\u200b", "\uff0e", "\u0000"])
        elif choice == "urlencode":
            data["code"] = quote(code, safe="")
        elif choice == "empty":
            data["code"] = ""

    def _mutate_client_id(self, data: dict) -> None:
        """T3: client_id special character injection."""
        cid = str(data.get("client_id", "testclient"))
        choice = random.choice(["colon", "space", "unicode", "long", "at"])
        if choice == "colon":
            data["client_id"] = cid + ":" + "secret"
        elif choice == "space":
            data["client_id"] = cid + " " + "extra"
        elif choice == "unicode":
            data["client_id"] = cid[:3] + "\u200b" + cid[3:]
        elif choice == "long":
            data["client_id"] = cid * 100
        elif choice == "at":
            data["client_id"] = cid + "@evil.com"

    def _mutate_redirect_uri(self, data: dict) -> None:
        """T4: redirect_uri micro-variations."""
        uri = str(data.get("redirect_uri", "http://example.com/cb"))
        choice = random.choice(["trailing", "case", "port", "backslash", "scheme"])
        if choice == "trailing":
            data["redirect_uri"] = uri + "/" if not uri.endswith("/") else uri[:-1]
        elif choice == "case":
            data["redirect_uri"] = uri.replace("http://", "HTTP://")
        elif choice == "port":
            data["redirect_uri"] = uri.replace("example.com", "example.com:80")
        elif choice == "backslash":
            data["redirect_uri"] = uri.replace("/cb", "\\..\\admin")
        elif choice == "scheme":
            data["redirect_uri"] = uri.replace("http://", "https://")

    def _mutate_scope(self, data: dict) -> None:
        """T5: scope expansion/whitespace."""
        scope = str(data.get("scope", "openid"))
        choice = random.choice(["expand", "tab", "double", "extra"])
        if choice == "expand":
            data["scope"] = scope + " admin"
        elif choice == "tab":
            data["scope"] = scope.replace(" ", "\t")
        elif choice == "double":
            data["scope"] = scope.replace(" ", "  ")
        elif choice == "extra":
            parts = scope.split()
            data["scope"] = scope + " " + parts[0] if parts else scope


class O9_TokenResponseStrategy(OAuthMutationStrategy):
    """Mutate token_response inputs to trigger client-side parsing divergence.

    Targets: token_type case, expires_in type coercion, scope downgrade,
    error+200 confused deputy, JSON structure edge cases.
    """

    name = "oauth_token_response"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "token_response":
            return None

        mutation = random.choice([
            self._mutate_token_type,
            self._mutate_expires_in,
            self._mutate_scope,
            self._mutate_error,
            self._mutate_json_structure,
        ])
        new_data = dict(data)
        mutation(new_data)
        result = json.dumps(new_data, ensure_ascii=False).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None

    def _mutate_token_type(self, data: dict) -> None:
        """R1: token_type case and variant."""
        try:
            body = json.loads(data.get("body", "{}"))
        except (json.JSONDecodeError, ValueError):
            return
        if not isinstance(body, dict):
            return
        body["token_type"] = random.choice([
            "Bearer", "bearer", "BEARER", "BeArEr", " Bearer ", "mac",
            "MAC", "dpop", "DPoP", "",
        ])
        data["body"] = json.dumps(body)

    def _mutate_expires_in(self, data: dict) -> None:
        """R2: expires_in type coercion."""
        try:
            body = json.loads(data.get("body", "{}"))
        except (json.JSONDecodeError, ValueError):
            return
        if not isinstance(body, dict):
            return
        body["expires_in"] = random.choice([
            3600, "3600", -1, 0, 3600.5, "abc", "",
            999999999999, True, False, "3600.0", " 3600",
        ])
        data["body"] = json.dumps(body)

    def _mutate_scope(self, data: dict) -> None:
        """R3: scope downgrade/expansion/whitespace."""
        try:
            body = json.loads(data.get("body", "{}"))
        except (json.JSONDecodeError, ValueError):
            return
        if not isinstance(body, dict):
            return
        requested = str(data.get("requested_scope", "openid"))
        choice = random.choice(["expand", "downgrade", "tab", "missing", "empty"])
        if choice == "expand":
            body["scope"] = requested + " admin"
        elif choice == "downgrade":
            parts = requested.split()
            body["scope"] = parts[0] if parts else ""
        elif choice == "tab":
            body["scope"] = requested.replace(" ", "\t")
        elif choice == "missing":
            body.pop("scope", None)
        elif choice == "empty":
            body["scope"] = ""
        data["body"] = json.dumps(body)

    def _mutate_error(self, data: dict) -> None:
        """R4: error/status confused deputy."""
        choice = random.choice(["200_error", "400_token", "unknown_error"])
        if choice == "200_error":
            data["status_code"] = 200
            data["body"] = json.dumps({
                "error": random.choice(["invalid_grant", "invalid_client", "server_error"]),
                "error_description": "something went wrong",
            })
        elif choice == "400_token":
            data["status_code"] = 400
            data["body"] = json.dumps({
                "access_token": "tok",
                "token_type": "Bearer",
                "expires_in": 3600,
            })
        elif choice == "unknown_error":
            data["status_code"] = 200
            data["body"] = json.dumps({
                "error": "custom_error_" + str(random.randint(0, 99)),
            })

    def _mutate_json_structure(self, data: dict) -> None:
        """R5: JSON structure edge cases."""
        choice = random.choice(["malformed", "array", "empty", "nested"])
        if choice == "malformed":
            data["body"] = "{access_token: tok}"
        elif choice == "array":
            data["body"] = '[{"access_token":"tok"}]'
        elif choice == "empty":
            data["body"] = ""
        elif choice == "nested":
            data["body"] = json.dumps({
                "access_token": {"value": "tok"},
                "token_type": "Bearer",
                "expires_in": 3600,
            })


class O10_TokenExchangeRedirectStrategy(OAuthMutationStrategy):
    """Mutate token_exchange inputs: auth vs token redirect_uri normalization.

    RFC 6749 §4.1.3 requires redirect_uri at token endpoint to be "identical"
    to the value used in the authorization request. Libraries differ on whether
    "identical" means byte-level or normalized comparison (ACSAC'23: 6/16 IdPs
    vulnerable). This strategy injects normalization differences between
    auth_redirect_uri and token_redirect_uri.
    """

    name = "oauth_token_exchange"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "token_exchange":
            return None

        new_data = dict(data)
        mutation = random.choice([
            self._mutate_port_norm,
            self._mutate_case,
            self._mutate_encoding,
            self._mutate_trailing_slash,
            self._mutate_remove_token_redirect,
            self._mutate_query_param,
            self._mutate_dot_segment,
        ])
        mutation(new_data)
        result = json.dumps(new_data, ensure_ascii=False).encode("utf-8")
        return Input(result, metadata={"strategy": self.name}) if len(result) <= 8192 else None

    def _mutate_port_norm(self, data: dict) -> None:
        """TE1: Add/remove default port to token_redirect_uri."""
        auth_uri = str(data.get("auth_redirect_uri", ""))
        if "://example.com/" in auth_uri and ":80" not in auth_uri and ":443" not in auth_uri:
            if auth_uri.startswith("http://"):
                data["token_redirect_uri"] = auth_uri.replace("://example.com/", "://example.com:80/", 1)
            elif auth_uri.startswith("https://"):
                data["token_redirect_uri"] = auth_uri.replace("://example.com/", "://example.com:443/", 1)
        else:
            # Copy with minor change
            data["token_redirect_uri"] = auth_uri

    def _mutate_case(self, data: dict) -> None:
        """TE2: Scheme/host case difference."""
        auth_uri = str(data.get("auth_redirect_uri", ""))
        choice = random.choice(["scheme", "host", "both"])
        if choice == "scheme":
            data["token_redirect_uri"] = auth_uri[:auth_uri.find("://")].upper() + auth_uri[auth_uri.find("://"):]
        elif choice == "host":
            # Uppercase host part
            scheme_end = auth_uri.find("://") + 3
            path_start = auth_uri.find("/", scheme_end)
            if path_start == -1:
                path_start = len(auth_uri)
            data["token_redirect_uri"] = auth_uri[:scheme_end] + auth_uri[scheme_end:path_start].upper() + auth_uri[path_start:]
        else:
            data["token_redirect_uri"] = auth_uri.upper()

    def _mutate_encoding(self, data: dict) -> None:
        """TE3: Percent-encode unreserved chars in token_redirect_uri."""
        auth_uri = str(data.get("auth_redirect_uri", ""))
        # Encode a letter in the path
        if "/callback" in auth_uri:
            data["token_redirect_uri"] = auth_uri.replace("/callback", "/%63allback", 1)
        else:
            data["token_redirect_uri"] = auth_uri

    def _mutate_trailing_slash(self, data: dict) -> None:
        """TE4: Add/remove trailing slash."""
        auth_uri = str(data.get("auth_redirect_uri", ""))
        if auth_uri.endswith("/"):
            data["token_redirect_uri"] = auth_uri.rstrip("/")
        else:
            data["token_redirect_uri"] = auth_uri + "/"

    def _mutate_remove_token_redirect(self, data: dict) -> None:
        """TE5: Omit token_redirect_uri entirely."""
        data.pop("token_redirect_uri", None)

    def _mutate_query_param(self, data: dict) -> None:
        """TE6: Add query parameter to token_redirect_uri."""
        auth_uri = str(data.get("auth_redirect_uri", ""))
        data["token_redirect_uri"] = auth_uri + "?state=abc"

    def _mutate_dot_segment(self, data: dict) -> None:
        """TE7: Path dot-segment in token_redirect_uri."""
        auth_uri = str(data.get("auth_redirect_uri", ""))
        if "/callback" in auth_uri:
            data["token_redirect_uri"] = auth_uri.replace("/callback", "/other/../callback", 1)
        else:
            data["token_redirect_uri"] = auth_uri + "/./."


class O11_DPoPProofStrategy(OAuthMutationStrategy):
    """Mutate DPoP proof JWT inputs (RFC 9449).

    Sub-mutations target differential behavior in htm/htu/ath/iat/jti/nonce/typ/alg
    fields between implementations.

    Strategies D1-D8: field-level mutations (original).
    Strategies D9-D16: JWT-structural mutations (jwk, kid, base64url, envelope).
    Stacking: 1-3 mutations per round for cross-field interaction coverage.
    """

    name = "oauth_dpop"

    # Weighted strategy table: (method_name, weight).
    # Higher weight = more likely selected.  JWT-structural strategies
    # get elevated weight to compensate for the historical DPoP coverage gap.
    _STRATEGY_TABLE: list[tuple[str, int]] = [
        # D1-D8: field-level mutations
        ("_mutate_htm", 6),
        ("_mutate_htu", 10),          # biggest differential surface (urllib vs WHATWG URL)
        ("_mutate_ath", 7),
        ("_mutate_iat", 5),
        ("_mutate_jti", 5),
        ("_mutate_nonce", 5),
        ("_mutate_typ", 6),
        ("_mutate_alg", 7),
        # D9-D16: JWT-structural mutations
        ("_mutate_jwk_embed", 9),     # self-signed JWK in header
        ("_mutate_jwk_privkey", 9),   # RFC 9449 §4.3: private key leak detection
        ("_mutate_kid_inject", 7),    # kid path traversal / SQL injection
        ("_mutate_b64url_edge", 8),   # base64url padding/standard chars
        ("_mutate_htu_deep", 10),     # deep htu normalization (backslash, IDN, IPv6, double-encode)
        ("_mutate_extra_claims", 6),  # extra/duplicate DPoP claims
        ("_mutate_envelope", 6),      # JSON envelope mutations (extra fields, type swap)
        ("_mutate_header_dupes", 7),  # duplicate header keys (alg, typ)
    ]

    def __init__(self) -> None:
        self._methods = [(getattr(self, name), w) for name, w in self._STRATEGY_TABLE]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input | None:
        try:
            data = json.loads(inp.data.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        if data.get("type") != "dpop_proof":
            return None

        new_data = dict(data)
        proof = new_data.get("proof_jwt", "")
        if not proof or proof.count(".") != 2:
            return None

        try:
            header, payload, sig = self._decode_jwt_parts(proof)
        except Exception:
            return None

        # Stack 1-3 mutations for cross-field interaction coverage
        n_mutations = random.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        methods, weights = zip(*self._methods)
        applied: list[str] = []
        for _ in range(n_mutations):
            chosen = random.choices(methods, weights=weights, k=1)[0]
            chosen(header, payload, new_data)
            applied.append(chosen.__name__.lstrip("_"))

        new_data["proof_jwt"] = self._encode_jwt_parts(header, payload, sig)

        result = json.dumps(new_data, ensure_ascii=False).encode("utf-8")
        if len(result) > 8192:
            return None
        return Input(result, metadata={"strategy": self.name, "dpop_mutations": applied})

    @staticmethod
    def _b64url_decode(s: str) -> bytes:
        s = s.replace("-", "+").replace("_", "/")
        pad = 4 - len(s) % 4
        if pad != 4:
            s += "=" * pad
        import base64
        return base64.b64decode(s)

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _decode_jwt_parts(self, jwt_str: str) -> tuple[dict, dict, str]:
        parts = jwt_str.split(".")
        header = json.loads(self._b64url_decode(parts[0]))
        payload = json.loads(self._b64url_decode(parts[1]))
        return header, payload, parts[2]

    def _encode_jwt_parts(self, header: dict, payload: dict, sig: str) -> str:
        h = self._b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        return f"{h}.{p}.{sig}"

    # ── D1-D8: field-level mutations ──────────────────────────────

    def _mutate_htm(self, header: dict, payload: dict, data: dict) -> None:
        """D1: htm case/whitespace variation."""
        htm = payload.get("htm", "POST")
        choice = random.choice(["lower", "mixed", "space", "swap", "tab", "null"])
        if choice == "lower":
            payload["htm"] = htm.lower()
        elif choice == "mixed":
            payload["htm"] = htm[0] + htm[1:].lower()
        elif choice == "space":
            payload["htm"] = " " + htm
        elif choice == "swap":
            payload["htm"] = random.choice(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
        elif choice == "tab":
            payload["htm"] = "\t" + htm
        elif choice == "null":
            payload["htm"] = htm + "\x00"

    def _mutate_htu(self, header: dict, payload: dict, data: dict) -> None:
        """D2: htu normalization (port, case, encoding, trailing slash)."""
        htu = payload.get("htu", "")
        if not htu:
            return
        choice = random.choice(["port", "case", "encode", "slash", "query", "fragment"])
        if choice == "port":
            if "://example.com/" in htu and ":443" not in htu:
                payload["htu"] = htu.replace("://example.com/", "://example.com:443/", 1)
        elif choice == "case":
            payload["htu"] = htu.upper()
        elif choice == "encode":
            payload["htu"] = htu.replace("/token", "/%74oken", 1) if "/token" in htu else htu
        elif choice == "slash":
            payload["htu"] = htu.rstrip("/") + "/" if not htu.endswith("/") else htu.rstrip("/")
        elif choice == "query":
            payload["htu"] = htu + "?ignored=1"
        elif choice == "fragment":
            payload["htu"] = htu + "#frag"
        if random.random() < 0.3:
            data["http_uri"] = payload["htu"]

    def _mutate_ath(self, header: dict, payload: dict, data: dict) -> None:
        """D3: ath (access token hash) padding/corruption."""
        ath = payload.get("ath", "")
        if not ath:
            return
        choice = random.choice(["pad", "strip", "corrupt", "std_b64", "double_pad", "empty"])
        if choice == "pad":
            payload["ath"] = ath.rstrip("=") + "="
        elif choice == "strip":
            payload["ath"] = ath.rstrip("=")
        elif choice == "corrupt":
            if len(ath) > 2:
                pos = random.randint(0, len(ath) - 1)
                payload["ath"] = ath[:pos] + ("A" if ath[pos] != "A" else "B") + ath[pos + 1:]
        elif choice == "std_b64":
            payload["ath"] = ath.replace("-", "+").replace("_", "/")
        elif choice == "double_pad":
            payload["ath"] = ath.rstrip("=") + "=="
        elif choice == "empty":
            payload["ath"] = ""

    def _mutate_iat(self, header: dict, payload: dict, data: dict) -> None:
        """D4: iat timestamp edge cases."""
        import time
        choice = random.choice(["future", "expired", "zero", "huge", "string", "remove", "float", "negative"])
        if choice == "future":
            payload["iat"] = int(time.time()) + 86400
        elif choice == "expired":
            payload["iat"] = int(time.time()) - 86400
        elif choice == "zero":
            payload["iat"] = 0
        elif choice == "huge":
            payload["iat"] = 9999999999
        elif choice == "string":
            payload["iat"] = str(int(time.time()))
        elif choice == "remove":
            payload.pop("iat", None)
        elif choice == "float":
            payload["iat"] = time.time()
        elif choice == "negative":
            payload["iat"] = -1

    def _mutate_jti(self, header: dict, payload: dict, data: dict) -> None:
        """D5: jti uniqueness/format edge cases."""
        choice = random.choice(["empty", "long", "remove", "numeric", "special", "bool", "array"])
        if choice == "empty":
            payload["jti"] = ""
        elif choice == "long":
            payload["jti"] = "a" * 1024
        elif choice == "remove":
            payload.pop("jti", None)
        elif choice == "numeric":
            payload["jti"] = 12345
        elif choice == "special":
            payload["jti"] = "jti\x00with\nnull"
        elif choice == "bool":
            payload["jti"] = True
        elif choice == "array":
            payload["jti"] = ["id1", "id2"]

    def _mutate_nonce(self, header: dict, payload: dict, data: dict) -> None:
        """D6: DPoP nonce presence/absence/value."""
        choice = random.choice(["remove", "empty", "wrong", "add", "numeric", "null"])
        if choice == "remove":
            payload.pop("nonce", None)
            data.pop("server_nonce", None)
        elif choice == "empty":
            payload["nonce"] = ""
        elif choice == "wrong":
            payload["nonce"] = "wrong_nonce_value"
        elif choice == "add":
            payload["nonce"] = "server-nonce-123"
            data["server_nonce"] = "server-nonce-123"
        elif choice == "numeric":
            payload["nonce"] = 999
        elif choice == "null":
            payload["nonce"] = None

    def _mutate_typ(self, header: dict, payload: dict, data: dict) -> None:
        """D7: DPoP typ header variations."""
        choice = random.choice(["jwt", "remove", "wrong", "case", "space", "null_byte"])
        if choice == "jwt":
            header["typ"] = "JWT"
        elif choice == "remove":
            header.pop("typ", None)
        elif choice == "wrong":
            header["typ"] = "at+jwt"
        elif choice == "case":
            header["typ"] = random.choice(["dpop+jwt", "DPoP+jwt", "DPOP+JWT", "dpop+JWT"])
        elif choice == "space":
            header["typ"] = " dpop+jwt"
        elif choice == "null_byte":
            header["typ"] = "dpop+jwt\x00"

    def _mutate_alg(self, header: dict, payload: dict, data: dict) -> None:
        """D8: Algorithm confusion attacks."""
        header["alg"] = random.choice([
            "none", "None", "NONE", "nOnE",
            "HS256", "HS384", "HS512",
            "RS256", "ES256", "PS256", "EdDSA",
            "", "unknown", " ES256", "ES256\x00",
        ])

    # ── D9-D16: JWT-structural mutations ──────────────────────────

    def _mutate_jwk_embed(self, header: dict, payload: dict, data: dict) -> None:
        """D9: Embed self-signed JWK in header — test whether implementations
        trust embedded keys vs require pre-registered keys."""
        choice = random.choice(["oct_key", "rsa_pub", "ec_pub", "missing_kty"])
        if choice == "oct_key":
            header["jwk"] = {"kty": "oct", "k": self._b64url_encode(b"attacker-secret")}
            header["alg"] = "HS256"
        elif choice == "rsa_pub":
            header["jwk"] = {
                "kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM",
                "e": "AQAB", "kid": "attacker-rsa",
            }
            header["alg"] = "RS256"
        elif choice == "ec_pub":
            header["jwk"] = {
                "kty": "EC", "crv": "P-256",
                "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            }
            header["alg"] = "ES256"
        elif choice == "missing_kty":
            header["jwk"] = {"n": "abc", "e": "AQAB"}

    def _mutate_jwk_privkey(self, header: dict, payload: dict, data: dict) -> None:
        """D10: Embed private key material in jwk — RFC 9449 §4.3 MUST reject.
        Tests whether implementations detect and reject private key fields."""
        header["jwk"] = {
            "kty": "EC", "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d": "jpsQnnGQmL-YBIffS1BSyVKhrlRhFpJ8sHAk-SRkGEY",
        }
        header["alg"] = "ES256"
        if random.random() < 0.3:
            header["jwk"] = {
                "kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM",
                "e": "AQAB",
                "d": "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH",
                "p": "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQ",
                "q": "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuq",
            }

    def _mutate_kid_inject(self, header: dict, payload: dict, data: dict) -> None:
        """D11: kid injection in DPoP header — path traversal, SQL, null byte."""
        header["kid"] = random.choice([
            "../../../../dev/null",
            "' UNION SELECT 'secret' --",
            "key-1\x00../../etc/passwd",
            "",
            "../../../proc/self/environ",
            "key\nnewline",
        ])

    def _mutate_b64url_edge(self, header: dict, payload: dict, data: dict) -> None:
        """D12: base64url encoding edge cases in JWT segments."""
        proof = data.get("proof_jwt", "")
        if not proof or proof.count(".") != 2:
            return
        parts = proof.split(".")
        choice = random.choice(["padding", "std_chars", "whitespace", "bom"])
        if choice == "padding":
            parts[1] = parts[1].rstrip("=") + "="
        elif choice == "std_chars":
            parts[1] = parts[1].replace("-", "+").replace("_", "/")
        elif choice == "whitespace":
            if len(parts[0]) > 4:
                pos = random.randint(2, len(parts[0]) - 2)
                ws = random.choice([" ", "\n", "\t"])
                parts[0] = parts[0][:pos] + ws + parts[0][pos:]
        elif choice == "bom":
            try:
                raw = self._b64url_decode(parts[1])
                raw = b"\xef\xbb\xbf" + raw
                parts[1] = self._b64url_encode(raw)
            except Exception:
                pass
        data["proof_jwt"] = ".".join(parts)

    def _mutate_htu_deep(self, header: dict, payload: dict, data: dict) -> None:
        """D13: Deep htu normalization tricks — targets urllib vs WHATWG URL divergence.

        These exploit known differences between Python's urllib.parse.urlparse
        and Node's WHATWG URL (new URL()) for htu comparison.
        """
        htu = payload.get("htu", "https://auth.example.com/token")
        choice = random.choice([
            "backslash",       # urllib keeps \, WHATWG normalizes to /
            "ipv6",            # bracket handling differences
            "idn",             # internationalized domain names
            "double_encode",   # %25xx double encoding
            "dot_segments",    # /./  and /../ resolution
            "empty_port",      # :  with no port number
            "port_80_https",   # :80 on https (not default, but sometimes stripped)
            "tab_newline",     # \t, \n in URL — WHATWG strips, urllib keeps
            "userinfo",        # user:pass@ — handling differs
            "unicode_host",    # non-ASCII in host
        ])
        if choice == "backslash":
            payload["htu"] = htu.replace("/token", "\\token", 1)
        elif choice == "ipv6":
            payload["htu"] = htu.replace("auth.example.com", "[::1]", 1)
        elif choice == "idn":
            payload["htu"] = htu.replace("auth.example.com", "auth.ex\u00e4mple.com", 1)
        elif choice == "double_encode":
            payload["htu"] = htu.replace("/token", "/%2574oken", 1)
        elif choice == "dot_segments":
            payload["htu"] = htu.replace("/token", "/./token", 1)
            if random.random() < 0.5:
                payload["htu"] = htu.replace("/token", "/dummy/../token", 1)
        elif choice == "empty_port":
            payload["htu"] = htu.replace("example.com", "example.com:", 1)
        elif choice == "port_80_https":
            payload["htu"] = htu.replace("example.com", "example.com:80", 1)
        elif choice == "tab_newline":
            ch = random.choice(["\t", "\n", "\r"])
            payload["htu"] = htu[:8] + ch + htu[8:]
        elif choice == "userinfo":
            payload["htu"] = htu.replace("://", "://admin@", 1)
        elif choice == "unicode_host":
            payload["htu"] = htu.replace("example.com", "example\u200b.com", 1)
        if random.random() < 0.4:
            data["http_uri"] = payload["htu"]

    def _mutate_extra_claims(self, header: dict, payload: dict, data: dict) -> None:
        """D14: Extra/duplicate DPoP payload claims — spec doesn't forbid extras."""
        choice = random.choice(["case_htm", "case_htu", "extra_sub", "extra_iss", "cnf"])
        if choice == "case_htm":
            payload["HTM"] = payload.get("htm", "POST")
        elif choice == "case_htu":
            payload["HTU"] = payload.get("htu", "")
        elif choice == "extra_sub":
            payload["sub"] = "attacker@evil.com"
        elif choice == "extra_iss":
            payload["iss"] = "https://evil.com"
        elif choice == "cnf":
            payload["cnf"] = {"jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}

    def _mutate_envelope(self, header: dict, payload: dict, data: dict) -> None:
        """D15: JSON envelope mutations — extra fields, type confusion."""
        choice = random.choice([
            "extra_field", "remove_method", "remove_uri", "swap_type",
            "null_token", "array_method",
        ])
        if choice == "extra_field":
            data["extra_ignored"] = "should_be_ignored"
        elif choice == "remove_method":
            data.pop("http_method", None)
        elif choice == "remove_uri":
            data.pop("http_uri", None)
        elif choice == "swap_type":
            data["type"] = random.choice(["dpop_proof", "DPoP_proof", "dpop", "jwt"])
        elif choice == "null_token":
            data["access_token"] = None
        elif choice == "array_method":
            data["http_method"] = ["POST", "GET"]

    def _mutate_header_dupes(self, header: dict, payload: dict, data: dict) -> None:
        """D16: Craft raw JWT with duplicate header keys (first-wins vs last-wins).
        Since Python dicts can't hold dupes, we build the raw JWT string directly."""
        proof = data.get("proof_jwt", "")
        if not proof or proof.count(".") != 2:
            return
        parts = proof.split(".")
        try:
            hdr_json = self._b64url_decode(parts[0]).decode("utf-8")
        except Exception:
            return
        choice = random.choice(["dup_alg", "dup_typ"])
        if choice == "dup_alg":
            inject = '"alg":"none",'
            if hdr_json.startswith("{"):
                hdr_json = "{" + inject + hdr_json[1:]
        elif choice == "dup_typ":
            inject = '"typ":"JWT",'
            if hdr_json.startswith("{"):
                hdr_json = "{" + inject + hdr_json[1:]
        parts[0] = self._b64url_encode(hdr_json.encode("utf-8"))
        data["proof_jwt"] = ".".join(parts)


class OAuthMutator:
    """Main OAuth mutator — combines all strategies."""

    name = "oauth"

    def __init__(self, seed: int | None = None):
        if seed is not None:
            random.seed(seed)
        self.strategies: list[OAuthMutationStrategy] = [
            O1_RedirectUriNormStrategy(),
            O2_RedirectUriAttackStrategy(),
            O3_ScopeWhitespaceStrategy(),
            O4_ScopeSemanticStrategy(),
            O5_TypeSwitchStrategy(),
            O6_UnicodeEncodingStrategy(),
            O7_PKCEStrategy(),
            O8_TokenRequestStrategy(),
            O9_TokenResponseStrategy(),
            O10_TokenExchangeRedirectStrategy(),
            O11_DPoPProofStrategy(),
        ]
        self._strategy_names = [s.name for s in self.strategies]
        self._base_weights = [10] * len(self.strategies)
        self._weights = list(self._base_weights)
        self._strategy_finds: list[int] = [0] * len(self.strategies)
        self._strategy_cov: list[int] = [0] * len(self.strategies)
        self._total_feedback_calls: int = 0

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        # Weighted selection instead of random shuffle
        indices = list(range(len(self.strategies)))
        random.shuffle(indices)
        # Sort by weight descending so higher-weight strategies are tried first
        indices.sort(key=lambda i: self._weights[i], reverse=True)
        for i in indices:
            result = self.strategies[i].mutate(inp, corpus)
            if result is not None:
                return result
        # Fallback: random byte mutation
        data = bytearray(inp.data)
        if data:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        return Input(bytes(data), metadata={"strategy": "fallback"})

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
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 4, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "stage_up":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] * 15 // 100, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "coverage":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 10, 1),
                self._base_weights[idx] * 3,
            )

        if self._total_feedback_calls % 1000 == 0:
            for i in range(len(self.strategies)):
                if self._strategy_finds[i] == 0 and self._strategy_cov[i] == 0:
                    self._weights[i] = max(self._weights[i] - 1, 1)

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset dynamic weights — called by engine on stall detection."""
        if boost_zero_finds:
            for i in range(len(self.strategies)):
                if self._strategy_finds[i] == 0:
                    self._weights[i] = min(
                        self._base_weights[i] + max(self._base_weights[i] // 3, 1),
                        self._base_weights[i] * 2,
                    )
                else:
                    self._weights[i] = self._base_weights[i]
        else:
            self._weights = list(self._base_weights)
