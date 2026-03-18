"""JWT domain plugin for property-learning concolic layer.

Extracts ~30 structural properties from JWT tokens (base64-encoded JSON)
and provides perturbation operators for each.
"""

from __future__ import annotations

import base64
import json
import math
import random
import re
from collections import Counter
from typing import Any

from ..domain_plugin import DomainPlugin
from ..property_vector import PropertyVector

NUM_JWT_PROPERTIES = 30

JWT_PROPERTY_NAMES: tuple[str, ...] = (
    # Size (3)
    "total_bytes",          # 0
    "num_segments",         # 1 — number of dot-separated segments
    "payload_size_ratio",   # 2 — payload segment size / total
    # Header (7)
    "alg_present",          # 3
    "alg_is_none",          # 4 — alg=none/None/NONE
    "alg_is_hmac",          # 5 — HS256/HS384/HS512
    "alg_is_rsa",           # 6 — RS/PS variants
    "alg_is_ec",            # 7 — ES variants
    "typ_present",          # 8
    "kid_present",          # 9
    # Header exotic (4)
    "jku_present",          # 10 — JSON Key URL
    "jwk_present",          # 11 — embedded key
    "x5u_present",          # 12 — X.509 URL
    "crit_present",         # 13 — critical header
    # Payload claims (8)
    "sub_present",          # 14
    "iss_present",          # 15
    "aud_present",          # 16
    "exp_present",          # 17
    "nbf_present",          # 18
    "iat_present",          # 19
    "claim_count",          # 20 — total claims
    "nested_jwt_present",   # 21 — JWT inside claim value
    # Structure (5)
    "has_duplicate_header_keys",  # 22
    "has_duplicate_claim_keys",   # 23
    "b64_padding_present",  # 24 — '=' in base64
    "non_standard_b64",     # 25 — base64url vs standard
    "signature_length",     # 26 — normalized
    # Encoding (3)
    "header_entropy",       # 27 — decoded header byte entropy
    "payload_entropy",      # 28 — decoded payload byte entropy
    "has_unicode",          # 29 — non-ASCII in decoded payload
)

assert len(JWT_PROPERTY_NAMES) == NUM_JWT_PROPERTIES


def _safe_b64_decode(s: bytes) -> bytes:
    """Decode base64url with padding tolerance."""
    s = s.replace(b"-", b"+").replace(b"_", b"/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += b"=" * pad
    try:
        return base64.b64decode(s)
    except Exception:
        return b""


def _safe_json(data: bytes) -> dict[str, Any]:
    try:
        return json.loads(data)
    except Exception:
        return {}


class JwtPlugin(DomainPlugin):
    """JWT-specific property extraction and perturbation."""

    def extract(self, data: bytes) -> PropertyVector:
        v = [0.0] * NUM_JWT_PROPERTIES
        text = data.strip()

        # Split segments
        parts = text.split(b".")
        num_seg = len(parts)

        # Size
        v[0] = min(len(text) / 5000.0, 1.0)
        v[1] = min(num_seg / 5.0, 1.0)
        if num_seg >= 2 and len(text) > 0:
            v[2] = len(parts[1]) / len(text)

        # Decode header + payload
        header_raw = _safe_b64_decode(parts[0]) if num_seg >= 1 else b""
        payload_raw = _safe_b64_decode(parts[1]) if num_seg >= 2 else b""
        header = _safe_json(header_raw)
        payload = _safe_json(payload_raw)

        # Header fields
        alg = str(header.get("alg", "")).lower()
        v[3] = 1.0 if "alg" in header else 0.0
        v[4] = 1.0 if alg in ("none", "none", "") else 0.0
        v[5] = 1.0 if alg.startswith("hs") else 0.0
        v[6] = 1.0 if alg.startswith("rs") or alg.startswith("ps") else 0.0
        v[7] = 1.0 if alg.startswith("es") else 0.0
        v[8] = 1.0 if "typ" in header else 0.0
        v[9] = 1.0 if "kid" in header else 0.0

        # Header exotic
        v[10] = 1.0 if "jku" in header else 0.0
        v[11] = 1.0 if "jwk" in header else 0.0
        v[12] = 1.0 if "x5u" in header else 0.0
        v[13] = 1.0 if "crit" in header else 0.0

        # Payload claims
        v[14] = 1.0 if "sub" in payload else 0.0
        v[15] = 1.0 if "iss" in payload else 0.0
        v[16] = 1.0 if "aud" in payload else 0.0
        v[17] = 1.0 if "exp" in payload else 0.0
        v[18] = 1.0 if "nbf" in payload else 0.0
        v[19] = 1.0 if "iat" in payload else 0.0
        v[20] = min(len(payload) / 20.0, 1.0)
        # Nested JWT detection
        for val in payload.values():
            if isinstance(val, str) and val.count(".") == 2 and len(val) > 20:
                v[21] = 1.0
                break

        # Structure
        v[22] = 1.0 if _has_dup_keys(header_raw) else 0.0
        v[23] = 1.0 if _has_dup_keys(payload_raw) else 0.0
        v[24] = 1.0 if b"=" in text else 0.0
        v[25] = 1.0 if b"+" in text or b"/" in text else 0.0
        if num_seg >= 3:
            v[26] = min(len(parts[2]) / 500.0, 1.0)

        # Encoding
        v[27] = _byte_entropy(header_raw)
        v[28] = _byte_entropy(payload_raw)
        v[29] = 1.0 if any(b > 127 for b in payload_raw) else 0.0

        return PropertyVector(tuple(v))

    @property
    def property_names(self) -> tuple[str, ...]:
        return JWT_PROPERTY_NAMES

    @property
    def num_properties(self) -> int:
        return NUM_JWT_PROPERTIES

    def perturb(self, data: bytes, prop_idx: int, rng: random.Random) -> list[bytes]:
        fn_list = _JWT_PERTURBATIONS.get(prop_idx, [])
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
            "alg_none": 4, "alg_hmac": 5, "alg_rsa": 6, "alg_ec": 7,
            "typ": 8, "kid": 9, "jku": 10, "jwk": 11, "crit": 13,
            "sub": 14, "iss": 15, "aud": 16, "exp": 17, "nbf": 18,
            "claim_count": 20, "nested_jwt": 21,
            "dup_header": 22, "dup_claims": 23, "b64_padding": 24,
            "signature": 26, "num_segments": 1,
            # Aliases from AST analyzer
            "encoding_decl": 24, "tag_count": 20,
            "assertion_count": 20, "issuer": 15, "audience": 16,
            "nameid_format": 14, "subject": 14,
        }


# ── Helpers ──────────────────────────────────────────────────────

def _has_dup_keys(raw_json: bytes) -> bool:
    """Check if JSON has duplicate keys (crude regex)."""
    keys = re.findall(rb'"(\w+)"\s*:', raw_json)
    return len(keys) != len(set(keys))


def _byte_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = Counter(buf)
    n = len(buf)
    entropy = 0.0
    for f in counts.values():
        p = f / n
        entropy -= p * math.log2(p)
    return entropy / 8.0


def _modify_header(data: bytes, key: str, value: Any, rng: random.Random) -> list[bytes]:
    """Decode JWT header, modify a key, re-encode."""
    parts = data.strip().split(b".")
    if len(parts) < 2:
        return []
    header_raw = _safe_b64_decode(parts[0])
    header = _safe_json(header_raw)
    if not header:
        return []
    header[key] = value
    new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
    return [new_header + b"." + b".".join(parts[1:])]


def _modify_payload(data: bytes, key: str, value: Any, rng: random.Random) -> list[bytes]:
    """Decode JWT payload, modify a key, re-encode."""
    parts = data.strip().split(b".")
    if len(parts) < 2:
        return []
    payload_raw = _safe_b64_decode(parts[1])
    payload = _safe_json(payload_raw)
    if not isinstance(payload, dict):
        return []
    payload[key] = value
    new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    return [parts[0] + b"." + new_payload + (b"." + b".".join(parts[2:]) if len(parts) > 2 else b".")]


# ── Perturbation functions ────────────────────────────────────────

def _perturb_alg_none(data: bytes, rng: random.Random) -> list[bytes]:
    variants = ["none", "None", "NONE", "nOnE"]
    return _modify_header(data, "alg", rng.choice(variants), rng)


def _perturb_alg_hmac(data: bytes, rng: random.Random) -> list[bytes]:
    variants = ["HS256", "HS384", "HS512"]
    return _modify_header(data, "alg", rng.choice(variants), rng)


def _perturb_alg_rsa(data: bytes, rng: random.Random) -> list[bytes]:
    variants = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
    return _modify_header(data, "alg", rng.choice(variants), rng)


def _perturb_alg_ec(data: bytes, rng: random.Random) -> list[bytes]:
    variants = ["ES256", "ES384", "ES512"]
    return _modify_header(data, "alg", rng.choice(variants), rng)


def _perturb_typ(data: bytes, rng: random.Random) -> list[bytes]:
    results = _modify_header(data, "typ", rng.choice(["JWT", "jwt", "at+jwt", ""]), rng)
    # Also try removing typ
    parts = data.strip().split(b".")
    if len(parts) >= 2:
        header = _safe_json(_safe_b64_decode(parts[0]))
        if "typ" in header:
            del header["typ"]
            new_h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
            results.append(new_h + b"." + b".".join(parts[1:]))
    return results


def _perturb_kid(data: bytes, rng: random.Random) -> list[bytes]:
    kids = ["kid-1", "../key", "../../etc/passwd", "", "kid-" + str(rng.randint(1, 99))]
    return _modify_header(data, "kid", rng.choice(kids), rng)


def _perturb_jku(data: bytes, rng: random.Random) -> list[bytes]:
    urls = ["https://evil.com/.well-known/jwks.json", "http://localhost/jwks",
            "https://issuer.example/.well-known/jwks.json"]
    return _modify_header(data, "jku", rng.choice(urls), rng)


def _perturb_jwk(data: bytes, rng: random.Random) -> list[bytes]:
    jwk = {"kty": "RSA", "n": "AAAA", "e": "AQAB"}
    return _modify_header(data, "jwk", jwk, rng)


def _perturb_crit(data: bytes, rng: random.Random) -> list[bytes]:
    crits = [["b64"], ["x-custom"], ["alg"], []]
    return _modify_header(data, "crit", rng.choice(crits), rng)


def _perturb_sub(data: bytes, rng: random.Random) -> list[bytes]:
    subs = ["admin", "user-123", "", "../../admin", "user-123\x00admin"]
    return _modify_payload(data, "sub", rng.choice(subs), rng)


def _perturb_iss(data: bytes, rng: random.Random) -> list[bytes]:
    issuers = ["https://evil.com", "", "https://issuer.example", "null"]
    return _modify_payload(data, "iss", rng.choice(issuers), rng)


def _perturb_aud(data: bytes, rng: random.Random) -> list[bytes]:
    auds = ["https://evil.com", ["https://api.example", "https://evil.com"], "", None]
    return _modify_payload(data, "aud", rng.choice(auds), rng)


def _perturb_exp(data: bytes, rng: random.Random) -> list[bytes]:
    results: list[bytes] = []
    results.extend(_modify_payload(data, "exp", 0, rng))
    results.extend(_modify_payload(data, "exp", 9999999999, rng))
    results.extend(_modify_payload(data, "exp", "1704067200", rng))  # string
    return results


def _perturb_nbf(data: bytes, rng: random.Random) -> list[bytes]:
    results: list[bytes] = []
    results.extend(_modify_payload(data, "nbf", 9999999999, rng))  # far future
    results.extend(_modify_payload(data, "nbf", 0, rng))
    return results


def _perturb_claim_count(data: bytes, rng: random.Random) -> list[bytes]:
    """Add extra claims."""
    extras = {"admin": True, "role": "admin", "scope": "admin:*",
              "groups": ["admins"], "x-custom": "value"}
    key = rng.choice(list(extras.keys()))
    return _modify_payload(data, key, extras[key], rng)


def _perturb_nested_jwt(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject a nested JWT in a claim."""
    nested = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    return _modify_payload(data, "inner_token", nested, rng)


def _perturb_dup_header_keys(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject duplicate keys in header JSON."""
    parts = data.strip().split(b".")
    if len(parts) < 2:
        return []
    header_raw = _safe_b64_decode(parts[0])
    # Crude: just inject duplicate "alg" before closing brace
    if b'"alg"' in header_raw and header_raw.endswith(b"}"):
        dup = header_raw[:-1] + b',"alg":"none"}'
        new_h = base64.urlsafe_b64encode(dup).rstrip(b"=")
        return [new_h + b"." + b".".join(parts[1:])]
    return []


def _perturb_dup_claim_keys(data: bytes, rng: random.Random) -> list[bytes]:
    parts = data.strip().split(b".")
    if len(parts) < 2:
        return []
    payload_raw = _safe_b64_decode(parts[1])
    if b'"sub"' in payload_raw and payload_raw.endswith(b"}"):
        dup = payload_raw[:-1] + b',"sub":"admin"}'
        new_p = base64.urlsafe_b64encode(dup).rstrip(b"=")
        return [parts[0] + b"." + new_p + (b"." + b".".join(parts[2:]) if len(parts) > 2 else b".")]
    return []


def _perturb_b64_padding(data: bytes, rng: random.Random) -> list[bytes]:
    """Toggle base64 padding."""
    if b"=" in data:
        return [data.replace(b"=", b"")]
    # Add padding
    parts = data.strip().split(b".")
    results: list[bytes] = []
    for i, p in enumerate(parts):
        pad = 4 - len(p) % 4
        if pad != 4:
            padded = list(parts)
            padded[i] = p + b"=" * pad
            results.append(b".".join(padded))
    return results[:1]


def _perturb_signature(data: bytes, rng: random.Random) -> list[bytes]:
    """Modify signature segment."""
    parts = data.strip().split(b".")
    if len(parts) < 3:
        return []
    results: list[bytes] = []
    # Empty signature
    results.append(parts[0] + b"." + parts[1] + b".")
    # Random signature
    sig = base64.urlsafe_b64encode(rng.randbytes(32)).rstrip(b"=")
    results.append(parts[0] + b"." + parts[1] + b"." + sig)
    return results


def _perturb_num_segments(data: bytes, rng: random.Random) -> list[bytes]:
    """Change number of dot-separated segments."""
    parts = data.strip().split(b".")
    results: list[bytes] = []
    # 2 segments (no signature)
    if len(parts) >= 3:
        results.append(parts[0] + b"." + parts[1])
    # 4 segments
    results.append(data.strip() + b".extra")
    return results


# ── Perturbation registry ──────────────────────────────────────────

_JWT_PERTURBATIONS: dict[int, list] = {
    1:  [_perturb_num_segments],         # num_segments
    3:  [_perturb_alg_none],             # alg_present
    4:  [_perturb_alg_none],             # alg_is_none
    5:  [_perturb_alg_hmac],             # alg_is_hmac
    6:  [_perturb_alg_rsa],              # alg_is_rsa
    7:  [_perturb_alg_ec],               # alg_is_ec
    8:  [_perturb_typ],                  # typ_present
    9:  [_perturb_kid],                  # kid_present
    10: [_perturb_jku],                  # jku_present
    11: [_perturb_jwk],                  # jwk_present
    12: [_perturb_jku],                  # x5u_present (reuse jku)
    13: [_perturb_crit],                 # crit_present
    14: [_perturb_sub],                  # sub_present
    15: [_perturb_iss],                  # iss_present
    16: [_perturb_aud],                  # aud_present
    17: [_perturb_exp],                  # exp_present
    18: [_perturb_nbf],                  # nbf_present
    20: [_perturb_claim_count],          # claim_count
    21: [_perturb_nested_jwt],           # nested_jwt_present
    22: [_perturb_dup_header_keys],      # has_duplicate_header_keys
    23: [_perturb_dup_claim_keys],       # has_duplicate_claim_keys
    24: [_perturb_b64_padding],          # b64_padding_present
    26: [_perturb_signature],            # signature_length
}
