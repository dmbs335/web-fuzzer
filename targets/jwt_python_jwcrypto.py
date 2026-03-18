"""JWT target -- Python jwcrypto strict RFC 7519 verifier.

Uses the real jwcrypto library for strict verification.
Emits same JSON schema as other JWT targets for differential comparison.
Exit 0 = processed (even if signature invalid), Exit 1 = parse failure.
"""

from __future__ import annotations

import base64
import json
import sys
import time

from jwcrypto import jwk, jwt as jwcrypto_jwt
from jwcrypto.common import JWException

DEFAULT_HS_SECRET = b"secret"


def _b64url_decode(data: str) -> bytes:
    raw = data.encode("ascii")
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw)


def _parse_json_with_duplicates(raw: bytes) -> tuple[dict, list[str]]:
    duplicates: list[str] = []

    def hook(pairs):
        result = {}
        seen: set[str] = set()
        for key, value in pairs:
            if key in seen:
                duplicates.append(key)
            seen.add(key)
            result[key] = value
        return result

    obj = json.loads(raw.decode("utf-8"), object_pairs_hook=hook)
    if not isinstance(obj, dict):
        raise ValueError("JWT segment is not a JSON object")
    return obj, sorted(set(duplicates))


def _classify_time(payload: dict, now: int) -> tuple[bool, str, str, str]:
    time_valid = True

    def classify(name: str, mode: str) -> str:
        nonlocal time_valid
        if name not in payload:
            return "missing"
        value = payload[name]
        if not isinstance(value, (int, float)):
            time_valid = False
            return "invalid_type"
        if mode == "exp":
            if now >= int(value):
                time_valid = False
                return "expired"
            return "valid"
        if mode == "nbf":
            if now < int(value):
                time_valid = False
                return "not_yet_valid"
            return "valid"
        if mode == "iat":
            if now + 300 < int(value):
                time_valid = False
                return "future"
            return "valid"
        return "missing"

    return time_valid, classify("exp", "exp"), classify("nbf", "nbf"), classify("iat", "iat")


def _claim_types(payload: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    for key in ("sub", "iss", "aud", "role", "scope", "exp", "nbf", "iat"):
        if key in payload:
            result[key] = type(payload[key]).__name__
    return result


def verify_jwt(token: str) -> str:
    raw = token.strip()
    parts = raw.split(".")
    token_type_observed = "jws" if len(parts) == 3 else "jwe" if len(parts) == 5 else "unknown"
    token_type_expected = "jws"

    if len(parts) < 2:
        raise ValueError("JWT must contain at least header and payload segments")

    # Pre-parse header/payload for observability (before library verification)
    header_raw = _b64url_decode(parts[0])
    header, duplicate_header_keys = _parse_json_with_duplicates(header_raw)

    # For 3-segment JWS, parse payload directly; for JWE we defer
    payload: dict = {}
    duplicate_claim_keys: list[str] = []
    if len(parts) >= 2:
        try:
            payload_raw = _b64url_decode(parts[1])
            payload, duplicate_claim_keys = _parse_json_with_duplicates(payload_raw)
        except Exception:
            pass

    header_alg = str(header.get("alg") or "")
    typ = header.get("typ")
    cty = header.get("cty")
    crit = header.get("crit")
    b64_mode = "unencoded" if header.get("b64") is False else "normal"

    signature_valid = False
    signature_error = None
    key_source = "configured"
    effective_alg = header_alg
    crit_processed = None
    nested_jwt = bool(cty == "JWT" or isinstance(payload.get("nested"), str))
    inner_alg = None
    inner_signature_valid = None

    # Determine key source from header
    if header.get("jku"):
        key_source = "jku"
    elif header.get("jwk"):
        key_source = "embedded_jwk"
    elif header.get("x5u"):
        key_source = "x5u"
    elif header.get("x5c"):
        key_source = "x5c"

    # Attempt verification with jwcrypto
    try:
        key = jwk.JWK(kty="oct", k=base64.urlsafe_b64encode(DEFAULT_HS_SECRET).rstrip(b"=").decode())
        tok = jwcrypto_jwt.JWT(
            jwt=raw,
            key=key,
            algs=["HS256", "HS384", "HS512"],
        )
        # If we reach here, verification succeeded
        signature_valid = True
        effective_alg = header_alg
        # jwcrypto processes crit headers
        if crit is not None:
            crit_processed = True
    except JWException as e:
        signature_error = f"{type(e).__name__}: {str(e)[:200]}"
        if crit is not None:
            # jwcrypto rejects unsupported crit — but it did process them
            crit_processed = True
    except Exception as e:
        signature_error = f"{type(e).__name__}: {str(e)[:200]}"
        if crit is not None:
            crit_processed = None

    now = int(time.time())
    time_valid, exp_state, nbf_state, iat_state = _classify_time(payload, now)

    result = {
        "signature_valid": signature_valid,
        "signature_error": signature_error,
        "header_alg": header_alg,
        "effective_alg": effective_alg,
        "key_source": key_source,
        "resolved_kid": header.get("kid"),
        "jwk_source": "embedded" if "jwk" in header else None,
        "jku_source": header.get("jku"),
        "x5u_source": header.get("x5u"),
        "token_type_expected": token_type_expected,
        "token_type_observed": token_type_observed,
        "typ": typ,
        "cty": cty,
        "crit_processed": crit_processed,
        "b64_mode": b64_mode,
        "detached_payload_used": False,
        "sub": payload.get("sub"),
        "iss": payload.get("iss"),
        "aud": payload.get("aud"),
        "role": payload.get("role"),
        "scope": payload.get("scope"),
        "claim_types": _claim_types(payload),
        "duplicate_header_keys": duplicate_header_keys,
        "duplicate_claim_keys": duplicate_claim_keys,
        "claim_parse_mode": "last_wins",
        "time_valid": time_valid,
        "exp_state": exp_state,
        "nbf_state": nbf_state,
        "iat_state": iat_state,
        "nested_jwt": nested_jwt,
        "inner_alg": inner_alg,
        "inner_signature_valid": inner_signature_valid,
    }
    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: jwt_python_jwcrypto.py <input_file>", file=sys.stderr)
        sys.exit(2)
    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        print(verify_jwt(data))
        sys.exit(0)
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
