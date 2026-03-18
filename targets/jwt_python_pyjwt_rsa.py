"""JWT target -- Python PyJWT RSA verifier.

Configured with RS256 + RSA public key. Enables testing:
  §1-2 Algorithm Confusion (RS256→HS256 with public key as HMAC secret)
  §2-3 Embedded JWK self-signed tokens
  §2-4 Self-signed x5c certificates
  §7-1 JWS/JWE confusion
"""

from __future__ import annotations

import base64
import json
import sys
import time

import jwt as pyjwt

RSA_PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmYZu2CPMrFIitVfZx11f
S9iPLlOuS5yFApFK4/kbyNEWt2aGEI3pgs36GB9uodriS4wVAk+Y/f59fSn0kwjJ
ptFI4Jqvq+96ncNVVmj0Swf/k3W5zN30nGhfgL1gUp8AdWEAfiFif37u+4JWOJ0S
pcBAfNEHCylzbgribR9I/EkaO0sl8d6yvKxKLB6mxlBZfTNZlVKHyq5VRlzPGLUj
T4/YtiJws86VvabuBdNfjAIYZc3j+mRQPwGU94lapioC+toVLpZ9MwvqP8JmypVf
iNTuIny4kZVBk0+vNt5Tzzw7QJZpk8Kzs7WxvRnKqRoR3SJEQcYcFiHaOWIeVEh
YCQIDAQAB
-----END PUBLIC KEY-----"""


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

    header_raw = _b64url_decode(parts[0])
    header, duplicate_header_keys = _parse_json_with_duplicates(header_raw)

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
    b64_mode = "unencoded" if header.get("b64") is False else "normal"

    signature_valid = False
    signature_error = None
    key_source = "configured"
    effective_alg = header_alg
    crit_processed = None
    nested_jwt = bool(cty == "JWT" or isinstance(payload.get("nested"), str))
    inner_alg = None
    inner_signature_valid = None

    if header.get("jku"):
        key_source = "jku"
    elif header.get("jwk"):
        key_source = "embedded_jwk"
    elif header.get("x5u"):
        key_source = "x5u"
    elif header.get("x5c"):
        key_source = "x5c"

    # RS256 verification with RSA public key — only RS256 allowed
    try:
        decoded = pyjwt.decode(
            raw,
            RSA_PUBLIC_KEY_PEM,
            algorithms=["RS256"],
            options={
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
            },
        )
        signature_valid = True
        payload = decoded
    except pyjwt.exceptions.PyJWTError as e:
        signature_error = f"{type(e).__name__}: {str(e)[:200]}"
    except Exception as e:
        signature_error = f"{type(e).__name__}: {str(e)[:200]}"

    nested_candidate = payload.get("nested") if isinstance(payload.get("nested"), str) else None
    if (cty == "JWT" or nested_candidate) and nested_candidate and nested_candidate.count(".") >= 1:
        try:
            inner_header_raw = _b64url_decode(nested_candidate.split(".")[0])
            inner_header = json.loads(inner_header_raw)
            inner_alg = inner_header.get("alg")
        except Exception:
            pass

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
        print("Usage: jwt_python_pyjwt_rsa.py <input_file>", file=sys.stderr)
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
