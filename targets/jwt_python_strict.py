"""JWT target -- Python strict manual verifier.

Verifies compact JWS tokens using a pinned HS* secret and rejects dynamic
header-based key resolution. Emits rich JSON observability fields for
differential JWT fuzzing.

Output: standardized JSON for differential comparison.
Exit 0 = processed (even if signature invalid), Exit 1 = parse failure.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time

DEFAULT_HS_SECRET = b"secret"
SUPPORTED_HS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_decode(data: str) -> bytes:
    raw = data.encode("ascii")
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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

    exp_state = classify("exp", "exp")
    nbf_state = classify("nbf", "nbf")
    iat_state = classify("iat", "iat")
    return time_valid, exp_state, nbf_state, iat_state


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
    payload_raw = _b64url_decode(parts[1])
    header, duplicate_header_keys = _parse_json_with_duplicates(header_raw)
    payload, duplicate_claim_keys = _parse_json_with_duplicates(payload_raw)

    header_alg = str(header.get("alg") or "")
    typ = header.get("typ")
    cty = header.get("cty")
    crit = header.get("crit")
    b64_mode = "unencoded" if header.get("b64") is False else "normal"
    crit_processed = None if crit is None else False

    signature_valid = False
    signature_error = None
    key_source = "configured"
    effective_alg = header_alg
    sig_segment = parts[2] if len(parts) >= 3 else ""

    if token_type_observed != "jws":
        signature_error = f"Unexpected token type: {token_type_observed}"
    elif crit:
        signature_error = "Critical headers unsupported"
    elif header_alg not in SUPPORTED_HS:
        signature_error = f"Unsupported alg: {header_alg}"
    else:
        digestmod = SUPPORTED_HS[header_alg]
        expected_sig = _b64url_encode(
            hmac.new(DEFAULT_HS_SECRET, f"{parts[0]}.{parts[1]}".encode("ascii"), digestmod).digest()
        )
        signature_valid = hmac.compare_digest(sig_segment, expected_sig)
        if not signature_valid:
            signature_error = "Signature mismatch"

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
        "nested_jwt": bool(cty == "JWT" or isinstance(payload.get("nested"), str)),
        "inner_alg": None,
        "inner_signature_valid": None,
    }
    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: jwt_python_strict.py <input_file>", file=sys.stderr)
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
