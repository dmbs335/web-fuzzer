"""DPoP proof verification target using authlib for JWT parsing.

Validates DPoP proof JWTs per RFC 9449.
Uses urllib.parse.urlparse for htu normalization (scheme-based: strip default
ports, lowercase scheme+host).

Input:  JSON { type: "dpop_proof", proof_jwt, http_method, http_uri, access_token?, server_nonce? }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
import time
from urllib.parse import urlparse, urlunparse

ASYMMETRIC_ALGS = frozenset({
    "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512",
    "PS256", "PS384", "PS512",
    "EdDSA",
})

PRIVATE_KEY_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth"})

# Default ports per scheme
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _b64url_decode(s: str) -> bytes:
    """Base64url decode with padding tolerance (authlib style)."""
    s = s.replace("-", "+").replace("_", "/")
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.b64decode(s)


def _b64url_encode_nopad(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _normalize_htu(uri: str) -> str:
    """Normalize htu using urllib.parse — lowercase scheme+host, strip default port,
    remove query and fragment."""
    try:
        parsed = urlparse(uri)
        scheme = parsed.scheme.lower()
        host = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        # Strip default port
        if port and _DEFAULT_PORTS.get(scheme) == port:
            port = None
        netloc = host
        if port:
            netloc = f"{host}:{port}"
        # Strip query and fragment
        return urlunparse((scheme, netloc, parsed.path, "", "", ""))
    except Exception:
        return uri


def _has_private_key(jwk: dict) -> bool:
    if not isinstance(jwk, dict):
        return False
    return bool(PRIVATE_KEY_FIELDS & jwk.keys())


def process_dpop(input_str: str) -> str:
    raw = input_str.strip()
    data = json.loads(raw)

    if not isinstance(data, dict) or data.get("type") != "dpop_proof":
        raise ValueError("Invalid input: type must be dpop_proof")

    proof_jwt = str(data.get("proof_jwt", ""))
    http_method = data.get("http_method")
    if http_method is not None:
        http_method = str(http_method)
    http_uri = data.get("http_uri")
    if http_uri is not None:
        http_uri = str(http_uri)
    access_token = data.get("access_token")
    if access_token is not None:
        access_token = str(access_token)
    server_nonce = data.get("server_nonce")
    if server_nonce is not None:
        server_nonce = str(server_nonce)

    result = {
        "input_type": "dpop_proof",
        "proof_valid": False,
        "header_typ": None,
        "header_typ_valid": False,
        "header_alg": None,
        "header_alg_valid": False,
        "header_has_jwk": False,
        "htm_matches": False,
        "htm_value": None,
        "htu_matches": False,
        "htu_value": None,
        "htu_normalized": None,
        "ath_valid": None,
        "ath_value": None,
        "ath_has_padding": False,
        "iat_valid": False,
        "iat_value": None,
        "jti": None,
        "jti_valid": False,
        "nonce_valid": None,
        "nonce_value": None,
        "jwt_parse_error": None,
    }

    # Parse JWT
    parts = proof_jwt.split(".")
    if len(parts) != 3:
        result["jwt_parse_error"] = "invalid JWT structure: expected 3 parts"
        return json.dumps(result, sort_keys=True, ensure_ascii=True)

    try:
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
    except Exception as e:
        result["jwt_parse_error"] = f"header decode failed: {e}"
        return json.dumps(result, sort_keys=True, ensure_ascii=True)

    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception as e:
        result["jwt_parse_error"] = f"payload decode failed: {e}"
        return json.dumps(result, sort_keys=True, ensure_ascii=True)

    # Check header typ
    result["header_typ"] = str(header["typ"]) if "typ" in header else None
    result["header_typ_valid"] = result["header_typ"] == "dpop+jwt"

    # Check header alg
    result["header_alg"] = str(header["alg"]) if "alg" in header else None
    result["header_alg_valid"] = (
        result["header_alg"] is not None
        and result["header_alg"] != "none"
        and not result["header_alg"].startswith("HS")
        and result["header_alg"] in ASYMMETRIC_ALGS
    )

    # Check jwk
    result["header_has_jwk"] = "jwk" in header and isinstance(header.get("jwk"), dict)

    # Check for private key in jwk
    if result["header_has_jwk"] and _has_private_key(header["jwk"]):
        result["header_alg_valid"] = False

    # Check htm
    result["htm_value"] = str(payload["htm"]) if "htm" in payload else None
    if http_method is not None and result["htm_value"] is not None:
        result["htm_matches"] = result["htm_value"] == http_method  # Case-sensitive

    # Check htu with urllib normalization
    result["htu_value"] = str(payload["htu"]) if "htu" in payload else None
    if http_uri is not None and result["htu_value"] is not None:
        normalized_htu = _normalize_htu(result["htu_value"])
        normalized_expected = _normalize_htu(http_uri)
        result["htu_normalized"] = normalized_htu
        result["htu_matches"] = normalized_htu == normalized_expected
    else:
        result["htu_normalized"] = (
            _normalize_htu(result["htu_value"]) if result["htu_value"] is not None else None
        )

    # Check ath
    if access_token is not None:
        result["ath_value"] = str(payload["ath"]) if "ath" in payload else None
        if result["ath_value"] is not None:
            expected_ath = _b64url_encode_nopad(
                hashlib.sha256(access_token.encode("ascii")).digest()
            )
            result["ath_valid"] = result["ath_value"] == expected_ath
            result["ath_has_padding"] = "=" in result["ath_value"]
        else:
            result["ath_valid"] = False
    else:
        result["ath_valid"] = None
        result["ath_value"] = str(payload["ath"]) if "ath" in payload else None
        result["ath_has_padding"] = "=" in (result["ath_value"] or "")

    # Check iat
    result["iat_value"] = payload.get("iat")
    if isinstance(result["iat_value"], (int, float)):
        now = int(time.time())
        diff = abs(now - result["iat_value"])
        result["iat_valid"] = diff <= 300

    # Check jti
    result["jti"] = str(payload["jti"]) if "jti" in payload else None
    result["jti_valid"] = isinstance(result["jti"], str) and len(result["jti"]) > 0

    # Check nonce
    if server_nonce is not None:
        result["nonce_value"] = str(payload["nonce"]) if "nonce" in payload else None
        if result["nonce_value"] is not None:
            result["nonce_valid"] = result["nonce_value"] == server_nonce
        else:
            result["nonce_valid"] = False
    else:
        result["nonce_valid"] = None
        result["nonce_value"] = str(payload["nonce"]) if "nonce" in payload else None

    # Compute overall validity
    result["proof_valid"] = (
        result["header_typ_valid"]
        and result["header_alg_valid"]
        and result["htm_matches"]
        and result["htu_matches"]
        and (result["ath_valid"] is True if access_token is not None else True)
        and result["iat_valid"]
        and result["jti_valid"]
        and (result["nonce_valid"] is True if server_nonce is not None else True)
    )

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: dpop_python_authlib.py <input_file>", file=sys.stderr)
        sys.exit(2)
    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)
    try:
        print(process_dpop(data))
        sys.exit(0)
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
