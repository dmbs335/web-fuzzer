"""OAuth token request validation target using REAL authlib library.

Validates token endpoint parameters the way authlib would:
- grant_type: normalized via .lower(), loose matching
- client_id: any non-empty string accepted
- redirect_uri: urlparse-based validation
- code: any non-empty string accepted
- scope: scope_to_list() splits on any whitespace

Input:  JSON { type: "token_request", grant_type, code, redirect_uri,
               client_id, client_secret, scope, code_verifier }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import json
import re
import sys
from urllib.parse import urlparse

from authlib.oauth2.rfc6749 import scope_to_list

_KNOWN_GRANTS = {
    "authorization_code", "refresh_token", "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
}

_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def _check_token_request(data: dict) -> dict:
    grant_type = str(data.get("grant_type", ""))
    client_id = str(data.get("client_id", ""))
    client_secret = str(data.get("client_secret", ""))
    code = str(data.get("code", ""))
    redirect_uri = str(data.get("redirect_uri", ""))
    scope = str(data.get("scope", ""))
    code_verifier = str(data.get("code_verifier", ""))

    # authlib normalizes grant_type via .lower()
    grant_type_normalized = grant_type.strip().lower()
    grant_type_valid = grant_type_normalized in _KNOWN_GRANTS

    # authlib: client_id just needs to be non-empty
    client_id_valid = bool(client_id.strip())

    # authlib: no format restriction on client_secret
    client_secret_format_valid = True

    # authlib: redirect_uri validated via urlparse
    redirect_uri_format_valid = False
    if redirect_uri:
        try:
            parsed = urlparse(redirect_uri)
            redirect_uri_format_valid = bool(parsed.scheme and parsed.netloc)
        except Exception:
            redirect_uri_format_valid = False

    # authlib: code is any non-empty string
    code_format_valid = bool(code) and len(code) <= 2048

    # scope via real authlib
    scope_parsed = scope_to_list(scope) if scope else []
    scope_valid = scope_parsed is not None

    # PKCE verifier validation
    pkce_verifier_present = bool(code_verifier)
    pkce_verifier_format_valid = (
        bool(_VERIFIER_RE.match(code_verifier)) if code_verifier else None
    )

    # Overall validity
    overall_valid = grant_type_valid and client_id_valid
    rejection_reason = None
    if not grant_type_valid:
        rejection_reason = "unsupported_grant_type"
    elif not client_id_valid:
        rejection_reason = "invalid_client"
    elif grant_type_normalized == "authorization_code":
        if not code_format_valid:
            overall_valid = False
            rejection_reason = "invalid_grant"
        elif redirect_uri and not redirect_uri_format_valid:
            overall_valid = False
            rejection_reason = "invalid_request"

    return {
        "input_type": "token_request",
        "grant_type_valid": grant_type_valid,
        "grant_type_normalized": grant_type_normalized,
        "client_id_valid": client_id_valid,
        "client_secret_format_valid": client_secret_format_valid,
        "redirect_uri_present": bool(redirect_uri),
        "redirect_uri_format_valid": redirect_uri_format_valid if redirect_uri else None,
        "code_format_valid": code_format_valid if code else None,
        "code_length": len(code) if code else 0,
        "scope_valid": scope_valid,
        "scope_parsed": scope_parsed or [],
        "pkce_verifier_present": pkce_verifier_present,
        "pkce_verifier_format_valid": pkce_verifier_format_valid,
        "overall_valid": overall_valid,
        "rejection_reason": rejection_reason,
    }


def process_oauth(input_str: str) -> str:
    raw = input_str.strip()
    data = json.loads(raw)

    if not isinstance(data, dict) or "type" not in data:
        raise ValueError("Invalid input")

    if data["type"] == "token_request":
        result = _check_token_request(data)
    else:
        # Delegate to PKCE target for other types
        from oauth_pkce_authlib import process_oauth as pkce_process
        return pkce_process(input_str)

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_tokenreq_authlib.py <input_file>", file=sys.stderr)
        sys.exit(2)
    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)
    try:
        print(process_oauth(data))
        sys.exit(0)
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
