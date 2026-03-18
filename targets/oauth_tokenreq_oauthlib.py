"""OAuth token request validation target using REAL oauthlib library.

Validates token endpoint parameters the way oauthlib would:
- grant_type: exact string match (case-sensitive)
- client_id: printable ASCII enforcement
- redirect_uri: is_absolute_uri() regex validation
- code: VSCHAR validation (RFC 6749 Appendix A)
- scope: scope_to_list() splits on single space only

Input:  JSON { type: "token_request", grant_type, code, redirect_uri,
               client_id, client_secret, scope, code_verifier }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import json
import re
import sys

from oauthlib.oauth2.rfc6749.utils import scope_to_list
from oauthlib.uri_validate import is_absolute_uri

_KNOWN_GRANTS = {
    "authorization_code", "refresh_token", "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:jwt-bearer",
}

# RFC 6749 Appendix A: VSCHAR = %x20-7E
_VSCHAR_RE = re.compile(r"^[\x20-\x7e]+$")
# NQCHAR (client_id): %x21 / %x23-5B / %x5D-7E
_NQCHAR_RE = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def _check_token_request(data: dict) -> dict:
    grant_type = str(data.get("grant_type", ""))
    client_id = str(data.get("client_id", ""))
    client_secret = str(data.get("client_secret", ""))
    code = str(data.get("code", ""))
    redirect_uri = str(data.get("redirect_uri", ""))
    scope = str(data.get("scope", ""))
    code_verifier = str(data.get("code_verifier", ""))

    # oauthlib: exact string match, NO case normalization
    grant_type_normalized = grant_type.strip()
    grant_type_valid = grant_type_normalized in _KNOWN_GRANTS

    # oauthlib: client_id must be NQCHAR (printable ASCII, no spaces/quotes)
    client_id_valid = bool(client_id) and bool(_NQCHAR_RE.match(client_id))

    # oauthlib: client_secret is VSCHAR
    client_secret_format_valid = (
        bool(_VSCHAR_RE.match(client_secret)) if client_secret else True
    )

    # oauthlib: redirect_uri via is_absolute_uri regex
    redirect_uri_format_valid = False
    if redirect_uri:
        redirect_uri_format_valid = bool(is_absolute_uri(redirect_uri))

    # oauthlib: code must be VSCHAR
    code_format_valid = (
        bool(code) and bool(_VSCHAR_RE.match(code)) and len(code) <= 2048
    )

    # scope via real oauthlib (single space split)
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
        from oauth_pkce_oauthlib import process_oauth as pkce_process
        return pkce_process(input_str)

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_tokenreq_oauthlib.py <input_file>", file=sys.stderr)
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
