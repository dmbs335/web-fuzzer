"""OAuth token response parsing target using REAL oauthlib library.

Parses token endpoint responses the way oauthlib servers would:
- token_type: case-insensitive comparison (lowered internally)
- expires_in: must be integer, string "3600" rejected
- scope: scope_to_list() splits on single space only

Input:  JSON { type: "token_response", status_code, body, requested_scope }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import json
import sys

from oauthlib.oauth2.rfc6749.utils import scope_to_list


def _check_token_response(status_code: int, body: str, requested_scope: str) -> dict:
    parse_success = False
    token_data = {}
    try:
        token_data = json.loads(body)
        if isinstance(token_data, dict):
            parse_success = True
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    is_error = "error" in token_data or status_code >= 400

    # oauthlib: token_type compared case-insensitively
    token_type_raw = token_data.get("token_type")
    token_type_normalized = None
    token_type_valid = False
    if token_type_raw is not None:
        token_type_normalized = str(token_type_raw).lower()
        token_type_valid = token_type_normalized == "bearer"

    # oauthlib: expires_in MUST be an integer — rejects string "3600"
    expires_in_raw = token_data.get("expires_in")
    expires_in_raw_type = type(expires_in_raw).__name__ if expires_in_raw is not None else "missing"
    expires_in_value = None
    expires_in_valid = False
    if expires_in_raw is not None:
        if isinstance(expires_in_raw, int):
            expires_in_value = expires_in_raw
            expires_in_valid = expires_in_value > 0
        # oauthlib does NOT convert string to int — rejects non-int types

    # Access token
    access_token = token_data.get("access_token")
    access_token_present = access_token is not None
    access_token_length = len(str(access_token)) if access_token is not None else 0

    # Refresh token
    refresh_token_present = "refresh_token" in token_data

    # Scope comparison using real oauthlib (single space split)
    scope_returned_str = token_data.get("scope", "")
    scope_returned = scope_to_list(str(scope_returned_str)) if scope_returned_str else []
    scope_requested = scope_to_list(requested_scope) if requested_scope else []

    scope_subset = False
    scope_changed = False
    if scope_returned and scope_requested:
        scope_subset = set(scope_returned).issubset(set(scope_requested))
        scope_changed = set(scope_returned) != set(scope_requested)
    elif scope_returned and not scope_requested:
        scope_subset = False
        scope_changed = True

    # Error fields
    error_code = token_data.get("error")
    error_description = token_data.get("error_description")

    return {
        "input_type": "token_response",
        "is_error_response": is_error,
        "access_token_present": access_token_present,
        "access_token_length": access_token_length,
        "token_type_raw": str(token_type_raw) if token_type_raw is not None else None,
        "token_type_normalized": token_type_normalized,
        "token_type_valid": token_type_valid,
        "expires_in_raw_type": expires_in_raw_type,
        "expires_in_value": expires_in_value,
        "expires_in_valid": expires_in_valid,
        "refresh_token_present": refresh_token_present,
        "scope_returned": scope_returned,
        "scope_requested": scope_requested,
        "scope_subset_of_requested": scope_subset,
        "scope_changed": scope_changed,
        "error_code": str(error_code) if error_code else None,
        "error_description": str(error_description) if error_description else None,
        "parse_success": parse_success,
    }


def process_oauth(input_str: str) -> str:
    raw = input_str.strip()
    data = json.loads(raw)

    if not isinstance(data, dict) or "type" not in data:
        raise ValueError("Invalid input")

    if data["type"] == "token_response":
        status_code = int(data.get("status_code", 200))
        body = str(data.get("body", ""))
        requested_scope = str(data.get("requested_scope", ""))
        result = _check_token_response(status_code, body, requested_scope)
    else:
        from oauth_tokenreq_oauthlib import process_oauth as req_process
        return req_process(input_str)

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_tokenresp_oauthlib.py <input_file>", file=sys.stderr)
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
