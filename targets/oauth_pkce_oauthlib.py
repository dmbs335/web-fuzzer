"""OAuth PKCE target using REAL oauthlib library.

Calls oauthlib's code_challenge_method_s256/plain directly.
Key behavior: oauthlib strips base64url padding with .rstrip('=').
Also validates verifier with regex: [a-zA-Z0-9\\-._~]{43,128}

Input:  JSON { type: "pkce", method, verifier, challenge }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from base64 import urlsafe_b64encode

from oauthlib.oauth2.rfc6749.grant_types.authorization_code import (
    code_challenge_method_plain,
    code_challenge_method_s256,
)

_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def _compute_s256(verifier: str) -> str:
    """Compute S256 challenge the oauthlib way."""
    return urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")


def _check_pkce(method: str, verifier: str, challenge: str) -> dict:
    verifier_valid = bool(_VERIFIER_RE.match(verifier)) if verifier else False

    challenge_computed = None
    challenge_match = False

    method_upper = (method or "").strip().upper()

    if method_upper == "S256" or method_upper == "":
        try:
            challenge_computed = _compute_s256(verifier)
            challenge_match = code_challenge_method_s256(verifier, challenge)
        except Exception:
            challenge_match = False
    elif method_upper == "PLAIN":
        challenge_computed = verifier
        challenge_match = code_challenge_method_plain(verifier, challenge)
    else:
        challenge_computed = None
        challenge_match = False

    return {
        "input_type": "pkce",
        "method": method,
        "method_resolved": method_upper if method_upper in ("S256", "PLAIN") else method,
        "challenge_computed": challenge_computed,
        "challenge_match": challenge_match,
        "verifier_valid": verifier_valid,
        "challenge_has_padding": "=" in (challenge_computed or ""),
        "verifier_length": len(verifier) if verifier else 0,
    }


def process_oauth(input_str: str) -> str:
    raw = input_str.strip()
    data = json.loads(raw)

    if not isinstance(data, dict) or "type" not in data:
        raise ValueError("Invalid input")

    if data["type"] == "pkce":
        method_was_absent = "method" not in data
        challenge_was_absent = "challenge" not in data
        verifier_was_absent = "verifier" not in data
        method = str(data.get("method", "S256"))
        verifier = str(data.get("verifier", ""))
        challenge = str(data.get("challenge", ""))
        result = _check_pkce(method, verifier, challenge)
        result["method_was_absent"] = method_was_absent
        result["challenge_was_absent"] = challenge_was_absent
        result["verifier_was_absent"] = verifier_was_absent
    else:
        from oauth_scope_oauthlib_real import process_oauth as scope_process
        return scope_process(input_str)

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_pkce_oauthlib.py <input_file>", file=sys.stderr)
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
