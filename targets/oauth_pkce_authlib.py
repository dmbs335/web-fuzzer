"""OAuth PKCE target using REAL authlib library.

Calls authlib.oauth2.rfc7636 functions directly.
Key behavior: create_s256_code_challenge uses urlsafe_b64encode without explicit
padding strip (but authlib 1.6+ strips padding via to_unicode).

Input:  JSON { type: "pkce", method, verifier, challenge }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import json
import re
import sys

from authlib.oauth2.rfc7636 import create_s256_code_challenge
from authlib.oauth2.rfc7636.challenge import (
    compare_plain_code_challenge,
    compare_s256_code_challenge,
)

_VERIFIER_RE = re.compile(r"^[A-Za-z0-9\-._~]{43,128}$")


def _check_pkce(method: str, verifier: str, challenge: str) -> dict:
    verifier_valid = bool(_VERIFIER_RE.match(verifier)) if verifier else False

    # Compute challenge from verifier
    challenge_computed = None
    challenge_match = False

    method_upper = (method or "").strip().upper()

    if method_upper == "S256" or method_upper == "":
        # Default to S256 per RFC 7636
        try:
            challenge_computed = create_s256_code_challenge(verifier)
            challenge_match = compare_s256_code_challenge(verifier, challenge)
        except Exception:
            challenge_match = False
    elif method_upper == "PLAIN":
        challenge_computed = verifier
        challenge_match = compare_plain_code_challenge(verifier, challenge)
    else:
        # Unsupported method
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
        # Pass through to scope/redirect handling (reuse authlib_real)
        from oauth_scope_authlib_real import process_oauth as scope_process
        return scope_process(input_str)

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_pkce_authlib.py <input_file>", file=sys.stderr)
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
