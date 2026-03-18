"""OAuth redirect_uri target -- Authlib REAL validation logic.

Uses REAL library imports:
  - authlib.oauth2.rfc6749.util.scope_to_list: splits on any whitespace
    Source: .venv/Lib/site-packages/authlib/oauth2/rfc6749/util.py

Redirect URI matching: authlib delegates to client.check_redirect_uri() which
is an abstract method (ClientMixin). The standard implementation is raw string
comparison (redirect_uri in client.redirect_uris). This is by design — authlib
does NOT normalize URLs for redirect_uri comparison.
  Source: .venv/Lib/site-packages/authlib/oauth2/rfc6749/grants/base.py

Token exchange: authlib compares redirect_uri with raw string !=
  Source: .venv/Lib/site-packages/authlib/oauth2/rfc6749/grants/authorization_code.py:236
  `redirect_uri != original_redirect_uri`

Input:  JSON { type, registered, candidate } or { type, granted, requested }
Output: standardized JSON for differential comparison.
Exit 0 = processed, Exit 1 = parse failure.
"""

from __future__ import annotations

import json
import sys
from urllib.parse import urlparse

# --- REAL LIBRARY IMPORT ---
from authlib.oauth2.rfc6749 import scope_to_list


def _url_components(candidate: str) -> dict:
    """Extract URL components using Python urllib (RFC 3986)."""
    try:
        p = urlparse(candidate)
        return {
            "scheme": p.scheme or None,
            "host": p.hostname or None,
            "port": str(p.port) if p.port else None,
            "path": p.path or None,
        }
    except Exception:
        return {"scheme": None, "host": None, "port": None, "path": None}


def _check_redirect_uri(registered: list[str], candidate: str) -> dict:
    """Authlib-style redirect_uri matching: raw string comparison.

    Source: authlib ClientMixin.check_redirect_uri() is abstract.
    Standard implementation: `redirect_uri in client.redirect_uris`
    NO URL normalization is performed.
    """
    fragment_present = "#" in candidate
    components = _url_components(candidate)

    # Raw string comparison — NO normalization (authlib design)
    match_idx = None
    for i, uri in enumerate(registered):
        if candidate == uri:
            match_idx = i
            break

    return {
        "redirect_match": match_idx is not None,
        "redirect_matched_index": match_idx,
        "candidate_scheme": components["scheme"],
        "candidate_host": components["host"],
        "candidate_port": components["port"],
        "candidate_path": components["path"],
        "candidate_normalized": candidate,  # No normalization
        "loopback_detected": False,
        "fragment_present": fragment_present,
    }


def _check_token_exchange(data: dict) -> dict:
    """Token exchange: authlib uses raw string != comparison.

    Source: authorization_code.py:236
    `redirect_uri != original_redirect_uri`
    """
    registered = data.get("registered", [])
    if not isinstance(registered, list):
        registered = []

    auth_uri = str(data.get("auth_redirect_uri", ""))
    token_uri = data.get("token_redirect_uri")

    auth_components = _url_components(auth_uri)

    # Raw string match — NO normalization
    auth_match = any(auth_uri == r for r in registered)

    if token_uri is not None:
        token_uri = str(token_uri)
        token_components = _url_components(token_uri)
        token_match = any(token_uri == r for r in registered)
        # Raw string comparison (authlib: redirect_uri != original_redirect_uri)
        uri_identical = auth_uri == token_uri
    else:
        token_components = {"scheme": None, "host": None, "port": None, "path": None}
        token_match = False
        uri_identical = False

    return {
        "input_type": "token_exchange",
        "auth_match": auth_match,
        "token_match": token_match,
        "uri_identical": uri_identical,
        "auth_normalized": auth_uri,  # Raw string, no normalization
        "token_normalized": token_uri,
        "auth_host": auth_components["host"],
        "token_host": token_components["host"],
        "auth_port": auth_components["port"],
        "token_port": token_components["port"],
    }


def _check_scope(granted: str, requested: str) -> dict:
    """Scope parsing using REAL authlib scope_to_list().

    Source: authlib/oauth2/rfc6749/util.py
    Uses str.split() (any whitespace) — tabs, newlines are delimiters.
    """
    granted_list = scope_to_list(granted) or []
    requested_list = scope_to_list(requested) or []

    granted_set = set(granted_list)
    all_match = all(s in granted_set for s in requested_list)

    # Count empty elements from space-only split for comparison metadata
    granted_raw_parts = granted.split(" ") if granted else []

    return {
        "scope_match": all_match,
        "scope_parsed_granted": granted_list,
        "scope_parsed_requested": requested_list,
        "scope_count_granted": len(granted_list),
        "scope_count_requested": len(requested_list),
        "scope_empty_elements": sum(1 for s in granted_raw_parts if s == ""),
    }


def process_oauth(input_str: str) -> str:
    raw = input_str.strip()
    data = json.loads(raw)

    if not isinstance(data, dict) or "type" not in data:
        raise ValueError("Invalid input: must be JSON with 'type' field")

    result = {
        "input_type": data["type"],
        "redirect_match": None,
        "redirect_matched_index": None,
        "candidate_scheme": None,
        "candidate_host": None,
        "candidate_port": None,
        "candidate_path": None,
        "candidate_normalized": None,
        "loopback_detected": None,
        "fragment_present": None,
        "scope_match": None,
        "scope_parsed_granted": None,
        "scope_parsed_requested": None,
        "scope_count_granted": None,
        "scope_count_requested": None,
        "scope_empty_elements": None,
    }

    if data["type"] == "redirect_uri":
        registered = data.get("registered", [])
        if not isinstance(registered, list):
            registered = []
        candidate = str(data.get("candidate", ""))
        redir = _check_redirect_uri(registered, candidate)
        result.update(redir)
    elif data["type"] == "scope":
        granted = str(data["granted"]) if data.get("granted") is not None else ""
        requested = str(data["requested"]) if data.get("requested") is not None else ""
        sc = _check_scope(granted, requested)
        result.update(sc)
    elif data["type"] == "token_exchange":
        te = _check_token_exchange(data)
        return json.dumps(te, sort_keys=True, ensure_ascii=True)

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_redirect_authlib.py <input_file>", file=sys.stderr)
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
