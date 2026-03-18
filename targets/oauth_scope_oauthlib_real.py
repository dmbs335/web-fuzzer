"""OAuth scope target using REAL oauthlib library.

Calls oauthlib.oauth2.rfc6749.utils.scope_to_list() directly.
Key behavior: .split(" ") (single space only) — tabs/newlines NOT treated as delimiters.

Also uses oauthlib.uri_validate.is_absolute_uri() for redirect_uri format check.

Input:  JSON { type, granted, requested } or { type, registered, candidate }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import json
import sys

from oauthlib.oauth2.rfc6749.utils import scope_to_list, list_to_scope
from oauthlib.uri_validate import is_absolute_uri


def _check_redirect_uri(registered: list[str], candidate: str) -> dict:
    fragment_present = "#" in candidate
    is_valid = bool(is_absolute_uri(candidate))

    # Extract components via simple URL parsing (no normalization)
    scheme = host = port = path = None
    try:
        from urllib.parse import urlparse
        p = urlparse(candidate)
        scheme = p.scheme or None
        host = p.hostname or None
        port = str(p.port) if p.port else None
        path = p.path or None
    except Exception:
        pass

    match_idx = None
    if is_valid:
        for i, uri in enumerate(registered):
            if candidate == uri:
                match_idx = i
                break

    return {
        "redirect_match": match_idx is not None,
        "redirect_matched_index": match_idx,
        "candidate_scheme": scheme,
        "candidate_host": host,
        "candidate_port": port,
        "candidate_path": path,
        "candidate_normalized": candidate,
        "loopback_detected": False,
        "fragment_present": fragment_present,
    }


def _normalize_uri(uri: str) -> str:
    """Oauthlib-style normalization: lowercase scheme+host, strip default ports."""
    try:
        from urllib.parse import urlparse
        p = urlparse(uri)
        scheme = (p.scheme or "").lower()
        host = (p.hostname or "").lower()
        port = p.port
        # Strip default ports
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
        netloc = host
        if port:
            netloc = f"{host}:{port}"
        if p.username:
            userinfo = p.username
            if p.password:
                userinfo += f":{p.password}"
            netloc = f"{userinfo}@{netloc}"
        return f"{scheme}://{netloc}{p.path}"
    except Exception:
        return uri


def _url_components(candidate: str) -> dict:
    """Extract URL components using Python urllib."""
    try:
        from urllib.parse import urlparse
        p = urlparse(candidate)
        return {
            "host": p.hostname or None,
            "port": str(p.port) if p.port else None,
        }
    except Exception:
        return {"host": None, "port": None}


def _check_token_exchange(data: dict) -> dict:
    """Check token exchange: compare auth_redirect_uri vs token_redirect_uri."""
    registered = data.get("registered", [])
    if not isinstance(registered, list):
        registered = []

    auth_uri = str(data.get("auth_redirect_uri", ""))
    token_uri = data.get("token_redirect_uri")

    auth_comps = _url_components(auth_uri)
    auth_normalized = _normalize_uri(auth_uri)

    # Check auth_redirect_uri against registered (exact string match)
    auth_match = any(auth_uri == r for r in registered)

    if token_uri is not None:
        token_uri = str(token_uri)
        token_comps = _url_components(token_uri)
        token_normalized = _normalize_uri(token_uri)
        token_match = any(token_uri == r for r in registered)
        uri_identical = auth_normalized == token_normalized
    else:
        token_comps = {"host": None, "port": None}
        token_normalized = None
        token_match = False
        uri_identical = False

    return {
        "input_type": "token_exchange",
        "auth_match": auth_match,
        "token_match": token_match,
        "uri_identical": uri_identical,
        "auth_normalized": auth_normalized,
        "token_normalized": token_normalized,
        "auth_host": auth_comps["host"],
        "token_host": token_comps["host"],
        "auth_port": auth_comps["port"],
        "token_port": token_comps["port"],
    }


def _check_scope(granted: str, requested: str) -> dict:
    # REAL oauthlib call
    granted_list = scope_to_list(granted) or []
    requested_list = scope_to_list(requested) or []

    granted_clean = [s for s in granted_list if s]
    requested_clean = [s for s in requested_list if s]
    granted_set = set(granted_clean)
    all_match = all(s in granted_set for s in requested_clean)

    return {
        "scope_match": all_match,
        "scope_parsed_granted": granted_list,
        "scope_parsed_requested": requested_list,
        "scope_count_granted": len(granted_list),
        "scope_count_requested": len(requested_list),
        "scope_empty_elements": sum(1 for s in granted_list if s == ""),
    }


def process_oauth(input_str: str) -> str:
    raw = input_str.strip()
    data = json.loads(raw)

    if not isinstance(data, dict) or "type" not in data:
        raise ValueError("Invalid input")

    result = {
        "input_type": data["type"],
        "redirect_match": None, "redirect_matched_index": None,
        "candidate_scheme": None, "candidate_host": None,
        "candidate_port": None, "candidate_path": None,
        "candidate_normalized": None, "loopback_detected": None,
        "fragment_present": None,
        "scope_match": None, "scope_parsed_granted": None,
        "scope_parsed_requested": None, "scope_count_granted": None,
        "scope_count_requested": None, "scope_empty_elements": None,
    }

    if data["type"] == "redirect_uri":
        registered = data.get("registered", [])
        if not isinstance(registered, list):
            registered = []
        candidate = str(data.get("candidate", ""))
        result.update(_check_redirect_uri(registered, candidate))
    elif data["type"] == "scope":
        granted = str(data["granted"]) if data.get("granted") is not None else ""
        requested = str(data["requested"]) if data.get("requested") is not None else ""
        result.update(_check_scope(granted, requested))
    elif data["type"] == "token_exchange":
        te = _check_token_exchange(data)
        return json.dumps(te, sort_keys=True, ensure_ascii=True)

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_scope_oauthlib_real.py <input_file>", file=sys.stderr)
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
