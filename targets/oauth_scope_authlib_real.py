"""OAuth scope target using REAL authlib library.

Calls authlib.oauth2.rfc6749.scope_to_list() directly.
Key behavior: .split() (any whitespace) — tabs, newlines split into scopes.

Input:  JSON { type, granted, requested } or { type, registered, candidate }
Output: standardized JSON for differential comparison.
"""

from __future__ import annotations

import json
import re
import sys
from urllib.parse import urlparse

from authlib.oauth2.rfc6749 import scope_to_list, list_to_scope


def _url_components(candidate: str) -> dict:
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
    fragment_present = "#" in candidate
    components = _url_components(candidate)
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
        "candidate_normalized": candidate,
        "loopback_detected": False,
        "fragment_present": fragment_present,
    }


def _check_scope(granted: str, requested: str) -> dict:
    # REAL authlib call
    granted_list = scope_to_list(granted) or []
    requested_list = scope_to_list(requested) or []
    granted_set = set(granted_list)
    all_match = all(s in granted_set for s in requested_list)

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

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_scope_authlib_real.py <input_file>", file=sys.stderr)
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
