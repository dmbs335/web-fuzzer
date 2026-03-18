"""OAuth scope target -- oauthlib REAL scope parsing.

Uses REAL library import:
  - oauthlib.oauth2.rfc6749.utils.scope_to_list: splits on single space only
    Source: .venv/Lib/site-packages/oauthlib/oauth2/rfc6749/utils.py
    Uses .split(" ") — tabs and newlines are NOT delimiters.

Input:  JSON { type: "scope", granted, requested }
Output: standardized JSON for differential comparison.
Exit 0 = processed, Exit 1 = parse failure.
"""

from __future__ import annotations

import json
import sys

# --- REAL LIBRARY IMPORT ---
from oauthlib.oauth2.rfc6749.utils import scope_to_list


def _check_scope(granted: str, requested: str) -> dict:
    """Scope parsing using REAL oauthlib scope_to_list().

    Source: oauthlib/oauth2/rfc6749/utils.py
    Uses .split(" ") — single space only.
    "openid\tprofile" → ['openid\\tprofile'] (tab is NOT a delimiter)
    "openid  profile" → ['openid', '', 'profile'] (empty string preserved)
    """
    granted_list = scope_to_list(granted) or []
    requested_list = scope_to_list(requested) or []

    # For matching, filter empty strings
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

    if data["type"] == "scope":
        granted = str(data["granted"]) if data.get("granted") is not None else ""
        requested = str(data["requested"]) if data.get("requested") is not None else ""
        sc = _check_scope(granted, requested)
        result.update(sc)
    elif data["type"] == "redirect_uri":
        # Redirect_uri uses raw string match (same as oauthlib's abstract design)
        result["input_type"] = "redirect_uri"
        registered = data.get("registered", [])
        if not isinstance(registered, list):
            registered = []
        candidate = str(data.get("candidate", ""))
        match_idx = None
        for i, uri in enumerate(registered):
            if candidate == uri:
                match_idx = i
                break
        result["redirect_match"] = match_idx is not None
        result["redirect_matched_index"] = match_idx
        result["candidate_normalized"] = candidate
        result["fragment_present"] = "#" in candidate
        result["loopback_detected"] = False

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: oauth_scope_oauthlib.py <input_file>", file=sys.stderr)
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
