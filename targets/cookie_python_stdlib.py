"""Cookie parser target — Python stdlib http.cookies.

Parses Set-Cookie header values using http.cookies.SimpleCookie
and outputs parsed components as JSON for differential comparison.

http.cookies.SimpleCookie follows RFC 2109/6265 loosely — it has
known quirks around quoted values, special characters, and attribute
parsing that differ from other implementations.

References:
  - RFC 6265bis (Cookies: HTTP State Management Mechanism)
  - Python docs: http.cookies
  - PortSwigger "Cookie Chaos" (2025) — $Version parsing differentials
"""

import json
import sys
from http.cookies import SimpleCookie


def parse_cookie(data: str) -> str:
    """Parse Set-Cookie header and return canonical JSON."""
    data = data.strip()
    if not data:
        raise ValueError("Empty input")

    sc = SimpleCookie()
    # SimpleCookie expects "Set-Cookie: " prefix to be absent
    sc.load(data)

    if not sc:
        raise ValueError("No cookies parsed")

    # Extract first (and should be only) cookie
    for name, morsel in sc.items():
        result = {
            "name": name,
            "value": morsel.value,
            "domain": morsel.get("domain", "") or "",
            "path": morsel.get("path", "") or "",
            "expires": morsel.get("expires", "") or "",
            "max_age": str(morsel.get("max-age", "") or ""),
            "secure": bool(morsel.get("secure", "")),
            "httponly": bool(morsel.get("httponly", "")),
            "samesite": morsel.get("samesite", "") or "",
            "version": morsel.get("version", "") or "",
            "comment": morsel.get("comment", "") or "",
        }
        return json.dumps(result, sort_keys=True, ensure_ascii=True)

    raise ValueError("No cookies extracted")


def main():
    if len(sys.argv) < 2:
        print("Usage: cookie_python_stdlib.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = parse_cookie(data)
        print(result)
        sys.exit(0)
    except (ValueError, TypeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
