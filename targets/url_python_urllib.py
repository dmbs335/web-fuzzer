"""URL parser target — Python stdlib urllib.parse.

Parses URLs using urllib.parse.urlparse() and outputs parsed
components as JSON for differential comparison.

urllib.parse follows RFC 3986 loosely — it accepts many non-standard
inputs that stricter parsers reject, making it a rich differential
testing target against WHATWG URL or strict RFC 3986 implementations.

References:
  - RFC 3986 (Uniform Resource Identifier)
  - Python docs: urllib.parse
  - Orange Tsai, "A New Era of SSRF" (BlackHat 2017)
"""

import json
import sys
import urllib.parse


def parse_url(data: str) -> str:
    """Parse URL with urllib.parse and return canonical JSON."""
    data = data.strip()
    if not data:
        raise ValueError("Empty input")

    parsed = urllib.parse.urlparse(data)

    # Extract userinfo from netloc
    userinfo = ""
    host = parsed.hostname or ""
    if "@" in parsed.netloc:
        userinfo_part, _, host_part = parsed.netloc.rpartition("@")
        userinfo = userinfo_part
        # Re-parse host from the part after @
        if host_part.startswith("["):
            # IPv6
            bracket_end = host_part.find("]")
            if bracket_end != -1:
                host = host_part[1:bracket_end]
            else:
                host = host_part
        elif ":" in host_part:
            host = host_part.rsplit(":", 1)[0]
        else:
            host = host_part

    port = str(parsed.port) if parsed.port is not None else ""

    result = {
        "scheme": parsed.scheme,
        "userinfo": userinfo,
        "host": host,
        "port": port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main():
    if len(sys.argv) < 2:
        print("Usage: url_python_urllib.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = parse_url(data)
        print(result)
        sys.exit(0)
    except (ValueError, TypeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
