"""URL parser target — Python rfc3986 library (strict RFC 3986).

Parses URLs using the rfc3986 library with strict validation.
This is the most standards-compliant parser in the test suite,
rejecting inputs that RFC 3986 does not permit.

Differential value: strict RFC 3986 vs lenient urllib vs WHATWG URL
reveals inputs that slip through validation but are interpreted
differently by the actual HTTP client.

References:
  - RFC 3986 (Uniform Resource Identifier)
  - rfc3986 library (https://github.com/python-hyper/rfc3986)

Requires: pip install rfc3986
"""

import json
import sys

try:
    import rfc3986
except ImportError:
    print("Error: rfc3986 not installed. Run: pip install rfc3986", file=sys.stderr)
    sys.exit(2)


def parse_url(data: str) -> str:
    """Parse URL with rfc3986 and return canonical JSON."""
    data = data.strip()
    if not data:
        raise ValueError("Empty input")

    parsed = rfc3986.urlparse(data)

    # Extract userinfo from the parsed authority
    userinfo = parsed.userinfo or ""
    host = parsed.host or ""
    port = parsed.port or ""

    # Strip brackets from IPv6
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]

    result = {
        "scheme": parsed.scheme or "",
        "userinfo": userinfo,
        "host": host,
        "port": port,
        "path": parsed.path or "",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
    }

    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main():
    if len(sys.argv) < 2:
        print("Usage: url_python_rfc3986.py <file>", file=sys.stderr)
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
