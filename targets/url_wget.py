"""URL parser target — wget.

Parses URLs using wget's URL handling and outputs parsed
components as JSON for differential comparison.

wget's URL parsing differs from curl in subtle ways:
  - Different IRI/IDN handling
  - Different redirect following behavior
  - Different handling of backslash and special characters
  - Relevant for comparing with curl in SSRF scenarios

We use wget --spider (HEAD request, no download) with a very
short timeout, then parse the URL from the debug output.

References:
  - GNU wget docs
  - wget vs curl URL handling differences
"""

import json
import re
import subprocess
import sys
from urllib.parse import urlparse


def parse_url(data: str) -> str:
    """Parse URL with wget's parser via debug output and return canonical JSON."""
    data = data.strip()
    if not data:
        raise ValueError("Empty input")

    # Use wget -d (debug) --spider to see how wget parses the URL
    # without downloading anything
    try:
        proc = subprocess.run(
            [
                "wget",
                "-d",          # debug output shows parsed URL
                "--spider",    # don't download
                "-t", "1",     # 1 try
                "-T", "1",     # 1 second timeout
                "--no-check-certificate",
                "--", data,
            ],
            capture_output=True,
            timeout=5,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        raise ValueError("wget not found")

    # Parse wget's debug output for connection info
    debug = proc.stderr.decode("utf-8", errors="replace")

    # wget debug output contains lines like:
    #   Connecting to hostname:port...
    #   --YYYY-MM-DD HH:MM:SS--  http://host:port/path?query

    # Try to extract from the reconstructed URL line
    url_match = re.search(r"--\d{4}-\d{2}-\d{2}\s+[\d:]+--\s+(.+)", debug)
    if url_match:
        resolved_url = url_match.group(1).strip()
        # Parse the resolved URL
        parsed = urlparse(resolved_url)

        userinfo = ""
        host = parsed.hostname or ""
        if "@" in (parsed.netloc or ""):
            userinfo_part, _, _ = parsed.netloc.rpartition("@")
            userinfo = userinfo_part

        port = str(parsed.port) if parsed.port else ""

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

    # Fallback: try to extract host from "Connecting to" line
    conn_match = re.search(r"Connecting to ([^|]+)\|([^|]+)\|:(\d+)", debug)
    if conn_match:
        hostname = conn_match.group(1).strip()
        ip = conn_match.group(2).strip()
        port = conn_match.group(3).strip()

        # Minimal result from connection info
        parsed = urlparse(data)
        result = {
            "scheme": parsed.scheme or "",
            "userinfo": "",
            "host": hostname,
            "port": port,
            "path": parsed.path or "",
            "query": parsed.query or "",
            "fragment": parsed.fragment or "",
        }
        return json.dumps(result, sort_keys=True, ensure_ascii=True)

    raise ValueError(f"Could not parse wget debug output")


def main():
    if len(sys.argv) < 2:
        print("Usage: url_wget.py <file>", file=sys.stderr)
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
    except subprocess.TimeoutExpired:
        print("REJECT: wget timeout", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
