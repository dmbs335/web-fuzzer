"""URL parser target — curl (libcurl).

Parses URLs using curl's URL parser via -w format and outputs parsed
components as JSON for differential comparison.

curl uses libcurl's URL parser which is the actual request-side parser
for PHP's curl_exec(), making this the ground truth for what host
PHP+curl SSRF would actually connect to.

curl -w variables (8.1.0+):
  %{url.scheme}, %{url.host}, %{url.port}, %{url.path},
  %{url.query}, %{url.fragment}, %{url.user}, %{url.password}

References:
  - libcurl URL parsing API
  - curl -w format docs
  - Orange Tsai, "Confusion Attacks" (BlackHat 2023)
"""

import json
import subprocess
import sys


# curl -w format to extract parsed URL components as tab-separated values
CURL_FORMAT = (
    "%{url.scheme}\t"
    "%{url.user}\t"
    "%{url.password}\t"
    "%{url.host}\t"
    "%{url.port}\t"
    "%{url.path}\t"
    "%{url.query}\t"
    "%{url.fragment}"
)


def parse_url(data: str) -> tuple[str, int]:
    """Parse URL with curl's libcurl parser and return (json_str, exit_code).

    Returns partial results even when curl can't fully parse the URL.
    Only returns exit_code=1 when curl produces completely empty output
    (URL is entirely unparseable).
    """
    data = data.strip()
    if not data:
        return json.dumps({
            "scheme": "", "userinfo": "", "host": "",
            "port": "", "path": "", "query": "", "fragment": "",
        }, sort_keys=True, ensure_ascii=True), 1

    # Use --connect-timeout 0.001 to prevent actual connections while
    # still allowing curl's URL parser to run.  Previous --max-time 0.01
    # wasted time on DNS/TCP attempts and often returned exit 28 (timeout).
    proc = subprocess.run(
        [
            "curl",
            "-s",
            "--output", "/dev/null",
            "--connect-timeout", "0.001",
            "-w", CURL_FORMAT,
            "--", data,
        ],
        capture_output=True,
        timeout=5,
        stdin=subprocess.DEVNULL,
    )

    # curl -w output is always written regardless of exit code
    output = proc.stdout.decode("utf-8", errors="replace")

    # Parse tab-separated components (curl always writes 8 fields)
    parts = output.split("\t")

    # Pad to 8 fields if somehow truncated
    while len(parts) < 8:
        parts.append("")

    scheme = parts[0].strip()
    user = parts[1].strip()
    password = parts[2].strip()
    host = parts[3].strip()
    port = parts[4].strip()
    path = parts[5].strip()
    query = parts[6].strip()
    fragment = parts[7].strip()

    # Build userinfo
    userinfo = ""
    if user:
        userinfo = user
        if password:
            userinfo += ":" + password

    # curl may return "0" for unset port
    if port == "0":
        port = ""

    # Normalize default ports to empty (match other parsers' convention)
    DEFAULT_PORTS = {"http": "80", "https": "443", "ftp": "21", "ws": "80", "wss": "443"}
    if port == DEFAULT_PORTS.get(scheme, ""):
        port = ""

    result = {
        "scheme": scheme,
        "userinfo": userinfo,
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
    }

    json_str = json.dumps(result, sort_keys=True, ensure_ascii=True)

    # Determine exit code: if ANY component was parsed, report success
    # so differential strategies can compare partial results
    has_content = any([scheme, host, path, query, fragment, userinfo])
    exit_code = 0 if has_content else 1

    return json_str, exit_code


def main():
    if len(sys.argv) < 2:
        print("Usage: url_curl.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result, exit_code = parse_url(data)
        print(result)
        sys.exit(exit_code)
    except subprocess.TimeoutExpired:
        print("REJECT: curl timeout", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
