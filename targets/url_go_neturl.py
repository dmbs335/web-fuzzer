"""URL parser target — Go net/url (subprocess wrapper).

Invokes the compiled Go binary for differential comparison.
Use this as --diff-cmd target. The compiled binary at
targets/url_go_neturl/url_go_neturl.exe must be built first:

    cd targets/url_go_neturl && go build -o url_go_neturl.exe .

Go's net/url.Parse() follows RFC 3986 with some lenient extensions:
  - Stricter than Python urllib (rejects backslash, NULL bytes)
  - Does NOT normalize hex/octal IPs (keeps 0x7f000001 as-is)
  - Opaque URI support (scheme:opaque)
  - Relevant to Go-based proxies (Caddy, Traefik)

References:
  - Go stdlib: net/url package
  - RFC 3986
"""

import os
import subprocess
import sys

_DIR = os.path.dirname(os.path.abspath(__file__))
_BINARY = os.path.join(_DIR, "url_go_neturl", "url_go_neturl.exe")

# Fallback for non-Windows
if not os.path.exists(_BINARY):
    _BINARY = os.path.join(_DIR, "url_go_neturl", "url_go_neturl")


def main():
    if len(sys.argv) < 2:
        print("Usage: url_go_neturl.py <file>", file=sys.stderr)
        sys.exit(2)

    proc = subprocess.run(
        [_BINARY, sys.argv[1]],
        capture_output=True,
        timeout=5,
    )
    sys.stdout.buffer.write(proc.stdout)
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
