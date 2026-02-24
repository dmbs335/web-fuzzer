"""nh3 sanitizer target for differential fuzzing.

Usage: python sanitizer_nh3.py <input_file>
Output: sanitized HTML to stdout
"""
import sys

import nh3

if len(sys.argv) < 2:
    sys.stderr.write("Usage: python sanitizer_nh3.py <input_file>\n")
    sys.exit(1)

try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
        html = f.read()
    clean = nh3.clean(html)
    sys.stdout.write(clean)
except Exception as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(1)
