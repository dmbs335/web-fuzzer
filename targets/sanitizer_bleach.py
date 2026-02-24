"""Bleach sanitizer target for differential fuzzing.

Usage: python sanitizer_bleach.py <input_file>
Output: sanitized HTML to stdout
"""
import sys

import bleach

if len(sys.argv) < 2:
    sys.stderr.write("Usage: python sanitizer_bleach.py <input_file>\n")
    sys.exit(1)

try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
        html = f.read()
    clean = bleach.clean(html)
    sys.stdout.write(clean)
except Exception as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(1)
