"""nh3 differential target (process mode).

Usage: python sanitizer_nh3_diff.py <input_file>
Output: Standardized JSON with security signals.
"""
import json
import sys

import nh3

from sanitizer_diff_common import build_result

if len(sys.argv) < 2:
    sys.stderr.write("Usage: python sanitizer_nh3_diff.py <input_file>\n")
    sys.exit(1)

try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
        html = f.read()
    clean = nh3.clean(html)
    sys.stdout.write(json.dumps(build_result(clean)))
except Exception as e:
    sys.stdout.write(json.dumps({"error": str(e), "empty_output": True}))
    sys.exit(1)
