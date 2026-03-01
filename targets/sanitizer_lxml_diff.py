"""lxml.Cleaner differential target (process mode).

Usage: python sanitizer_lxml_diff.py <input_file>
Output: Standardized JSON with security signals.
"""
import json
import sys

from lxml.html.clean import Cleaner

from sanitizer_diff_common import build_result

_cleaner = Cleaner(
    scripts=True,
    javascript=True,
    embedded=True,
    meta=True,
    page_structure=False,
    processing_instructions=True,
    remove_unknown_tags=False,
    safe_attrs_only=True,
)

if len(sys.argv) < 2:
    sys.stderr.write("Usage: python sanitizer_lxml_diff.py <input_file>\n")
    sys.exit(1)

try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
        html = f.read()
    import lxml.html

    doc = lxml.html.fromstring(html)
    _cleaner(doc)
    clean = lxml.html.tostring(doc, encoding="unicode")
    sys.stdout.write(json.dumps(build_result(clean)))
except Exception as e:
    sys.stdout.write(json.dumps({"error": str(e), "empty_output": True}))
    sys.exit(1)
