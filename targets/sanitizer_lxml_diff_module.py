"""lxml.Cleaner differential fuzzing module for persistent wrapper."""
import json

import lxml.html
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


def process(input_str):
    try:
        doc = lxml.html.fromstring(input_str)
        _cleaner(doc)
        clean = lxml.html.tostring(doc, encoding="unicode")
        return {"output": json.dumps(build_result(clean)), "exit_code": 0}
    except Exception as e:
        return {"output": json.dumps({"error": str(e), "empty_output": True}), "exit_code": 1}
