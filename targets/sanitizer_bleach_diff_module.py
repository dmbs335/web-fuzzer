"""Bleach differential fuzzing module for persistent wrapper."""
import json

import bleach

from sanitizer_diff_common import build_result


def process(input_str):
    try:
        clean = bleach.clean(input_str)
        return {"output": json.dumps(build_result(clean)), "exit_code": 0}
    except Exception as e:
        return {"output": json.dumps({"error": str(e), "empty_output": True}), "exit_code": 1}
