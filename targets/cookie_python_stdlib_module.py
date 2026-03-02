"""Persistent module — Python http.cookies Set-Cookie parser.

Exports process(input) for use with persistent_wrapper.py.
"""
from cookie_python_stdlib import parse_cookie


def process(input_str):
    try:
        output = parse_cookie(input_str)
        return {"output": output, "exit_code": 0}
    except (ValueError, TypeError):
        return {"output": "", "exit_code": 1}
