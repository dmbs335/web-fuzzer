"""Persistent module — Python rfc3986 URL parser.

Exports process(input) for use with persistent_wrapper.py.
Requires: pip install rfc3986
"""
from url_python_rfc3986 import parse_url


def process(input_str):
    try:
        output = parse_url(input_str)
        return {"output": output, "exit_code": 0}
    except (ValueError, TypeError):
        return {"output": "", "exit_code": 1}
