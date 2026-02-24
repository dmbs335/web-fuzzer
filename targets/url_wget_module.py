"""Persistent module — wget URL parser.

Exports process(input) for use with persistent_wrapper.py.
"""
from url_wget import parse_url


def process(input_str):
    try:
        output = parse_url(input_str)
        return {"output": output, "exit_code": 0}
    except (ValueError, TypeError, Exception):
        return {"output": "", "exit_code": 1}
