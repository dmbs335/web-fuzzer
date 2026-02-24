"""Persistent module — curl (libcurl) URL parser.

Exports process(input) for use with persistent_wrapper.py.
"""
from url_curl import parse_url


def process(input_str):
    try:
        output, exit_code = parse_url(input_str)
        return {"output": output, "exit_code": exit_code}
    except Exception:
        return {"output": "", "exit_code": 1}
