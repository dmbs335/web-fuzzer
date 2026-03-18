"""Persistent module -- oauthlib style OAuth scope parser."""

from oauth_scope_oauthlib import process_oauth


def process(input_str):
    try:
        output = process_oauth(input_str)
        return {"output": output, "exit_code": 0}
    except Exception:
        return {"output": "", "exit_code": 1}
