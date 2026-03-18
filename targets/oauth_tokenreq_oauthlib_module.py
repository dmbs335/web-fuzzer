"""Persistent module -- real oauthlib token request target."""

from oauth_tokenreq_oauthlib import process_oauth


def process(input_str):
    try:
        output = process_oauth(input_str)
        return {"output": output, "exit_code": 0}
    except Exception:
        return {"output": "", "exit_code": 1}
