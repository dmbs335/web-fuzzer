"""Persistent module -- real authlib token response target."""

from oauth_tokenresp_authlib import process_oauth


def process(input_str):
    try:
        output = process_oauth(input_str)
        return {"output": output, "exit_code": 0}
    except Exception:
        return {"output": "", "exit_code": 1}
