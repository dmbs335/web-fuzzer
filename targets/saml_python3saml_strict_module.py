"""Persistent module -- python3-saml strict-mode verifier.

Exports process(input) for use with persistent_wrapper.py.
"""

import os

os.environ["SAML_PYTHON3SAML_STRICT"] = "1"

from saml_python3saml import verify_saml


def process(input_str):
    try:
        output = verify_saml(input_str)
        return {"output": output, "exit_code": 0}
    except (ValueError, TypeError):
        return {"output": "", "exit_code": 1}
