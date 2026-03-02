"""Persistent module -- signxml SAML verifier.

Exports process(input) for use with persistent_wrapper.py.
"""

from saml_signxml import verify_saml


def process(input_str):
    try:
        output = verify_saml(input_str)
        return {"output": output, "exit_code": 0}
    except (ValueError, TypeError):
        return {"output": "", "exit_code": 1}
