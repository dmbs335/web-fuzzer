"""Persistent module -- Authlib Python JWT verifier."""

from jwt_python_authlib import verify_jwt


def process(input_str):
    try:
        output = verify_jwt(input_str)
        return {"output": output, "exit_code": 0}
    except Exception:
        return {"output": "", "exit_code": 1}
