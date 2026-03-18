"""Persistent module -- strict Python JWT verifier."""

from jwt_python_strict import verify_jwt


def process(input_str):
    try:
        output = verify_jwt(input_str)
        return {"output": output, "exit_code": 0}
    except (ValueError, TypeError):
        return {"output": "", "exit_code": 1}
