"""Persistent module -- PyJWT Python JWT verifier."""

from jwt_python_pyjwt import verify_jwt


def process(input_str):
    try:
        output = verify_jwt(input_str)
        return {"output": output, "exit_code": 0}
    except Exception:
        return {"output": "", "exit_code": 1}
