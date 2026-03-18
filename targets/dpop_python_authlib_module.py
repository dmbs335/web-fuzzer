from dpop_python_authlib import process_dpop


def process(input_str):
    try:
        return {"output": process_dpop(input_str), "exit_code": 0}
    except Exception:
        return {"output": "", "exit_code": 1}
