"""Persistent module — PHP parse_url() URL parser.

Exports process(input) for use with persistent_wrapper.py.
Calls PHP CLI for each input (PHP starts fast ~10ms).
"""
import json
import subprocess
import tempfile
import os


def process(input_str):
    input_str = input_str.strip()
    if not input_str:
        return {"output": "", "exit_code": 1}

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write(input_str)
            tmp_path = f.name

        try:
            proc = subprocess.run(
                ["php", os.path.join(os.path.dirname(__file__), "url_php_parse_url.php"), tmp_path],
                capture_output=True,
                timeout=5,
                stdin=subprocess.DEVNULL,
            )
            if proc.returncode == 0:
                return {"output": proc.stdout.decode("utf-8", errors="replace").strip(), "exit_code": 0}
            else:
                return {"output": "", "exit_code": proc.returncode}
        finally:
            os.unlink(tmp_path)
    except Exception:
        return {"output": "", "exit_code": -1}
