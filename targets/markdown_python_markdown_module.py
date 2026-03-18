"""Persistent module -- Python-Markdown renderer.
Exports process(input) for use with persistent_wrapper.py.
"""
from markdown_python_markdown import render_markdown


def process(input_str):
    try:
        output = render_markdown(input_str)
        return {"output": output, "exit_code": 0}
    except (ValueError, TypeError):
        return {"output": "", "exit_code": 1}
