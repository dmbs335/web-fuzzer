"""Markdown target -- mistune library.

Usage: python markdown_python_mistune.py <input_file>
Output: JSON with security signals.
"""
import json
import sys

import mistune

from markdown_analysis_common import analyze_rendered_html


def render_markdown(input_str: str) -> str:
    """Render markdown and return JSON result."""
    html = mistune.html(input_str)
    result = analyze_rendered_html(html)
    return json.dumps(result)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python markdown_python_mistune.py <input_file>\n")
        sys.exit(1)
    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            md_input = f.read()
        output = render_markdown(md_input)
        sys.stdout.write(output)
    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
