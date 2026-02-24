"""Lenient JSON parser — accepts JSON supersets.

Deliberately more permissive than RFC 8259:
  - Allows trailing commas in arrays and objects
  - Allows single-quoted strings
  - Allows comments (// and /* */)
  - Allows duplicate keys (last wins)
  - Allows unquoted keys that look like identifiers
  - No depth limit
  - Allows trailing whitespace/data (ignores it)

This simulates a real-world "lenient" parser like those found in
JavaScript engines, config file parsers, or HJSON/JSON5 parsers.

References:
  - JSON5 specification (https://json5.org/)
  - HJSON (Human JSON)
  - Nezha (S&P'17): tests parsers with different strictness levels
  - Seriot, "Parsing JSON is a Minefield" (2016)
"""

import json
import re
import sys


def preprocess(data: str) -> str:
    """Transform JSON superset features into standard JSON."""
    # Strip BOM
    if data.startswith("\ufeff"):
        data = data[1:]

    # Remove single-line comments (// ...)
    data = re.sub(r"//[^\n]*", "", data)

    # Remove multi-line comments (/* ... */)
    data = re.sub(r"/\*.*?\*/", "", data, flags=re.DOTALL)

    # Replace single-quoted strings with double-quoted
    # (simplified: only handles non-nested cases)
    data = re.sub(r"'([^']*)'", r'"\1"', data)

    # Remove trailing commas before } or ]
    data = re.sub(r",\s*([}\]])", r"\1", data)

    # Quote unquoted keys: { key: value } -> { "key": value }
    data = re.sub(r"(?<=[\{,])\s*([a-zA-Z_]\w*)\s*:", r' "\1":', data)

    return data


def lenient_parse(data: str) -> str:
    """Parse JSON with lenient preprocessing."""
    processed = preprocess(data)

    # Try parsing the preprocessed version
    obj = json.loads(processed)

    # Re-serialize to canonical form
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)


def main():
    if len(sys.argv) < 2:
        print("Usage: json_lenient.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = lenient_parse(data)
        print(result)
        sys.exit(0)
    except (json.JSONDecodeError, ValueError, TypeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
