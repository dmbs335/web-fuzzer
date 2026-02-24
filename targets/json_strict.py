"""Strict JSON validator — RFC 8259 compliance checker.

Rejects inputs that Python's json.loads() might accept:
  - Duplicate object keys
  - Excessively deep nesting (>100)
  - NaN/Infinity values
  - Trailing data after root value
  - BOM markers

References:
  - RFC 8259 (The JavaScript Object Notation Data Interchange Format)
  - Nicolas Seriot, "Parsing JSON is a Minefield" (2016)
  - Nezha (IEEE S&P'17): differential testing of parser implementations
"""

import json
import sys


MAX_DEPTH = 100


def check_duplicate_keys(pairs):
    """object_pairs_hook that rejects duplicate keys."""
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise ValueError(f"Duplicate key: {key!r}")
        seen.add(key)
    return dict(pairs)


def check_depth(obj, depth=0):
    """Recursively check nesting depth."""
    if depth > MAX_DEPTH:
        raise ValueError(f"Nesting depth exceeds {MAX_DEPTH}")
    if isinstance(obj, dict):
        for v in obj.values():
            check_depth(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            check_depth(v, depth + 1)


def strict_validate(data: str) -> str:
    """Validate JSON with strict RFC 8259 rules."""
    # Reject BOM
    if data.startswith("\ufeff"):
        raise ValueError("BOM not allowed in JSON")

    # Parse with duplicate key detection
    obj = json.loads(data, object_pairs_hook=check_duplicate_keys)

    # Reject NaN/Infinity (should not appear in valid JSON)
    _check_no_special_floats(obj)

    # Check depth
    check_depth(obj)

    # Re-serialize to canonical form for output comparison
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)


def _check_no_special_floats(obj):
    if isinstance(obj, float):
        if obj != obj or obj == float("inf") or obj == float("-inf"):
            raise ValueError(f"Special float not allowed: {obj}")
    elif isinstance(obj, dict):
        for v in obj.values():
            _check_no_special_floats(v)
    elif isinstance(obj, list):
        for v in obj:
            _check_no_special_floats(v)


def main():
    if len(sys.argv) < 2:
        print("Usage: json_strict.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = strict_validate(data)
        print(result)
        sys.exit(0)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
