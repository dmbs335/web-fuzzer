"""Built-in generator functions for grammar symbols.

These handle special symbols like <int>, <string>, <hex>, etc.
Each function receives a random.Random instance and a params dict,
and returns a generated string.
"""

from __future__ import annotations

import random
import string
from typing import Callable

# Type for builtin generator functions
BuiltinFunc = Callable[[random.Random, dict[str, str]], str]

# Global registry of builtin functions
BUILTIN_REGISTRY: dict[str, BuiltinFunc] = {}


def register_builtin(name: str, func: BuiltinFunc) -> None:
    """Register a custom builtin function."""
    BUILTIN_REGISTRY[name] = func


def _builtin(name: str) -> Callable[[BuiltinFunc], BuiltinFunc]:
    """Decorator to register a builtin function."""
    def decorator(func: BuiltinFunc) -> BuiltinFunc:
        BUILTIN_REGISTRY[name] = func
        return func
    return decorator


# --- Built-in implementations ---


@_builtin("int")
def generate_int(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a random integer. Params: min, max."""
    lo = int(params.get("min", "0"))
    hi = int(params.get("max", "65535"))
    return str(rng.randint(lo, hi))


@_builtin("float")
def generate_float(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a random float. Params: min, max, precision."""
    lo = float(params.get("min", "0.0"))
    hi = float(params.get("max", "1.0"))
    precision = int(params.get("precision", "6"))
    return f"{rng.uniform(lo, hi):.{precision}f}"


@_builtin("string")
def generate_string(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a random alphanumeric string. Params: min, max, charset."""
    lo = int(params.get("min", "1"))
    hi = int(params.get("max", "16"))
    charset_name = params.get("charset", "alphanumeric")

    charset_map = {
        "alpha": string.ascii_letters,
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digit": string.digits,
        "alphanumeric": string.ascii_letters + string.digits,
        "hex": string.hexdigits[:16],
        "printable": string.printable.strip(),
    }
    charset = charset_map.get(charset_name, string.ascii_letters + string.digits)

    length = rng.randint(lo, hi)
    return "".join(rng.choices(charset, k=length))


@_builtin("hex")
def generate_hex(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a random hex string. Params: len, prefix."""
    length = int(params.get("len", "8"))
    prefix = params.get("prefix", "")
    hex_chars = "0123456789abcdef"
    return prefix + "".join(rng.choices(hex_chars, k=length))


@_builtin("char")
def generate_char(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a random character. Params: charset."""
    charset_name = params.get("charset", "printable")
    charset_map = {
        "alpha": string.ascii_letters,
        "lower": string.ascii_lowercase,
        "upper": string.ascii_uppercase,
        "digit": string.digits,
        "printable": string.printable.strip(),
        "ascii": "".join(chr(i) for i in range(32, 127)),
    }
    charset = charset_map.get(charset_name, string.printable.strip())
    return rng.choice(charset)


@_builtin("range")
def generate_range(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a number within a range. Params: start, end, step."""
    start = int(params.get("start", "0"))
    end = int(params.get("end", "100"))
    step = int(params.get("step", "1"))
    return str(rng.choice(range(start, end + 1, step)))


@_builtin("oneof")
def generate_oneof(rng: random.Random, params: dict[str, str]) -> str:
    """Pick one from positional arguments. Usage: <oneof a b c d>."""
    # Positional args are stored as _0, _1, _2, ...
    choices = [v for k, v in sorted(params.items()) if k.startswith("_")]
    if not choices:
        return ""
    return rng.choice(choices)


@_builtin("byte")
def generate_byte(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a raw byte value as \\xNN. Params: min, max."""
    lo = int(params.get("min", "0"))
    hi = int(params.get("max", "255"))
    val = rng.randint(lo, hi)
    return f"\\x{val:02x}"


@_builtin("codepoint")
def generate_codepoint(rng: random.Random, params: dict[str, str]) -> str:
    """Generate a Unicode codepoint. Params: min, max."""
    lo = int(params.get("min", "0"))
    hi = int(params.get("max", "65535"))
    val = rng.randint(lo, hi)
    try:
        return chr(val)
    except (ValueError, OverflowError):
        return chr(lo)


# --- Literal character builtins (for disambiguation) ---


@_builtin("lt")
def generate_lt(rng: random.Random, params: dict[str, str]) -> str:
    """Produce a literal '<' character."""
    return "<"


@_builtin("gt")
def generate_gt(rng: random.Random, params: dict[str, str]) -> str:
    """Produce a literal '>' character."""
    return ">"


@_builtin("amp")
def generate_amp(rng: random.Random, params: dict[str, str]) -> str:
    """Produce a literal '&' character."""
    return "&"


@_builtin("quot")
def generate_quot(rng: random.Random, params: dict[str, str]) -> str:
    """Produce a literal '"' character."""
    return '"'


@_builtin("nl")
def generate_nl(rng: random.Random, params: dict[str, str]) -> str:
    """Produce a newline character."""
    return "\n"


@_builtin("sp")
def generate_sp(rng: random.Random, params: dict[str, str]) -> str:
    """Produce a space character."""
    return " "


@_builtin("empty")
def generate_empty(rng: random.Random, params: dict[str, str]) -> str:
    """Produce an empty string (useful as a no-op alternative)."""
    return ""
