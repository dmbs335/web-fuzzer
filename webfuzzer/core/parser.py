"""DSL Parser — converts .grammar files into Grammar IR.

Grammar DSL syntax:
    # comment
    !directive value
    <rule_name> = expression

Expressions contain symbols separated by whitespace:
    literal text          → Literal symbol
    <rule_name>           → Rule reference
    <builtin key=val>     → Built-in function call
    @grammar:<rule>       → Cross-grammar reference
    <rule?>               → Optional (50% chance)
    <rule+>               → One or more repetitions
    <rule*>               → Zero or more repetitions
    <rule{2,5}>           → Bounded repetitions
    [weight=N] ...        → Weight annotation for this production
"""

from __future__ import annotations

import re
from pathlib import Path

from .grammar import Grammar, Production, Rule, Symbol


# --- Regex patterns ---

# Matches a directive line: !directive_name value
RE_DIRECTIVE = re.compile(r"^!(\w+)\s+(.+)$")

# Matches a rule definition: <rule_name> = expression (RHS may be empty)
RE_RULE_DEF = re.compile(r"^<(\w+)>\s*=\s*(.*)$")

# Matches weight annotation at the start of an expression: [weight=5]
RE_WEIGHT = re.compile(r"^\[weight=(\d+)\]\s*")

# Matches a cross-grammar reference: @grammar_name:<rule_name> with optional modifier
RE_CROSS_REF = re.compile(r"@(\w+):<(\w+)>([?+*]|\{\d+,\d+\})?")

# Matches a builtin or rule reference: <name...> with modifier inside or outside brackets
# Supports: <rule>, <rule?>, <rule+>, <rule*>, <rule{2,5}>,
#           <builtin key=val>, <builtin key=val>?
RE_SYMBOL = re.compile(
    r"<(\w+)"                                    # opening < and name
    r"((?:\s+\w+=[^\s>]+)*(?:\s+[^\s>]+)*)?"    # optional params (stop at >)
    r"\s*"
    r"([?+*]|\{\d+,\d+\})?"                     # modifier INSIDE brackets
    r">"
    r"([?+*]|\{\d+,\d+\})?"                     # modifier OUTSIDE brackets
)


class ParseError(Exception):
    """Raised when a grammar file contains invalid syntax."""

    def __init__(self, message: str, file: str = "", line_num: int = 0):
        self.file = file
        self.line_num = line_num
        loc = f"{file}:{line_num}" if file else f"line {line_num}"
        super().__init__(f"{loc}: {message}")


class GrammarParser:
    """Parses .grammar DSL files into Grammar IR objects."""

    def __init__(self) -> None:
        self._builtin_names: set[str] | None = None

    @property
    def builtin_names(self) -> set[str]:
        if self._builtin_names is None:
            from .builtins import BUILTIN_REGISTRY
            self._builtin_names = set(BUILTIN_REGISTRY.keys())
        return self._builtin_names

    def parse_file(self, path: Path) -> Grammar:
        """Parse a .grammar file and return a Grammar object."""
        text = path.read_text(encoding="utf-8")
        name = path.stem
        return self.parse_string(text, name=name, file=str(path))

    def parse_string(self, text: str, name: str = "unnamed", file: str = "") -> Grammar:
        """Parse grammar DSL text and return a Grammar object."""
        grammar = Grammar(name=name)

        for line_num, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # Try directive
            if line.startswith("!"):
                self._parse_directive(grammar, line, file, line_num)
                continue

            # Try rule definition
            m = RE_RULE_DEF.match(line)
            if m:
                rule_name = m.group(1)
                expr = m.group(2).strip()
                production = self._parse_expression(expr, file, line_num)
                grammar.add_rule_production(rule_name, production)
                continue

            raise ParseError(f"Unrecognized syntax: {line!r}", file, line_num)

        # Auto-detect root if not set
        if not grammar.root and grammar.rules:
            grammar.root = next(iter(grammar.rules))

        return grammar

    def _parse_directive(
        self, grammar: Grammar, line: str, file: str, line_num: int
    ) -> None:
        """Parse a !directive line."""
        m = RE_DIRECTIVE.match(line)
        if not m:
            raise ParseError(f"Invalid directive: {line!r}", file, line_num)

        name = m.group(1).lower()
        value = m.group(2).strip()

        if name == "max_depth":
            try:
                grammar.max_depth = int(value)
            except ValueError:
                raise ParseError(
                    f"!max_depth requires integer, got {value!r}", file, line_num
                )
        elif name == "import":
            grammar.imports.append(value)
        elif name == "root":
            # Strip angle brackets if present: <rule_name> → rule_name
            root = value.strip("<>")
            grammar.root = root
        else:
            raise ParseError(f"Unknown directive !{name}", file, line_num)

    def _parse_expression(
        self, expr: str, file: str, line_num: int
    ) -> Production:
        """Parse the right-hand side of a rule definition into a Production."""
        weight = 1

        # Check for weight annotation
        m = RE_WEIGHT.match(expr)
        if m:
            weight = int(m.group(1))
            expr = expr[m.end():]

        symbols = self._tokenize_expression(expr, file, line_num) if expr else []
        return Production(symbols=symbols, weight=weight)

    def _tokenize_expression(
        self, expr: str, file: str, line_num: int
    ) -> list[Symbol]:
        """Tokenize an expression string into a list of Symbols.

        Scans left-to-right, matching cross-refs, symbol refs, or
        collecting literal text between them.
        """
        symbols: list[Symbol] = []
        pos = 0
        literal_buf: list[str] = []

        def flush_literal() -> None:
            if literal_buf:
                text = "".join(literal_buf)
                if text:
                    symbols.append(Symbol(name=text, kind="literal"))
                literal_buf.clear()

        while pos < len(expr):
            # Try cross-grammar reference: @grammar:<rule>
            m = RE_CROSS_REF.match(expr, pos)
            if m:
                flush_literal()
                symbols.append(Symbol(
                    name=m.group(2),
                    kind="cross_ref",
                    grammar_ref=m.group(1),
                    modifier=m.group(3),
                ))
                pos = m.end()
                continue

            # Try symbol reference: <name params?modifier?>modifier?
            m = RE_SYMBOL.match(expr, pos)
            if m and expr[pos] == "<":
                flush_literal()
                sym_name = m.group(1)
                raw_params = (m.group(2) or "").strip()
                # Modifier can be inside <rule?> or outside <rule>?
                modifier = m.group(3) or m.group(4)

                if sym_name in self.builtin_names:
                    params = self._parse_params(raw_params)
                    symbols.append(Symbol(
                        name=sym_name,
                        kind="builtin",
                        params=params,
                        modifier=modifier,
                    ))
                else:
                    if raw_params:
                        # Non-builtin rules shouldn't have params
                        raise ParseError(
                            f"Rule reference <{sym_name}> cannot have parameters "
                            f"(did you mean a builtin?)",
                            file,
                            line_num,
                        )
                    symbols.append(Symbol(
                        name=sym_name,
                        kind="rule_ref",
                        modifier=modifier,
                    ))
                pos = m.end()
                continue

            # Accumulate literal character
            literal_buf.append(expr[pos])
            pos += 1

        flush_literal()
        return symbols

    @staticmethod
    def _parse_params(raw: str) -> dict[str, str]:
        """Parse 'key=value key2=value2 ...' or positional args into a dict."""
        if not raw:
            return {}

        params: dict[str, str] = {}
        positional_idx = 0

        for token in raw.split():
            if "=" in token:
                key, _, val = token.partition("=")
                params[key] = val
            else:
                # Positional args stored as _0, _1, ...
                params[f"_{positional_idx}"] = token
                positional_idx += 1

        return params
