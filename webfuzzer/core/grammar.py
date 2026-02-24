"""Grammar Intermediate Representation (IR).

Defines the core data structures that represent a parsed grammar:
Symbol → Production → Rule → Grammar
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Symbol:
    """A single symbol within a production.

    Symbols can be:
    - rule_ref: reference to another rule in the same grammar (<tagname>)
    - literal: raw text to emit as-is
    - builtin: built-in generator function (<int>, <string>, etc.)
    - cross_ref: reference to a rule in another grammar (@ecmascript:<program>)
    """

    name: str
    kind: Literal["rule_ref", "literal", "builtin", "cross_ref"]
    params: dict[str, str] = field(default_factory=dict)
    modifier: str | None = None  # '?', '+', '*', '{n,m}'
    grammar_ref: str | None = None  # target grammar name for cross_ref

    def is_terminal(self) -> bool:
        return self.kind in ("literal", "builtin")

    def __repr__(self) -> str:
        mod = self.modifier or ""
        if self.kind == "literal":
            return f"Lit({self.name!r}){mod}"
        if self.kind == "cross_ref":
            return f"@{self.grammar_ref}:<{self.name}>{mod}"
        if self.kind == "builtin":
            p = " ".join(f"{k}={v}" for k, v in self.params.items())
            return f"Builtin(<{self.name} {p}>){mod}" if p else f"Builtin(<{self.name}>){mod}"
        return f"<{self.name}>{mod}"


@dataclass
class Production:
    """A single production alternative — an ordered sequence of symbols.

    Example: `<lt> div <attrs> <gt>` becomes a Production with 4 symbols.
    """

    symbols: list[Symbol]
    weight: int = 1

    def is_terminal(self) -> bool:
        """True if this production contains no rule references."""
        return all(s.is_terminal() for s in self.symbols)


@dataclass
class Rule:
    """A named rule grouping all its alternative productions.

    When multiple lines define the same <rule_name>, they become
    separate Production entries within one Rule.
    """

    name: str
    productions: list[Production] = field(default_factory=list)

    def terminal_productions(self) -> list[Production]:
        """Return productions that don't reference other rules."""
        return [p for p in self.productions if p.is_terminal()]

    def add_production(self, production: Production) -> None:
        self.productions.append(production)


@dataclass
class Grammar:
    """A complete grammar parsed from a .grammar file.

    Contains all rules, metadata directives, and the entry-point rule name.
    """

    name: str
    rules: dict[str, Rule] = field(default_factory=dict)
    root: str = ""
    max_depth: int = 15
    imports: list[str] = field(default_factory=list)

    def get_rule(self, name: str) -> Rule | None:
        return self.rules.get(name)

    def add_rule_production(self, rule_name: str, production: Production) -> None:
        """Add a production to a rule, creating the rule if it doesn't exist."""
        if rule_name not in self.rules:
            self.rules[rule_name] = Rule(name=rule_name)
        self.rules[rule_name].add_production(production)

    def validate(self) -> list[str]:
        """Check for undefined rule references. Returns list of error messages."""
        from .builtins import BUILTIN_REGISTRY

        errors: list[str] = []
        defined = set(self.rules.keys())
        builtins = set(BUILTIN_REGISTRY.keys())

        for rule in self.rules.values():
            for prod in rule.productions:
                for sym in prod.symbols:
                    if sym.kind == "rule_ref" and sym.name not in defined:
                        errors.append(
                            f"Rule <{rule.name}>: undefined reference <{sym.name}>"
                        )
                    if sym.kind == "builtin" and sym.name not in builtins:
                        errors.append(
                            f"Rule <{rule.name}>: unknown builtin <{sym.name}>"
                        )
        return errors
