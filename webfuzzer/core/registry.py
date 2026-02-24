"""Grammar Registry — manages multiple grammars and resolves cross-references.

The registry is the central point for:
- Loading .grammar files from disk
- Storing parsed Grammar objects
- Resolving @grammar:<rule> cross-references
- Validating all grammars after loading
"""

from __future__ import annotations

from pathlib import Path

from .grammar import Grammar, Rule
from .parser import GrammarParser, ParseError


class RegistryError(Exception):
    """Raised for registry-level errors."""


class GrammarRegistry:
    """Central store for all loaded grammars."""

    def __init__(self) -> None:
        self._grammars: dict[str, Grammar] = {}
        self._parser = GrammarParser()

    @property
    def grammar_names(self) -> list[str]:
        return list(self._grammars.keys())

    def get(self, name: str) -> Grammar | None:
        return self._grammars.get(name)

    def register(self, grammar: Grammar) -> None:
        """Register a pre-parsed Grammar object."""
        self._grammars[grammar.name] = grammar

    def load_file(self, path: Path) -> Grammar:
        """Parse and register a single .grammar file."""
        grammar = self._parser.parse_file(path)
        self.register(grammar)
        return grammar

    def load_string(self, text: str, name: str = "unnamed") -> Grammar:
        """Parse and register grammar from a string."""
        grammar = self._parser.parse_string(text, name=name)
        self.register(grammar)
        return grammar

    def load_directory(self, dir_path: Path) -> list[Grammar]:
        """Load all .grammar files from a directory."""
        grammars: list[Grammar] = []
        grammar_dir = Path(dir_path)
        if not grammar_dir.is_dir():
            raise RegistryError(f"Not a directory: {grammar_dir}")

        for path in sorted(grammar_dir.glob("*.grammar")):
            grammar = self.load_file(path)
            grammars.append(grammar)

        return grammars

    def load_builtins(self) -> list[Grammar]:
        """Load all built-in grammar files shipped with the package."""
        builtins_dir = Path(__file__).parent.parent / "grammars"
        if builtins_dir.is_dir():
            return self.load_directory(builtins_dir)
        return []

    def resolve_cross_ref(self, grammar_name: str, rule_name: str) -> Rule:
        """Resolve a @grammar:<rule> cross-reference."""
        grammar = self.get(grammar_name)
        if grammar is None:
            raise RegistryError(
                f"Cross-reference target grammar {grammar_name!r} not loaded"
            )
        rule = grammar.get_rule(rule_name)
        if rule is None:
            raise RegistryError(
                f"Rule <{rule_name}> not found in grammar {grammar_name!r}"
            )
        return rule

    def validate_all(self) -> list[str]:
        """Validate all loaded grammars. Returns list of error messages."""
        errors: list[str] = []

        for grammar in self._grammars.values():
            # Internal validation (undefined rule refs within grammar)
            errors.extend(grammar.validate())

            # Validate cross-grammar imports
            for imp in grammar.imports:
                if imp not in self._grammars:
                    errors.append(
                        f"Grammar {grammar.name!r}: !import {imp!r} "
                        f"but grammar not loaded"
                    )

            # Validate cross-ref symbols point to loaded grammars
            for rule in grammar.rules.values():
                for prod in rule.productions:
                    for sym in prod.symbols:
                        if sym.kind == "cross_ref" and sym.grammar_ref:
                            ref_grammar = self.get(sym.grammar_ref)
                            if ref_grammar is None:
                                errors.append(
                                    f"Grammar {grammar.name!r}, rule <{rule.name}>: "
                                    f"cross-ref @{sym.grammar_ref}:<{sym.name}> "
                                    f"target grammar not loaded"
                                )
                            elif ref_grammar.get_rule(sym.name) is None:
                                errors.append(
                                    f"Grammar {grammar.name!r}, rule <{rule.name}>: "
                                    f"cross-ref @{sym.grammar_ref}:<{sym.name}> "
                                    f"rule not found in target grammar"
                                )

        return errors

    def __contains__(self, name: str) -> bool:
        return name in self._grammars

    def __len__(self) -> int:
        return len(self._grammars)
