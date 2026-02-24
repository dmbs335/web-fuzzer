"""Generation engine — walks Grammar IR to produce output strings.

Core algorithm:
1. Start from root rule
2. Select a production alternative (weighted random)
3. Expand each symbol in the production's sequence
4. Handle modifiers (?, +, *, {n,m})
5. Recurse into rule references; call builtins for builtin symbols
6. Respect max_depth to prevent infinite recursion
"""

from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING

from .builtins import BUILTIN_REGISTRY
from .grammar import Grammar, Production, Rule, Symbol

if TYPE_CHECKING:
    from .registry import GrammarRegistry

# Regex for parsing {min,max} repeat modifier
RE_BOUNDED_REPEAT = re.compile(r"\{(\d+),(\d+)\}")


class GenerationError(Exception):
    """Raised when generation fails."""


class Generator:
    """Walks grammar rules to produce randomized output strings."""

    def __init__(
        self,
        registry: GrammarRegistry,
        seed: int | None = None,
        max_depth_override: int | None = None,
    ):
        self.registry = registry
        self.rng = random.Random(seed)
        self.depth = 0
        self.max_depth_override = max_depth_override

    def generate(
        self,
        grammar_name: str,
        rule_name: str | None = None,
        *,
        max_depth: int | None = None,
    ) -> str:
        """Generate a string from the specified grammar.

        Args:
            grammar_name: Name of the grammar to use.
            rule_name: Starting rule (defaults to grammar's root).
            max_depth: Override max recursion depth for this generation.

        Returns:
            Generated string.
        """
        grammar = self.registry.get(grammar_name)
        if grammar is None:
            raise GenerationError(f"Grammar {grammar_name!r} not found in registry")

        if rule_name is None:
            rule_name = grammar.root
        if not rule_name:
            raise GenerationError(
                f"Grammar {grammar_name!r} has no root rule and none specified"
            )

        effective_max = (
            max_depth
            or self.max_depth_override
            or grammar.max_depth
        )

        self.depth = 0
        try:
            return self._expand_rule(grammar, rule_name, effective_max)
        except RecursionError:
            # Python stack overflow — grammar is too deeply nested for this seed
            return ""

    def _expand_rule(
        self, grammar: Grammar, rule_name: str, max_depth: int
    ) -> str:
        """Expand a rule by selecting a production and expanding its symbols."""
        rule = grammar.get_rule(rule_name)
        if rule is None:
            raise GenerationError(
                f"Undefined rule <{rule_name}> in grammar {grammar.name!r}"
            )

        self.depth += 1
        try:
            # Hard ceiling: force terminal at 2x max_depth regardless
            if self.depth >= max_depth * 2:
                terminals = rule.terminal_productions()
                if terminals:
                    return "".join(
                        self._expand_symbol_once(grammar, s, max_depth)
                        for s in terminals[0].symbols
                    )
                return ""

            production = self._select_production(rule, max_depth)
            parts = [
                self._expand_symbol(grammar, sym, max_depth)
                for sym in production.symbols
            ]
            return "".join(parts)
        finally:
            self.depth -= 1

    def _select_production(self, rule: Rule, max_depth: int) -> Production:
        """Select a production alternative, preferring terminals at max depth."""
        productions = rule.productions
        if not productions:
            raise GenerationError(f"Rule <{rule.name}> has no productions")

        if self.depth >= max_depth:
            # At max depth: prefer terminal productions to avoid infinite recursion
            terminals = rule.terminal_productions()
            if terminals:
                productions = terminals
            else:
                # No terminal: pick the production with the fewest rule references
                productions = sorted(
                    productions,
                    key=lambda p: sum(
                        1 for s in p.symbols
                        if s.kind in ("rule_ref", "cross_ref")
                    ),
                )[:1]

        weights = [p.weight for p in productions]
        return self.rng.choices(productions, weights=weights, k=1)[0]

    def _expand_symbol(
        self, grammar: Grammar, symbol: Symbol, max_depth: int
    ) -> str:
        """Expand a single symbol to a string, handling modifiers."""
        # Apply modifier wrapping
        if symbol.modifier:
            return self._apply_modifier(grammar, symbol, max_depth)

        return self._expand_symbol_once(grammar, symbol, max_depth)

    def _expand_symbol_once(
        self, grammar: Grammar, symbol: Symbol, max_depth: int
    ) -> str:
        """Expand a symbol exactly once (no modifier handling)."""
        if symbol.kind == "literal":
            return symbol.name

        if symbol.kind == "builtin":
            func = BUILTIN_REGISTRY.get(symbol.name)
            if func is None:
                raise GenerationError(f"Unknown builtin <{symbol.name}>")
            return func(self.rng, symbol.params)

        if symbol.kind == "rule_ref":
            return self._expand_rule(grammar, symbol.name, max_depth)

        if symbol.kind == "cross_ref":
            ref_grammar_name = symbol.grammar_ref
            if ref_grammar_name is None:
                raise GenerationError(
                    f"Cross-ref symbol <{symbol.name}> missing grammar name"
                )
            ref_grammar = self.registry.get(ref_grammar_name)
            if ref_grammar is None:
                raise GenerationError(
                    f"Cross-ref grammar {ref_grammar_name!r} not found"
                )
            return self._expand_rule(ref_grammar, symbol.name, max_depth)

        raise GenerationError(f"Unknown symbol kind: {symbol.kind}")

    def _apply_modifier(
        self, grammar: Grammar, symbol: Symbol, max_depth: int
    ) -> str:
        """Apply repeat/optional modifiers to a symbol expansion."""
        mod = symbol.modifier

        # Create a copy without modifier for expansion
        bare = Symbol(
            name=symbol.name,
            kind=symbol.kind,
            params=symbol.params,
            modifier=None,
            grammar_ref=symbol.grammar_ref,
        )

        if mod == "?":
            # Optional: 50% chance to appear
            if self.rng.random() < 0.5:
                return ""
            return self._expand_symbol_once(grammar, bare, max_depth)

        if mod == "*":
            # Zero or more (0-5, biased toward fewer)
            count = self.rng.choices(
                range(6), weights=[3, 3, 2, 1, 1, 1], k=1
            )[0]
        elif mod == "+":
            # One or more (1-5, biased toward fewer)
            count = self.rng.choices(
                range(1, 6), weights=[3, 2, 1, 1, 1], k=1
            )[0]
        else:
            # {min,max}
            m = RE_BOUNDED_REPEAT.match(mod)
            if not m:
                raise GenerationError(f"Invalid modifier: {mod!r}")
            lo, hi = int(m.group(1)), int(m.group(2))
            count = self.rng.randint(lo, hi)

        # At max depth, minimize repetitions
        if self.depth >= max_depth:
            count = min(count, 1) if mod != "*" else 0

        parts = [
            self._expand_symbol_once(grammar, bare, max_depth)
            for _ in range(count)
        ]
        return "".join(parts)
