"""Grammar-based InputSource and DerivationTree for AST-level mutation.

Bridges the existing core/generator.py engine with the fuzzer framework.
Provides:
  - GrammarInputSource: wraps Generator as InputSource Protocol
  - DerivationTree / TreeNode: records generation choices for AST mutation
  - TreeGenerator: generates inputs while building derivation trees
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.builtins import BUILTIN_REGISTRY
from ..core.grammar import Grammar, Production, Rule, Symbol
from .protocols import Input

if TYPE_CHECKING:
    from ..core.registry import GrammarRegistry
    from .mcts import UCBTable
    from .protocols import ScheduleResult

RE_BOUNDED_REPEAT = re.compile(r"\{(\d+),(\d+)\}")


# ── DerivationTree ────────────────────────────────────────────────

@dataclass
class TreeNode:
    """A node in the derivation tree, recording one expansion step."""

    symbol: Symbol
    rule_name: str | None = None
    production_idx: int = -1
    children: list[TreeNode] = field(default_factory=list)
    value: str = ""   # terminal value for leaf nodes

    def to_string(self) -> str:
        """Reconstruct the generated string from this subtree."""
        if self.children:
            return "".join(child.to_string() for child in self.children)
        return self.value

    def all_rule_nodes(self) -> list[TreeNode]:
        """Collect all nodes that expanded a rule (non-leaf, non-builtin)."""
        nodes: list[TreeNode] = []
        if self.rule_name is not None:
            nodes.append(self)
        for child in self.children:
            nodes.extend(child.all_rule_nodes())
        return nodes

    def depth(self) -> int:
        if not self.children:
            return 0
        return 1 + max(c.depth() for c in self.children)

    def derivation_path(self) -> list[tuple[str, int]]:
        """Extract the sequence of (rule_name, production_idx) decisions."""
        path: list[tuple[str, int]] = []
        if self.rule_name is not None and self.production_idx >= 0:
            path.append((self.rule_name, self.production_idx))
        for child in self.children:
            path.extend(child.derivation_path())
        return path

    def clone(self) -> TreeNode:
        return TreeNode(
            symbol=self.symbol,
            rule_name=self.rule_name,
            production_idx=self.production_idx,
            children=[c.clone() for c in self.children],
            value=self.value,
        )


@dataclass
class DerivationTree:
    """Records the full derivation of a grammar-generated string.

    Used by GrammarMutator for AST-level mutation (Nautilus/Superion style).
    """

    root: TreeNode
    grammar_name: str

    def to_string(self) -> str:
        return self.root.to_string()

    def to_bytes(self) -> bytes:
        return self.to_string().encode("utf-8")

    def random_subtree(self, rng: random.Random) -> TreeNode | None:
        """Select a random rule-expansion node in the tree."""
        nodes = self.root.all_rule_nodes()
        if not nodes:
            return None
        return rng.choice(nodes)

    def clone(self) -> DerivationTree:
        return DerivationTree(root=self.root.clone(), grammar_name=self.grammar_name)


# ── TreeGenerator ─────────────────────────────────────────────────

class TreeGenerator:
    """Generates strings while building a DerivationTree.

    Same algorithm as core/generator.py but records the derivation path.
    Optionally uses a :class:`UCBTable` for UCB-guided production
    selection (UCB1 instead of weighted random).
    """

    def __init__(
        self,
        registry: GrammarRegistry,
        seed: int | None = None,
        ucb_table: "UCBTable | None" = None,
    ) -> None:
        self.registry = registry
        self.rng = random.Random(seed)
        self.depth = 0
        self.ucb_table = ucb_table

    def generate_tree(
        self,
        grammar_name: str,
        rule_name: str | None = None,
        max_depth: int | None = None,
    ) -> DerivationTree:
        """Generate a string and return its derivation tree."""
        grammar = self.registry.get(grammar_name)
        if grammar is None:
            raise ValueError(f"Grammar {grammar_name!r} not found")

        if rule_name is None:
            rule_name = grammar.root
        if not rule_name:
            raise ValueError(f"Grammar {grammar_name!r} has no root rule")

        effective_max = max_depth or grammar.max_depth
        self.depth = 0

        root_symbol = Symbol(name=rule_name, kind="rule_ref")
        try:
            root_node = self._expand_rule_tree(grammar, rule_name, effective_max)
        except RecursionError:
            root_node = TreeNode(symbol=root_symbol, value="")

        return DerivationTree(root=root_node, grammar_name=grammar_name)

    def _expand_rule_tree(
        self, grammar: Grammar, rule_name: str, max_depth: int
    ) -> TreeNode:
        rule = grammar.get_rule(rule_name)
        if rule is None:
            sym = Symbol(name=rule_name, kind="rule_ref")
            return TreeNode(symbol=sym, value=f"<{rule_name}>")

        self.depth += 1
        try:
            sym = Symbol(name=rule_name, kind="rule_ref")

            if self.depth >= max_depth * 2:
                terminals = rule.terminal_productions()
                if terminals:
                    prod = terminals[0]
                    prod_idx = rule.productions.index(prod)
                    children = [
                        self._expand_symbol_tree(grammar, s, max_depth)
                        for s in prod.symbols
                    ]
                    return TreeNode(
                        symbol=sym, rule_name=rule_name,
                        production_idx=prod_idx, children=children,
                    )
                return TreeNode(symbol=sym, rule_name=rule_name, value="")

            prod, prod_idx = self._select_production(rule, max_depth)
            children = [
                self._expand_symbol_tree(grammar, s, max_depth)
                for s in prod.symbols
            ]
            return TreeNode(
                symbol=sym, rule_name=rule_name,
                production_idx=prod_idx, children=children,
            )
        finally:
            self.depth -= 1

    def _select_production(
        self, rule: Rule, max_depth: int
    ) -> tuple[Production, int]:
        productions = rule.productions
        if self.depth >= max_depth:
            terminals = rule.terminal_productions()
            if terminals:
                productions = terminals
            else:
                productions = sorted(
                    productions,
                    key=lambda p: sum(
                        1 for s in p.symbols if s.kind in ("rule_ref", "cross_ref")
                    ),
                )[:1]

        weights = [p.weight for p in productions]

        # UCB-guided selection when the experimental table is available.
        if self.ucb_table is not None and rule.name:
            sub_idx = self.ucb_table.select_production(
                rule.name, len(productions), weights,
            )
            chosen = productions[sub_idx]
            idx = rule.productions.index(chosen)
            self.ucb_table.record_visit(rule.name, idx)
            return chosen, idx

        # Default: weighted random selection.
        chosen = self.rng.choices(productions, weights=weights, k=1)[0]
        idx = rule.productions.index(chosen)
        return chosen, idx

    def _expand_symbol_tree(
        self, grammar: Grammar, symbol: Symbol, max_depth: int
    ) -> TreeNode:
        if symbol.modifier:
            return self._apply_modifier_tree(grammar, symbol, max_depth)
        return self._expand_symbol_once_tree(grammar, symbol, max_depth)

    def _expand_symbol_once_tree(
        self, grammar: Grammar, symbol: Symbol, max_depth: int
    ) -> TreeNode:
        if symbol.kind == "literal":
            return TreeNode(symbol=symbol, value=symbol.name)

        if symbol.kind == "builtin":
            func = BUILTIN_REGISTRY.get(symbol.name)
            val = func(self.rng, symbol.params) if func else ""
            return TreeNode(symbol=symbol, value=val)

        if symbol.kind == "rule_ref":
            return self._expand_rule_tree(grammar, symbol.name, max_depth)

        if symbol.kind == "cross_ref" and symbol.grammar_ref:
            ref_grammar = self.registry.get(symbol.grammar_ref)
            if ref_grammar:
                return self._expand_rule_tree(ref_grammar, symbol.name, max_depth)
            return TreeNode(symbol=symbol, value="")

        return TreeNode(symbol=symbol, value="")

    def _apply_modifier_tree(
        self, grammar: Grammar, symbol: Symbol, max_depth: int
    ) -> TreeNode:
        bare = Symbol(
            name=symbol.name, kind=symbol.kind,
            params=symbol.params, modifier=None,
            grammar_ref=symbol.grammar_ref,
        )
        mod = symbol.modifier

        if mod == "?":
            if self.rng.random() < 0.5:
                return TreeNode(symbol=symbol, value="")
            child = self._expand_symbol_once_tree(grammar, bare, max_depth)
            return TreeNode(symbol=symbol, children=[child])

        if mod == "*":
            count = self.rng.choices(range(6), weights=[3, 3, 2, 1, 1, 1], k=1)[0]
        elif mod == "+":
            count = self.rng.choices(range(1, 6), weights=[3, 2, 1, 1, 1], k=1)[0]
        else:
            m = RE_BOUNDED_REPEAT.match(mod)
            if m:
                count = self.rng.randint(int(m.group(1)), int(m.group(2)))
            else:
                count = 1

        if self.depth >= max_depth:
            count = min(count, 1) if mod != "*" else 0

        children = [
            self._expand_symbol_once_tree(grammar, bare, max_depth)
            for _ in range(count)
        ]
        return TreeNode(symbol=symbol, children=children)


# ── GrammarInputSource ────────────────────────────────────────────

class GrammarInputSource:
    """Wraps the grammar TreeGenerator as an InputSource for the fuzzer.

    Generated inputs include the DerivationTree in metadata for
    grammar-aware mutation.

    When a :class:`UCBTable` is provided, the generator uses UCB-guided
    production selection and supports ``update()`` for reward backpropagation.
    """

    def __init__(
        self,
        registry: GrammarRegistry,
        grammar_name: str,
        rule_name: str | None = None,
        seed: int | None = None,
        ucb_table: "UCBTable | None" = None,
    ) -> None:
        self.tree_gen = TreeGenerator(registry, seed=seed, ucb_table=ucb_table)
        self.grammar_name = grammar_name
        self.rule_name = rule_name

    def generate(self) -> Input:
        tree = self.tree_gen.generate_tree(self.grammar_name, self.rule_name)
        data = tree.to_bytes()
        return Input(
            data=data,
            metadata={
                "grammar": self.grammar_name,
                "rule": self.rule_name or "root",
                "source": "grammar",
                "tree": tree,
            },
        )

    def update(self, inp: Input, result: "ScheduleResult") -> None:
        """Backpropagate execution feedback to the UCB1 table.

        Duck-typed — called by the engine only when this method exists.
        No-op when no UCBTable is attached.
        """
        if self.tree_gen.ucb_table is None:
            return
        tree = inp.metadata.get("tree") if inp.metadata else None
        if tree is None:
            return
        reward = 0.0
        if result.found_new_coverage:
            reward += 1.0
        if result.found_crash:
            reward += 5.0
        if reward > 0:
            self.tree_gen.ucb_table.backpropagate(
                tree.root.derivation_path(), reward,
            )
