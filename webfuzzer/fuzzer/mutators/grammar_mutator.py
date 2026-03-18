"""Grammar-aware AST-level mutator (Nautilus/Superion style).

Operates on DerivationTrees — mutates at the grammar structure level
rather than byte level. Four mutation strategies:

  1. subtree_replace  — replace a random subtree with a fresh generation
  2. subtree_splice   — swap a subtree with one from another corpus seed
  3. production_swap   — switch which production alternative a rule uses
  4. rule_regenerate   — fully regenerate from a random rule node
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from ..grammar_source import DerivationTree, GrammarInputSource, TreeGenerator, TreeNode
from ..protocols import Input

if TYPE_CHECKING:
    from ...core.registry import GrammarRegistry
    from ..corpus import Seed
    from ..mcts import UCBTable


class GrammarMutator:
    """Grammar-aware AST mutation.

    Requires inputs to have a DerivationTree in metadata["tree"].
    Falls back to regeneration if no tree is available.
    """

    name = "grammar"
    requires_tree = True

    def __init__(
        self,
        registry: GrammarRegistry,
        grammar_name: str,
        rule_name: str | None = None,
        seed: int | None = None,
        ucb_table: "UCBTable | None" = None,
    ) -> None:
        self.registry = registry
        self.grammar_name = grammar_name
        self.rule_name = rule_name
        self.rng = random.Random(seed)
        self.tree_gen = TreeGenerator(registry, seed=seed, ucb_table=ucb_table)
        self._input_source = GrammarInputSource(
            registry, grammar_name, rule_name, seed=seed, ucb_table=ucb_table,
        )

        self._strategies = [
            self._subtree_replace,
            self._subtree_splice,
            self._production_swap,
            self._rule_regenerate,
        ]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        tree: DerivationTree | None = inp.metadata.get("tree")
        if tree is not None and not hasattr(tree, "clone"):
            tree = None  # stale checkpoint data — not a DerivationTree

        if tree is None:
            # No tree available — borrow one from a corpus seed that has one.
            # This avoids discarding valuable file-based seeds entirely.
            for _ in range(min(len(corpus), 10)):
                donor = self.rng.choice(corpus) if corpus else None
                dtree = donor.input.metadata.get("tree") if donor else None
                if dtree is not None and hasattr(dtree, "clone"):
                    tree = dtree.clone()
                    break
            if tree is None:
                # Last resort: generate fresh (no tree-bearing seeds in corpus yet)
                return self._input_source.generate()

        # Clone tree to avoid mutating the original
        tree = tree.clone()

        # Pick a random mutation strategy
        strategy = self.rng.choice(self._strategies)
        success = strategy(tree, corpus)

        if not success:
            # If mutation failed, generate fresh
            return self._input_source.generate()

        data = tree.to_bytes()
        return Input(
            data=data,
            metadata={
                "grammar": self.grammar_name,
                "rule": self.rule_name or "root",
                "source": "grammar",
                "mutator": self.name,
                "tree": tree,
            },
        )

    def _subtree_replace(self, tree: DerivationTree, corpus: list[Seed]) -> bool:
        """Replace a random subtree with a freshly generated one."""
        node = tree.random_subtree(self.rng)
        if node is None or node.rule_name is None:
            return False

        grammar = self.registry.get(tree.grammar_name)
        if grammar is None:
            return False

        # Generate new subtree for the same rule
        new_subtree = self.tree_gen._expand_rule_tree(
            grammar, node.rule_name, grammar.max_depth
        )

        # Replace node contents
        node.production_idx = new_subtree.production_idx
        node.children = new_subtree.children
        node.value = new_subtree.value
        return True

    def _subtree_splice(self, tree: DerivationTree, corpus: list[Seed]) -> bool:
        """Splice a compatible subtree from another corpus seed."""
        node = tree.random_subtree(self.rng)
        if node is None or node.rule_name is None:
            return False

        # Find compatible subtrees in corpus
        target_rule = node.rule_name
        candidates: list[TreeNode] = []

        for seed in corpus:
            other_tree: DerivationTree | None = seed.input.metadata.get("tree")
            if other_tree is None:
                continue
            for other_node in other_tree.root.all_rule_nodes():
                if other_node.rule_name == target_rule:
                    candidates.append(other_node)

        if not candidates:
            return False

        # Pick a random compatible subtree and clone it
        donor = self.rng.choice(candidates).clone()
        node.production_idx = donor.production_idx
        node.children = donor.children
        node.value = donor.value
        return True

    def _production_swap(self, tree: DerivationTree, corpus: list[Seed]) -> bool:
        """Switch a rule node to use a different production alternative."""
        node = tree.random_subtree(self.rng)
        if node is None or node.rule_name is None:
            return False

        grammar = self.registry.get(tree.grammar_name)
        if grammar is None:
            return False

        rule = grammar.get_rule(node.rule_name)
        if rule is None or len(rule.productions) <= 1:
            return False

        # Pick a different production
        current_idx = node.production_idx
        other_indices = [i for i in range(len(rule.productions)) if i != current_idx]
        if not other_indices:
            return False

        new_idx = self.rng.choice(other_indices)
        prod = rule.productions[new_idx]

        # Regenerate children for the new production
        children = [
            self.tree_gen._expand_symbol_tree(grammar, s, grammar.max_depth)
            for s in prod.symbols
        ]
        node.production_idx = new_idx
        node.children = children
        node.value = ""
        return True

    def _rule_regenerate(self, tree: DerivationTree, corpus: list[Seed]) -> bool:
        """Fully regenerate from the root — essentially a fresh generation
        but reusing the tree structure."""
        grammar = self.registry.get(tree.grammar_name)
        if grammar is None:
            return False

        rule_name = self.rule_name or grammar.root
        if not rule_name:
            return False

        new_root = self.tree_gen._expand_rule_tree(
            grammar, rule_name, grammar.max_depth
        )
        tree.root = new_root
        return True
