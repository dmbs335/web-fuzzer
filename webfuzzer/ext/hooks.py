"""Extension hooks for post-processing and custom generation logic.

Hooks allow users to modify generated output at various stages:
- pre_generate: Before generation starts (can modify grammar/rule selection)
- post_produce: After a single production is expanded (can modify the string)
- post_generate: After full generation is complete (final transformation)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


# Hook function signatures
PreGenerateHook = Callable[[str, str], tuple[str, str]]  # (grammar, rule) -> (grammar, rule)
PostProduceHook = Callable[[str, str, str], str]  # (grammar, rule, output) -> output
PostGenerateHook = Callable[[str, str], str]  # (grammar, output) -> output


@dataclass
class HookRegistry:
    """Registry for generation hooks."""

    pre_generate: list[PreGenerateHook] = field(default_factory=list)
    post_produce: list[PostProduceHook] = field(default_factory=list)
    post_generate: list[PostGenerateHook] = field(default_factory=list)

    def on_pre_generate(self, func: PreGenerateHook) -> PreGenerateHook:
        """Decorator to register a pre-generate hook."""
        self.pre_generate.append(func)
        return func

    def on_post_produce(self, func: PostProduceHook) -> PostProduceHook:
        """Decorator to register a post-produce hook."""
        self.post_produce.append(func)
        return func

    def on_post_generate(self, func: PostGenerateHook) -> PostGenerateHook:
        """Decorator to register a post-generate hook."""
        self.post_generate.append(func)
        return func

    def run_pre_generate(self, grammar: str, rule: str) -> tuple[str, str]:
        for hook in self.pre_generate:
            grammar, rule = hook(grammar, rule)
        return grammar, rule

    def run_post_produce(self, grammar: str, rule: str, output: str) -> str:
        for hook in self.post_produce:
            output = hook(grammar, rule, output)
        return output

    def run_post_generate(self, grammar: str, output: str) -> str:
        for hook in self.post_generate:
            output = hook(grammar, output)
        return output
