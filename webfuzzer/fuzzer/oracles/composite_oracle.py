"""Composite oracle — chains multiple oracles into one."""

from __future__ import annotations

from ..protocols import ExecutionResult, Finding, Input, Oracle


class CompositeOracle:
    """Runs multiple oracles and returns the first finding."""

    name = "composite"

    def __init__(self, oracles: list[Oracle]) -> None:
        self.oracles = oracles

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        for oracle in self.oracles:
            finding = oracle.check(inp, result)
            if finding:
                return finding
        return None
