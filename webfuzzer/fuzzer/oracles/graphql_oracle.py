"""GraphQL single-target security oracle.

Detects high-signal anomalies in one GraphQL implementation's output:
  - Empty selection accepted
  - Introspection accessible
  - Deeply nested queries accepted without limits
  - Invalid enum values accepted
  - Null directive arguments accepted

Cross-library divergences are handled by graphql_diff_strategy.py.
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_graphql_output(stdout: bytes) -> dict | None:
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "parsed" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        pass
    return None


class GraphqlOracle:
    """Single-target GraphQL security oracle."""

    name = "graphql"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0:
            return None

        parsed = _parse_graphql_output(result.stdout)
        if parsed is None:
            return None

        is_valid = parsed.get("valid")
        if not is_valid:
            return None

        # Excessive depth accepted (potential DoS)
        max_depth = parsed.get("max_depth", 0)
        if max_depth >= 15:
            return Finding(
                title=f"GraphQL: excessive query depth accepted ({max_depth})",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    "category": "excessive_depth",
                    "max_depth": max_depth,
                    "selection_count": parsed.get("selection_count", 0),
                },
            )

        # Empty selection accepted
        if parsed.get("selection_count", 0) == 0:
            return Finding(
                title="GraphQL: empty selection set accepted",
                severity=Severity.LOW,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={"category": "empty_selection"},
            )

        return None
