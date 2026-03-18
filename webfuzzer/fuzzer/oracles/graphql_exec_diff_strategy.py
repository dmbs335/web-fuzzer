"""GraphQL EXECUTION differential strategies.

Compares execution semantics (not just parse/validate) across implementations.
Targets the space where implementations actually diverge: null propagation,
error handling, partial results, type coercion at execution time.

  GX1  Data shape divergence      -- response structures differ
  GX2  Null propagation           -- null bubbles up differently
  GX3  Error path divergence      -- execution errors at different fields
  GX4  Partial data divergence    -- one returns partial data, other doesn't
  GX5  Execution acceptance split -- one executes, other rejects at execution
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_exec_output(stdout: bytes) -> dict | None:
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "parsed" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:400].decode("utf-8", errors="replace")


# -- GX1: Data Shape Divergence ------------------------------------------------

class GraphqlExecDataShapeStrategy:
    """Response data structure (shape) differs between implementations."""

    name = "graphql_exec_data_shape"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_exec_output(primary.stdout)
        r = _parse_exec_output(reference.stdout)
        if p is None or r is None:
            return None

        # Both must have executed
        if not p.get("executed") or not r.get("executed"):
            return None

        p_shape = p.get("data_shape")
        r_shape = r.get("data_shape")

        if p_shape == r_shape:
            return None

        return Finding(
            title=f"GraphQL exec: data shape divergence",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "exec_data_shape_divergence",
                "ref_index": ref_index,
                "primary_shape": str(p_shape)[:300],
                "ref_shape": str(r_shape)[:300],
                "primary_data_hash": p.get("data_hash"),
                "ref_data_hash": r.get("data_hash"),
                "input_preview": _input_preview(inp),
            },
        )


# -- GX2: Null Propagation Divergence -----------------------------------------

class GraphqlExecNullPropagationStrategy:
    """Null propagation paths differ -- the core execution differential."""

    name = "graphql_exec_null_propagation"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_exec_output(primary.stdout)
        r = _parse_exec_output(reference.stdout)
        if p is None or r is None:
            return None

        if not p.get("executed") or not r.get("executed"):
            return None

        p_nulls = set(p.get("null_paths", []))
        r_nulls = set(r.get("null_paths", []))

        if p_nulls == r_nulls:
            return None

        only_p = p_nulls - r_nulls
        only_r = r_nulls - p_nulls

        # Severity based on propagation depth difference
        p_depth = p.get("null_propagation_depth", 0)
        r_depth = r.get("null_propagation_depth", 0)
        depth_diff = abs(p_depth - r_depth)

        severity = Severity.CRITICAL if depth_diff >= 2 else Severity.HIGH

        return Finding(
            title=f"GraphQL exec: null propagation divergence ({len(only_p)}+{len(only_r)} path diffs, depth {p_depth} vs {r_depth})",
            severity=severity,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "exec_null_propagation_divergence",
                "ref_index": ref_index,
                "only_primary_nulls": sorted(only_p)[:20],
                "only_ref_nulls": sorted(only_r)[:20],
                "primary_depth": p_depth,
                "ref_depth": r_depth,
                "primary_null_hash": p.get("null_path_hash"),
                "ref_null_hash": r.get("null_path_hash"),
                "input_preview": _input_preview(inp),
            },
        )


# -- GX3: Error Path Divergence -----------------------------------------------

class GraphqlExecErrorPathStrategy:
    """Execution errors occur at different field paths."""

    name = "graphql_exec_error_path"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_exec_output(primary.stdout)
        r = _parse_exec_output(reference.stdout)
        if p is None or r is None:
            return None

        if not p.get("executed") or not r.get("executed"):
            return None

        p_errors = set(p.get("error_paths", []))
        r_errors = set(r.get("error_paths", []))

        if p_errors == r_errors:
            return None

        only_p = p_errors - r_errors
        only_r = r_errors - p_errors

        return Finding(
            title=f"GraphQL exec: error path divergence ({len(only_p)}+{len(only_r)} path diffs)",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "exec_error_path_divergence",
                "ref_index": ref_index,
                "only_primary_errors": sorted(only_p)[:20],
                "only_ref_errors": sorted(only_r)[:20],
                "primary_error_count": p.get("error_count_exec", 0),
                "ref_error_count": r.get("error_count_exec", 0),
                "input_preview": _input_preview(inp),
            },
        )


# -- GX4: Partial Data Divergence ---------------------------------------------

class GraphqlExecPartialDataStrategy:
    """One returns partial data (data + errors), other returns clean or null."""

    name = "graphql_exec_partial_data"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_exec_output(primary.stdout)
        r = _parse_exec_output(reference.stdout)
        if p is None or r is None:
            return None

        if not p.get("executed") or not r.get("executed"):
            return None

        p_partial = p.get("has_partial_data", False)
        r_partial = r.get("has_partial_data", False)

        if p_partial == r_partial:
            return None

        partial_side = "primary" if p_partial else f"ref_{ref_index}"

        return Finding(
            title=f"GraphQL exec: partial data divergence -- {partial_side} returns partial results",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "exec_partial_data_divergence",
                "ref_index": ref_index,
                "partial_side": partial_side,
                "primary_error_count": p.get("error_count_exec", 0),
                "ref_error_count": r.get("error_count_exec", 0),
                "primary_data_hash": p.get("data_hash"),
                "ref_data_hash": r.get("data_hash"),
                "input_preview": _input_preview(inp),
            },
        )


# -- GX5: Execution Acceptance Split -------------------------------------------

class GraphqlExecAcceptanceSplitStrategy:
    """Both parse+validate, but one executes successfully while other fails."""

    name = "graphql_exec_acceptance_split"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_exec_output(primary.stdout)
        r = _parse_exec_output(reference.stdout)
        if p is None or r is None:
            return None

        # Both must parse and validate
        if not (p.get("valid") and r.get("valid")):
            return None

        p_exec = p.get("executed", False)
        r_exec = r.get("executed", False)

        if p_exec == r_exec:
            return None

        accepting_side = "primary" if p_exec else f"ref_{ref_index}"
        failing = r if p_exec else p

        return Finding(
            title=f"GraphQL exec: execution acceptance split -- {accepting_side} executes",
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "exec_acceptance_split",
                "accepting_side": accepting_side,
                "ref_index": ref_index,
                "exec_error": str(failing.get("exec_error", ""))[:200],
                "input_preview": _input_preview(inp),
            },
        )


# -- GX6: Data Hash Divergence (exact value diff) -----------------------------

class GraphqlExecDataHashStrategy:
    """Both execute with same shape but different actual values."""

    name = "graphql_exec_data_hash"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_exec_output(primary.stdout)
        r = _parse_exec_output(reference.stdout)
        if p is None or r is None:
            return None

        if not p.get("executed") or not r.get("executed"):
            return None

        # Shape must match (otherwise GX1 catches it)
        if p.get("data_shape") != r.get("data_shape"):
            return None

        p_hash = p.get("data_hash")
        r_hash = r.get("data_hash")

        if p_hash == r_hash:
            return None

        return Finding(
            title=f"GraphQL exec: data value divergence (same shape, different values)",
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "exec_data_value_divergence",
                "ref_index": ref_index,
                "primary_data_hash": p_hash,
                "ref_data_hash": r_hash,
                "data_shape": p.get("data_shape", "")[:200],
                "input_preview": _input_preview(inp),
            },
        )


# -- Strategy registry ---------------------------------------------------------

def get_graphql_exec_strategies() -> list:
    return [
        GraphqlExecAcceptanceSplitStrategy(),
        GraphqlExecNullPropagationStrategy(),
        GraphqlExecDataShapeStrategy(),
        GraphqlExecErrorPathStrategy(),
        GraphqlExecPartialDataStrategy(),
        GraphqlExecDataHashStrategy(),
    ]
