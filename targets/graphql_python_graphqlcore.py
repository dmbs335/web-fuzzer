"""GraphQL target -- Python graphql-core (reference port of graphql-js).

Parses + validates a GraphQL query against the common schema.
Output: standardized JSON for differential comparison.
Exit 0 = processed, Exit 1 = parse failure.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from graphql import (
    build_schema,
    parse as gql_parse,
    validate as gql_validate,
    Undefined,
)
from graphql.language import ast as gql_ast

# Load shared schema
SCHEMA_PATH = Path(__file__).parent / "graphql_schema.graphql"
SCHEMA_SDL = SCHEMA_PATH.read_text(encoding="utf-8")
SCHEMA = build_schema(SCHEMA_SDL)


def _type_node_to_string(type_node) -> str:
    if isinstance(type_node, gql_ast.NonNullTypeNode):
        return _type_node_to_string(type_node.type) + "!"
    if isinstance(type_node, gql_ast.ListTypeNode):
        return "[" + _type_node_to_string(type_node.type) + "]"
    return type_node.name.value


def _value_to_py(value_node):
    if isinstance(value_node, gql_ast.IntValueNode):
        return int(value_node.value)
    if isinstance(value_node, gql_ast.FloatValueNode):
        return float(value_node.value)
    if isinstance(value_node, gql_ast.StringValueNode):
        return value_node.value
    if isinstance(value_node, gql_ast.BooleanValueNode):
        return value_node.value
    if isinstance(value_node, gql_ast.NullValueNode):
        return None
    if isinstance(value_node, gql_ast.EnumValueNode):
        return value_node.value
    if isinstance(value_node, gql_ast.ListValueNode):
        return [_value_to_py(v) for v in value_node.values]
    if isinstance(value_node, gql_ast.ObjectValueNode):
        return {f.name.value: _value_to_py(f.value) for f in value_node.fields}
    return str(getattr(value_node, "value", ""))


def _simple_hash(s: str) -> str:
    h = 0
    for c in s:
        h = ((h << 5) - h + ord(c)) & 0xFFFFFFFF
    return f"{h:08x}"


def _classify_errors(error_messages: list[str]) -> list[str]:
    cats: set[str] = set()
    for msg in error_messages:
        m = msg.lower()
        if "enum" in m or "not exist in" in m:
            cats.add("enum_value")
        elif "cannot query field" in m:
            cats.add("unknown_field")
        elif "unknown argument" in m:
            cats.add("unknown_argument")
        elif "required" in m or "non-null" in m:
            cats.add("required_field")
        elif "variable" in m:
            cats.add("variable_type")
        elif "fragment" in m and "cycle" in m:
            cats.add("fragment_cycle")
        elif "fragment" in m:
            cats.add("fragment_error")
        elif "directive" in m:
            cats.add("directive_error")
        elif "type" in m:
            cats.add("type_error")
        elif "subscription" in m:
            cats.add("subscription_error")
        else:
            cats.add("other")
    return sorted(cats)


def analyze_query(query_str: str) -> str:
    raw = query_str.strip()
    if not raw:
        raise ValueError("Empty query")

    # Phase 1: Parse
    try:
        doc = gql_parse(raw)
    except Exception as parse_err:
        return json.dumps({
            "parsed": False,
            "valid": False,
            "parse_error": str(parse_err)[:300],
            "operation_type": None,
            "operation_name": None,
            "selection_count": 0,
            "field_paths": [],
            "fragment_names": [],
            "fragment_type_conditions": [],
            "variable_defs": {},
            "directive_names": [],
            "directive_args": {},
            "max_depth": 0,
            "errors": [str(parse_err)[:300]],
            "error_count": 1,
            "type_conditions": [],
            "has_introspection": False,
            "has_subscription": False,
            "has_mutation": False,
            "alias_count": 0,
            "inline_fragment_count": 0,
            "spread_count": 0,
        }, sort_keys=True, ensure_ascii=True)

    # Phase 2: Validate
    validation_errors = gql_validate(SCHEMA, doc)
    valid = len(validation_errors) == 0

    # Extract operation info
    operation_type = None
    operation_name = None
    has_subscription = False
    has_mutation = False
    variable_defs: dict[str, str] = {}

    for defn in doc.definitions:
        if isinstance(defn, gql_ast.OperationDefinitionNode):
            if defn.operation:
                operation_type = defn.operation.value
            operation_name = defn.name.value if defn.name else None
            if operation_type == "subscription":
                has_subscription = True
            if operation_type == "mutation":
                has_mutation = True
            if defn.variable_definitions:
                for v in defn.variable_definitions:
                    var_name = v.variable.name.value
                    variable_defs[var_name] = _type_node_to_string(v.type)

    # Walk AST
    field_paths: list[str] = []
    fragment_names: list[str] = []
    fragment_type_conditions: list[str] = []
    directive_names: set[str] = set()
    directive_args: dict[str, dict] = {}
    type_conditions: list[str] = []
    max_depth = 0
    selection_count = 0
    alias_count = 0
    inline_fragment_count = 0
    spread_count = 0
    has_introspection = False

    # Collect fragments
    for defn in doc.definitions:
        if isinstance(defn, gql_ast.FragmentDefinitionNode):
            fragment_names.append(defn.name.value)
            fragment_type_conditions.append(defn.type_condition.name.value)

    def _collect_directives(node):
        nonlocal directive_names, directive_args
        if hasattr(node, "directives") and node.directives:
            for d in node.directives:
                dname = d.name.value
                directive_names.add(dname)
                if d.arguments:
                    args = {}
                    for a in d.arguments:
                        args[a.name.value] = _value_to_py(a.value)
                    directive_args[dname] = args

    def _walk_selections(selection_set, depth: int, path_prefix: list[str]):
        nonlocal max_depth, selection_count, alias_count
        nonlocal inline_fragment_count, spread_count, has_introspection

        if not selection_set or not selection_set.selections:
            return

        for sel in selection_set.selections:
            if isinstance(sel, gql_ast.FieldNode):
                field_name = sel.name.value
                current_path = path_prefix + [field_name]
                field_paths.append(".".join(current_path))
                selection_count += 1
                if len(current_path) > max_depth:
                    max_depth = len(current_path)
                if sel.alias:
                    alias_count += 1
                if field_name.startswith("__"):
                    has_introspection = True
                _collect_directives(sel)
                if sel.selection_set:
                    _walk_selections(sel.selection_set, depth + 1, current_path)

            elif isinstance(sel, gql_ast.InlineFragmentNode):
                inline_fragment_count += 1
                if sel.type_condition:
                    type_conditions.append(sel.type_condition.name.value)
                _collect_directives(sel)
                _walk_selections(sel.selection_set, depth, path_prefix)

            elif isinstance(sel, gql_ast.FragmentSpreadNode):
                spread_count += 1
                _collect_directives(sel)

    for defn in doc.definitions:
        if isinstance(defn, gql_ast.OperationDefinitionNode):
            _collect_directives(defn)
            _walk_selections(defn.selection_set, 0, [])
        elif isinstance(defn, gql_ast.FragmentDefinitionNode):
            _walk_selections(defn.selection_set, 0, [])

    # Compute semantic hashes for coverage granularity
    sorted_paths = sorted(field_paths)
    field_set_hash = _simple_hash("|".join(sorted_paths))
    directive_set_hash = _simple_hash("|".join(sorted(directive_names)))
    fragment_set_hash = _simple_hash(
        "|".join(sorted(fragment_names)) + ":" + "|".join(sorted(fragment_type_conditions))
    )

    # Classify error categories
    error_categories = _classify_errors(
        [str(e.message)[:200] for e in validation_errors]
    )

    result = {
        "parsed": True,
        "valid": valid,
        "parse_error": None,
        "operation_type": operation_type,
        "operation_name": operation_name,
        "selection_count": selection_count,
        "field_paths": sorted_paths,
        "fragment_names": sorted(fragment_names),
        "fragment_type_conditions": sorted(fragment_type_conditions),
        "variable_defs": variable_defs,
        "directive_names": sorted(directive_names),
        "directive_args": directive_args,
        "max_depth": max_depth,
        "errors": [str(e.message)[:200] for e in validation_errors],
        "error_count": len(validation_errors),
        "error_categories": error_categories,
        "type_conditions": sorted(type_conditions),
        "has_introspection": has_introspection,
        "has_subscription": has_subscription,
        "has_mutation": has_mutation,
        "alias_count": alias_count,
        "inline_fragment_count": inline_fragment_count,
        "spread_count": spread_count,
        "field_set_hash": field_set_hash,
        "directive_set_hash": directive_set_hash,
        "fragment_set_hash": fragment_set_hash,
    }
    return json.dumps(result, sort_keys=True, ensure_ascii=True)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: graphql_python_graphqlcore.py <input_file>", file=sys.stderr)
        sys.exit(2)
    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        print(analyze_query(data))
        sys.exit(0)
    except (ValueError, TypeError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
