"""GraphQL differential strategies for cross-library comparison.

Detects divergences in how different GraphQL implementations parse, validate,
and interpret the same query against the same schema. Each strategy targets
a specific differential surface:

  G1  Parse divergence          — one parses, other rejects
  G2  Validation divergence     — both parse, validation differs
  G3  Field resolution          — accepted field sets differ
  G4  Directive handling        — @skip/@include/@deprecated behavior differs
  G5  Type condition matching   — inline fragment / union resolution differs
  G6  Enum coercion            — enum value handling differs (case, unknown)
  G7  Variable definition      — variable type interpretation differs
  G8  Depth/complexity          — depth calculation or limit differs
  G9  Introspection exposure   — __schema/__type access differs
  G10 Operation type           — subscription/mutation acceptance differs
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


def _input_preview(inp: Input) -> str:
    return inp.data[:400].decode("utf-8", errors="replace")


# ── G1: Parse Divergence ──────────────────────────────────────────────────

class GraphqlParseDivergenceStrategy:
    """One library parses the query, the other rejects at parse phase."""

    name = "graphql_parse_divergence"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        p_parsed = p.get("parsed")
        r_parsed = r.get("parsed")

        if p_parsed == r_parsed:
            return None

        accepting = p if p_parsed else r
        rejecting = r if p_parsed else p
        accepting_side = "primary" if p_parsed else f"ref_{ref_index}"

        return Finding(
            title=f"GraphQL: parse divergence — {accepting_side} accepts, other rejects",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "parse_divergence",
                "accepting_side": accepting_side,
                "ref_index": ref_index,
                "parse_error": rejecting.get("parse_error", "")[:200],
                "input_preview": _input_preview(inp),
            },
        )


# ── G2: Validation Divergence ────────────────────────────────────────────

class GraphqlValidationDivergenceStrategy:
    """Both parse, but one validates and the other doesn't."""

    name = "graphql_validation_divergence"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        # Both must parse
        if not p.get("parsed") or not r.get("parsed"):
            return None

        p_valid = p.get("valid")
        r_valid = r.get("valid")

        if p_valid == r_valid:
            return None

        accepting = p if p_valid else r
        rejecting = r if p_valid else p
        accepting_side = "primary" if p_valid else f"ref_{ref_index}"

        # Classify mechanism from error messages
        errors = rejecting.get("errors", [])
        mechanism = _classify_validation_mechanism(errors)

        return Finding(
            title=f"GraphQL: validation divergence ({mechanism}) — {accepting_side} validates",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "validation_divergence",
                "mechanism": mechanism,
                "accepting_side": accepting_side,
                "ref_index": ref_index,
                "rejecting_errors": errors[:5],
                "input_preview": _input_preview(inp),
            },
        )


def _classify_validation_mechanism(errors: list[str]) -> str:
    joined = " ".join(str(e).lower() for e in errors)
    if "unknown type" in joined or "not defined" in joined:
        return "type_unknown"
    if "enum" in joined:
        return "enum_coercion"
    if "field" in joined and ("not found" in joined or "cannot query" in joined):
        return "field_resolution"
    if "fragment" in joined:
        return "fragment_validation"
    if "variable" in joined:
        return "variable_type"
    if "directive" in joined:
        return "directive_validation"
    if "deprecated" in joined:
        return "deprecated_access"
    return "unknown"


# ── G3: Field Resolution Divergence ──────────────────────────────────────

class GraphqlFieldResolutionStrategy:
    """Both validate, but resolved field paths differ."""

    name = "graphql_field_resolution"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        p_fields = set(p.get("field_paths", []))
        r_fields = set(r.get("field_paths", []))

        if p_fields == r_fields:
            return None

        only_primary = p_fields - r_fields
        only_ref = r_fields - p_fields

        # Skip if validation status differs (covered by G2)
        if p.get("valid") != r.get("valid"):
            return None

        return Finding(
            title=f"GraphQL: field resolution divergence — {len(only_primary)} vs {len(only_ref)} extra fields",
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "field_resolution_divergence",
                "ref_index": ref_index,
                "only_primary": sorted(only_primary)[:20],
                "only_ref": sorted(only_ref)[:20],
                "p_count": len(p_fields),
                "r_count": len(r_fields),
            },
        )


# ── G4: Directive Handling Divergence ────────────────────────────────────

class GraphqlDirectiveDivergenceStrategy:
    """Directive names or arguments handling differs."""

    name = "graphql_directive_divergence"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        # Must have directives in input
        raw = inp.data.decode("utf-8", errors="replace")
        if "@" not in raw:
            return None

        p_dirs = set(p.get("directive_names", []))
        r_dirs = set(r.get("directive_names", []))

        p_valid = p.get("valid")
        r_valid = r.get("valid")

        # Interesting: directives recognized differently
        if p_dirs != r_dirs and p_valid == r_valid:
            return Finding(
                title="GraphQL: directive recognition divergence",
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name=self.name,
                metadata={
                    "category": "directive_recognition_divergence",
                    "ref_index": ref_index,
                    "primary_directives": sorted(p_dirs),
                    "ref_directives": sorted(r_dirs),
                },
            )

        # Most interesting: directive presence causes validation split
        if p_dirs and p_valid != r_valid:
            accepting_side = "primary" if p_valid else f"ref_{ref_index}"
            return Finding(
                title=f"GraphQL: directive causes validation divergence — {accepting_side} accepts",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name=self.name,
                metadata={
                    "category": "directive_validation_divergence",
                    "accepting_side": accepting_side,
                    "ref_index": ref_index,
                    "directives": sorted(p_dirs | r_dirs),
                },
            )

        return None


# ── G5: Type Condition Divergence ────────────────────────────────────────

class GraphqlTypeConditionStrategy:
    """Type conditions (inline fragments, union resolution) handled differently."""

    name = "graphql_type_condition"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        p_tc = set(p.get("type_conditions", []))
        r_tc = set(r.get("type_conditions", []))

        if not p_tc and not r_tc:
            return None

        if p_tc == r_tc:
            return None

        # Skip if validation differs (G2 handles that)
        if p.get("valid") != r.get("valid"):
            return None

        return Finding(
            title="GraphQL: type condition resolution divergence",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "type_condition_divergence",
                "ref_index": ref_index,
                "primary_types": sorted(p_tc),
                "ref_types": sorted(r_tc),
            },
        )


# ── G6: Enum Coercion Divergence ─────────────────────────────────────────

class GraphqlEnumCoercionStrategy:
    """Enum value handling differs (case sensitivity, unknown values)."""

    name = "graphql_enum_coercion"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        # Must have enum-related content
        raw = inp.data.decode("utf-8", errors="replace").upper()
        enum_values = {"ADMIN", "USER", "GUEST", "ACTIVE", "SUSPENDED", "DELETED"}
        has_enum = any(ev in raw for ev in enum_values)
        if not has_enum:
            # Also check lowercase variants
            raw_lower = raw.lower()
            has_enum = any(ev.lower() in raw_lower for ev in enum_values)

        if not has_enum:
            return None

        p_valid = p.get("valid")
        r_valid = r.get("valid")

        if p_valid == r_valid:
            return None

        # One validates enum, other rejects
        p_errors = " ".join(str(e).lower() for e in p.get("errors", []))
        r_errors = " ".join(str(e).lower() for e in r.get("errors", []))

        is_enum_error = "enum" in p_errors or "enum" in r_errors

        if not is_enum_error:
            return None

        accepting_side = "primary" if p_valid else f"ref_{ref_index}"

        return Finding(
            title=f"GraphQL: enum coercion divergence — {accepting_side} accepts",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "enum_coercion_divergence",
                "accepting_side": accepting_side,
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


# ── G7: Depth/Complexity Divergence ──────────────────────────────────────

class GraphqlDepthDivergenceStrategy:
    """Computed max_depth or selection_count differs."""

    name = "graphql_depth_divergence"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        p_depth = p.get("max_depth", 0)
        r_depth = r.get("max_depth", 0)
        p_sel = p.get("selection_count", 0)
        r_sel = r.get("selection_count", 0)

        if p_depth == r_depth and p_sel == r_sel:
            return None

        # Only interesting if depth > 3 or significant selection difference
        if max(p_depth, r_depth) < 3 and abs(p_sel - r_sel) < 2:
            return None

        return Finding(
            title=f"GraphQL: depth/complexity divergence (depth {p_depth} vs {r_depth}, sel {p_sel} vs {r_sel})",
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "depth_complexity_divergence",
                "ref_index": ref_index,
                "primary_depth": p_depth,
                "ref_depth": r_depth,
                "primary_selections": p_sel,
                "ref_selections": r_sel,
            },
        )


# ── G8: Introspection Exposure Divergence ─────────────────────────────────

class GraphqlIntrospectionStrategy:
    """One allows introspection queries, the other blocks them."""

    name = "graphql_introspection"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        p_intro = p.get("has_introspection", False)
        r_intro = r.get("has_introspection", False)

        if not p_intro and not r_intro:
            return None

        # Interesting if introspection present and validation differs
        p_valid = p.get("valid")
        r_valid = r.get("valid")

        if p_valid == r_valid:
            return None

        accepting_side = "primary" if p_valid else f"ref_{ref_index}"

        return Finding(
            title=f"GraphQL: introspection handling divergence — {accepting_side} allows",
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "introspection_divergence",
                "accepting_side": accepting_side,
                "ref_index": ref_index,
            },
        )


# ── G9: Operation Type Divergence ────────────────────────────────────────

class GraphqlOperationTypeDivergenceStrategy:
    """Operation type handling differs (subscription/mutation acceptance)."""

    name = "graphql_operation_type"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        p_type = p.get("operation_type")
        r_type = r.get("operation_type")

        if p_type == r_type:
            return None

        return Finding(
            title=f"GraphQL: operation type divergence ({p_type} vs {r_type})",
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "operation_type_divergence",
                "ref_index": ref_index,
                "primary_type": p_type,
                "ref_type": r_type,
            },
        )


# ── G10: Fragment Handling Divergence ─────────────────────────────────────

class GraphqlFragmentDivergenceStrategy:
    """Fragment definitions and spreads handled differently."""

    name = "graphql_fragment_divergence"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        p_frags = set(p.get("fragment_names", []))
        r_frags = set(r.get("fragment_names", []))
        p_tc = set(p.get("fragment_type_conditions", []))
        r_tc = set(r.get("fragment_type_conditions", []))

        if not p_frags and not r_frags:
            return None

        if p_frags == r_frags and p_tc == r_tc:
            return None

        # Skip if validation differs already (G2 handles)
        if p.get("valid") != r.get("valid"):
            return None

        return Finding(
            title="GraphQL: fragment handling divergence",
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "fragment_divergence",
                "ref_index": ref_index,
                "primary_fragments": sorted(p_frags),
                "ref_fragments": sorted(r_frags),
                "primary_type_conditions": sorted(p_tc),
                "ref_type_conditions": sorted(r_tc),
            },
        )


# ── G11: Error Count Divergence ──────────────────────────────────────────

class GraphqlErrorCountStrategy:
    """Both reject but with different number of validation errors."""

    name = "graphql_error_count"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        # Both must be invalid
        if p.get("valid") or r.get("valid"):
            return None

        p_count = p.get("error_count", 0)
        r_count = r.get("error_count", 0)

        if p_count == r_count:
            return None

        # Only report significant differences
        if abs(p_count - r_count) < 2:
            return None

        return Finding(
            title=f"GraphQL: error count divergence ({p_count} vs {r_count})",
            severity=Severity.LOW,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "error_count_divergence",
                "ref_index": ref_index,
                "primary_errors": p_count,
                "ref_errors": r_count,
            },
        )


# ── G12: Error Category Divergence ────────────────────────────────────────

class GraphqlErrorCategoryStrategy:
    """Both reject but with different categories of validation errors."""

    name = "graphql_error_category"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        p = _parse_graphql_output(primary.stdout)
        r = _parse_graphql_output(reference.stdout)
        if p is None or r is None:
            return None

        if not (p.get("parsed") and r.get("parsed")):
            return None

        # Both must be invalid
        if p.get("valid") or r.get("valid"):
            return None

        p_cats = set(p.get("error_categories", []))
        r_cats = set(r.get("error_categories", []))

        if not p_cats and not r_cats:
            return None

        if p_cats == r_cats:
            return None

        only_primary = p_cats - r_cats
        only_ref = r_cats - p_cats

        return Finding(
            title=f"GraphQL: error category divergence — primary:[{','.join(sorted(only_primary))}] ref:[{','.join(sorted(only_ref))}]",
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name=self.name,
            metadata={
                "category": "error_category_divergence",
                "ref_index": ref_index,
                "primary_categories": sorted(p_cats),
                "ref_categories": sorted(r_cats),
                "only_primary": sorted(only_primary),
                "only_ref": sorted(only_ref),
            },
        )


# ── Strategy registry ────────────────────────────────────────────────────

def get_graphql_strategies() -> list:
    return [
        GraphqlParseDivergenceStrategy(),
        GraphqlValidationDivergenceStrategy(),
        GraphqlFieldResolutionStrategy(),
        GraphqlDirectiveDivergenceStrategy(),
        GraphqlTypeConditionStrategy(),
        GraphqlEnumCoercionStrategy(),
        GraphqlDepthDivergenceStrategy(),
        GraphqlIntrospectionStrategy(),
        GraphqlOperationTypeDivergenceStrategy(),
        GraphqlFragmentDivergenceStrategy(),
        GraphqlErrorCountStrategy(),
        GraphqlErrorCategoryStrategy(),
    ]
