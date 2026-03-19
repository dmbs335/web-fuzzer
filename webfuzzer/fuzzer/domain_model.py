"""Domain model primitives for differential fuzzing profiles."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .protocols import Severity


@dataclass(frozen=True)
class DangerRung:
    """One level of the danger ladder."""

    level: int
    conditions: tuple[tuple[str, str, Any], ...]


def _rung_matches(parsed: dict, conditions: tuple[tuple[str, str, Any], ...]) -> bool:
    """Check whether all conditions of a rung are satisfied."""
    for fld, op, val in conditions:
        if op == "truthy":
            if not parsed.get(fld):
                return False
        elif op == "falsy":
            if parsed.get(fld):
                return False
        elif op == "eq":
            if parsed.get(fld) != val:
                return False
        elif op == "neq":
            if fld not in parsed or parsed[fld] == val:
                return False
        elif op == "in":
            if parsed.get(fld) not in val:
                return False
        elif op == "present":
            if fld not in parsed:
                return False
        elif op == "gt":
            value = parsed.get(fld)
            if not (isinstance(value, (int, float)) and value > val):
                return False
        elif op == "any_present":
            if not any(field_name in parsed for field_name in val):
                return False
        elif op == "any_truthy":
            if not any(parsed.get(field_name) for field_name in val):
                return False
        else:
            return False
    return True


def compute_danger(parsed: dict | None, ladder: tuple[DangerRung, ...]) -> int:
    """Evaluate a danger ladder against parsed target output."""
    if not parsed or not ladder:
        return 0

    max_level = 0
    for rung in ladder:
        if rung.level > max_level and _rung_matches(parsed, rung.conditions):
            max_level = rung.level
    return max_level


@dataclass(frozen=True)
class DomainProfile:
    """Declaration of domain-specific constants consumed by fuzzer components."""

    name: str
    comparison_keys: tuple[str, ...]
    categories: tuple[str, ...]
    field_category_map: dict[str, tuple[str, Severity]] = field(
        default_factory=dict,
        hash=False,
    )
    field_priority: tuple[str, ...] = ()
    danger_ladder: tuple[DangerRung, ...] = ()
