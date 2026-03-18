"""Exception feedback parser for constraint-guided deserialization mutation.

Parses structured exception data from DeserTarget's JSON output and
produces ExceptionHint objects that guide the next mutation cycle.
"""

from __future__ import annotations

import copy
import logging
import random
import re
from dataclasses import dataclass
from typing import Any

from .deser_constraints import (
    FIELD_CONTRACTS,
    _DEFAULT_OVERRIDES,
    _INTERFACE_MAP,
    fix_link,
)

logger = logging.getLogger(__name__)

# Regex for ClassCastException messages:
# "com.example.Foo cannot be cast to com.example.Bar"
_CCE_RE = re.compile(
    r"([\w.$]+)\s+cannot be cast to\s+([\w.$]+)"
)


@dataclass(slots=True)
class ExceptionHint:
    """Structured exception feedback from a single deserialization attempt."""
    constraint_type: str       # type_mismatch | null_field | no_such_field | class_not_found | other
    link_index: int            # which link failed (-1 if unknown)
    field_name: str            # failed field name (empty if unknown)
    expected_type: str         # expected type from CCE (empty if N/A)
    actual_type: str           # actual type from CCE (empty if N/A)
    progress: int              # number of links successfully compiled


def parse_exception(result: dict[str, Any]) -> ExceptionHint | None:
    """Parse DeserTarget output JSON into an ExceptionHint.

    Returns None if the result was successful or has no useful feedback.
    """
    # Only interesting if compilation or deserialization failed
    compiled = result.get("compiled", True)
    deserialized = result.get("deserialized", True)

    if compiled and deserialized:
        return None  # success — no feedback needed

    constraint_type = result.get("constraint_type", "")
    link_index = result.get("exception_link_index", -1)
    field_name = result.get("exception_field", "")
    progress = result.get("progress_depth", 0)
    exception_class = result.get("exception_class", "")
    exception_msg = result.get("exception", "") or result.get("error", "")

    # If no structured feedback, try to infer from exception class
    if not constraint_type and exception_class:
        if "ClassCastException" in exception_class:
            constraint_type = "type_mismatch"
        elif "NullPointerException" in exception_class:
            constraint_type = "null_field"
        elif "NoSuchFieldException" in exception_class:
            constraint_type = "no_such_field"
        elif "ClassNotFoundException" in exception_class:
            constraint_type = "class_not_found"
        elif "InvalidClassException" in exception_class:
            constraint_type = "filter_rejected"
        else:
            constraint_type = "other"

    if not constraint_type:
        return None

    # Parse CCE message for type info
    expected_type = ""
    actual_type = ""
    msg = field_name if field_name else exception_msg
    if constraint_type == "type_mismatch" and msg:
        m = _CCE_RE.search(msg)
        if m:
            actual_type = m.group(1)
            expected_type = m.group(2)

    # For no_such_field, the field name is in the exception message
    if constraint_type == "no_such_field" and not field_name:
        field_name = exception_msg.strip() if exception_msg else ""

    return ExceptionHint(
        constraint_type=constraint_type,
        link_index=link_index if isinstance(link_index, int) else -1,
        field_name=field_name,
        expected_type=expected_type,
        actual_type=actual_type,
        progress=progress if isinstance(progress, int) else 0,
    )


def suggest_fix(
    hint: ExceptionHint,
    ir: dict[str, Any],
    rng: random.Random,
) -> dict[str, Any] | None:
    """Apply a targeted fix to the IR based on the exception hint.

    Returns a new IR dict if a fix was applied, None otherwise.
    """
    if hint.link_index < 0:
        return None

    ir = copy.deepcopy(ir)
    links = ir.get("links", [])

    if hint.link_index >= len(links):
        return None

    link = links[hint.link_index]
    class_name = link.get("class", "")

    if hint.constraint_type == "type_mismatch":
        # Try to find a class that implements the expected interface
        if hint.expected_type:
            # Look through _INTERFACE_MAP for compatible classes
            from .deser_constraints import FIELD_CONTRACTS as _FC
            compatible = []
            for cls, iface in _INTERFACE_MAP.items():
                # Check if the class name contains the expected type
                if hint.expected_type in cls or hint.expected_type in iface:
                    compatible.append(cls)
            if compatible:
                new_class = rng.choice(compatible)
                link["class"] = new_class
                defaults = _DEFAULT_OVERRIDES.get(new_class)
                if defaults:
                    link["field_overrides"] = copy.deepcopy(defaults)
                links[hint.link_index] = link
                return ir

    elif hint.constraint_type == "null_field":
        # Set the field to a non-null default
        link = fix_link(link, rng)
        links[hint.link_index] = link
        return ir

    elif hint.constraint_type == "no_such_field":
        # Remove the bad field and replace with defaults
        overrides = link.get("field_overrides", {})
        bad_field = hint.field_name
        if bad_field and bad_field in overrides:
            del overrides[bad_field]
        # Apply defaults for this class
        defaults = _DEFAULT_OVERRIDES.get(class_name, {})
        for k, v in defaults.items():
            if k not in overrides:
                overrides[k] = copy.deepcopy(v)
        link["field_overrides"] = overrides
        links[hint.link_index] = link
        return ir

    elif hint.constraint_type == "class_not_found":
        # Replace with a known class from the same interface category
        iface = _INTERFACE_MAP.get(class_name)
        if iface:
            from .deser_mutator import TYPE_HIERARCHY
            candidates = TYPE_HIERARCHY.get(iface, [])
            candidates = [c for c in candidates if c != class_name]
            if candidates:
                new_class = rng.choice(candidates)
                link["class"] = new_class
                defaults = _DEFAULT_OVERRIDES.get(new_class)
                if defaults:
                    link["field_overrides"] = copy.deepcopy(defaults)
                links[hint.link_index] = link
                return ir

    elif hint.constraint_type == "filter_rejected":
        # Filter rejected a class — nothing to fix in the chain itself
        # (this is actually a finding, not an error)
        return None

    return None
