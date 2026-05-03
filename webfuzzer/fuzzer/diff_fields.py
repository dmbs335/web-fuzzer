"""Helpers for canonical differential field metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


_DIFF_FIELD_KEYS = ("diff_fields", "difference_fields", "all_diff_fields")


def get_diff_fields(metadata: Mapping[str, Any] | None) -> list[str]:
    """Return canonical diff fields from any accepted metadata alias."""
    if not metadata:
        return []

    out: list[str] = []
    seen: set[str] = set()
    for key in _DIFF_FIELD_KEYS:
        value = metadata.get(key)
        if value is None:
            continue
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, Sequence):
            values = value
        else:
            continue
        for item in values:
            text = str(item)
            if text not in seen:
                seen.add(text)
                out.append(text)
    return out


def set_diff_fields(metadata: dict[str, Any], diff_fields: Sequence[str]) -> None:
    """Populate both runtime and trace aliases for diff fields."""
    fields = [str(field) for field in diff_fields]
    metadata["diff_fields"] = list(fields)
    metadata["difference_fields"] = list(fields)
