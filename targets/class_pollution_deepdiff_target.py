#!/usr/bin/env python3
"""Class pollution target for DeepDiff Delta (CVE-2025-58367 reproduction).

CVE-2025-58367 (CVSS 10.0): DeepDiff's Delta class uses recursive merge
that allows __class__.__init__.__globals__ traversal, leading to:
- SAFE_TO_IMPORT list pollution → arbitrary module import
- pickle.loads override → RCE via deserialization

This target embeds a minimal reproduction of the vulnerable merge pattern
so it works without installing deepdiff.

Input format:
    {"payload": {"__class__": {"__init__": {"__globals__": {"SAFE_TO_IMPORT": ["os"]}}}}}

Output format:
    {"merged": true, "safe_to_import_before": [...], "safe_to_import_after": [...],
     "globals_polluted": [...], "attrs_changed": {...}, ...}
"""
from __future__ import annotations

import copy
import json
import sys
from typing import Any


# ── Emulated DeepDiff internals ──────────────────────────────
# Reproduces the exact vulnerable pattern from deepdiff/delta.py

# This is the actual guard list from DeepDiff — the CVE pollutes it
SAFE_TO_IMPORT = frozenset({
    "builtins.set", "builtins.list", "builtins.tuple", "builtins.dict",
    "builtins.frozenset", "builtins.str", "builtins.int", "builtins.float",
    "builtins.bool", "builtins.bytes", "builtins.NoneType",
    "collections.OrderedDict", "datetime.datetime", "datetime.date",
    "datetime.time", "datetime.timedelta", "decimal.Decimal",
    "uuid.UUID", "re.Pattern",
})

# Mutable version for testing pollution
_safe_to_import_mutable: list[str] = list(SAFE_TO_IMPORT)

# Simulated config that can be polluted
_DELTA_CONFIG = {
    "log_errors": True,
    "raise_errors": False,
    "verify_symmetry": False,
    "serializer": "json",
    "deserializer": "json",
}


class DeltaError(Exception):
    pass


class Delta:
    """Emulated DeepDiff Delta with the vulnerable merge pattern.

    The real CVE is in Delta.__init__ which calls _from_delta_dict()
    that recursively merges user-controlled data without dunder filtering.
    """

    _SAFE_TO_IMPORT = _safe_to_import_mutable

    def __init__(self, diff: dict | None = None, **kwargs):
        self.diff = diff or {}
        self.post_process_paths = {}
        self.force = kwargs.get("force", False)
        self.log_errors = True
        self.raise_errors = False

    def _from_delta_dict(self, delta_dict: dict) -> None:
        """VULNERABLE: Recursive merge without dunder filtering.

        This is the core of CVE-2025-58367.
        Real code at: deepdiff/delta.py Delta._from_delta_dict()
        """
        self._recursive_set(delta_dict, self)

    @staticmethod
    def _recursive_set(source: dict, target: Any, depth: int = 0) -> None:
        """The actual vulnerable merge — reproduces deepdiff behavior."""
        if depth > 10:
            return
        for key, value in source.items():
            if isinstance(value, dict):
                existing = getattr(target, key, None)
                if existing is not None and hasattr(existing, "__dict__"):
                    Delta._recursive_set(value, existing, depth + 1)
                elif isinstance(existing, dict):
                    Delta._recursive_set(value, existing, depth + 1)
                else:
                    try:
                        setattr(target, key, value)
                    except (AttributeError, TypeError):
                        pass
            else:
                try:
                    setattr(target, key, value)
                except (AttributeError, TypeError):
                    pass

    def _safe_import(self, module_path: str) -> bool:
        """Check if an import is allowed — the pollution target."""
        return module_path in self._SAFE_TO_IMPORT


class DeltaFiltered(Delta):
    """PATCHED: Delta with dunder filtering applied."""

    @staticmethod
    def _recursive_set(source: dict, target: Any, depth: int = 0) -> None:
        if depth > 10:
            return
        for key, value in source.items():
            # CVE fix: block dunder traversal
            if isinstance(key, str) and key.startswith("__"):
                continue
            if isinstance(value, dict):
                existing = getattr(target, key, None)
                if existing is not None and hasattr(existing, "__dict__"):
                    DeltaFiltered._recursive_set(value, existing, depth + 1)
                elif isinstance(existing, dict):
                    DeltaFiltered._recursive_set(value, existing, depth + 1)
                else:
                    try:
                        setattr(target, key, value)
                    except (AttributeError, TypeError):
                        pass
            else:
                try:
                    setattr(target, key, value)
                except (AttributeError, TypeError):
                    pass


DELTA_CLASSES = {
    "delta": Delta,
    "delta_filtered": DeltaFiltered,
}


# ── Snapshot helpers ─────────────────────────────────────────

def _snapshot_safe_imports() -> list[str]:
    return sorted(Delta._SAFE_TO_IMPORT)


def _snapshot_config() -> dict:
    return dict(_DELTA_CONFIG)


def _snapshot_delta_attrs(d: Delta) -> dict:
    return {
        "force": d.force,
        "log_errors": d.log_errors,
        "raise_errors": d.raise_errors,
    }


# ── Helpers for oracle compatibility ─────────────────────────

def _estimate_depth(payload: dict, depth: int = 0) -> int:
    """Estimate the nesting depth of dunder keys in a payload."""
    max_d = depth
    for key, value in payload.items():
        if isinstance(key, str) and key.startswith("__") and key.endswith("__"):
            if isinstance(value, dict):
                max_d = max(max_d, _estimate_depth(value, depth + 1))
            else:
                max_d = max(max_d, depth + 1)
    return max_d


def _extract_dunders(payload: dict) -> list[str]:
    """Extract all dunder keys traversed in a payload."""
    dunders = []
    for key, value in payload.items():
        if isinstance(key, str) and key.startswith("__") and key.endswith("__"):
            if key not in dunders:
                dunders.append(key)
            if isinstance(value, dict):
                for d in _extract_dunders(value):
                    if d not in dunders:
                        dunders.append(d)
    return dunders


# ── Main processing ─────────────────────────────────────────

def process_input(raw: bytes) -> dict:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"merged": False, "error": "invalid_json", "delta_class": "unknown"}

    payload = data.get("payload", {})
    delta_class_name = data.get("delta_class", "delta")

    if not isinstance(payload, dict):
        return {"merged": False, "error": "payload_not_dict", "delta_class": delta_class_name}

    delta_cls = DELTA_CLASSES.get(delta_class_name)
    if delta_cls is None:
        return {"merged": False, "error": f"unknown_class:{delta_class_name}", "delta_class": delta_class_name}

    # Snapshot before
    safe_imports_before = _snapshot_safe_imports()
    config_before = _snapshot_config()
    delta = delta_cls()
    attrs_before = _snapshot_delta_attrs(delta)

    exc_class = None
    exc_msg = None
    merged = False

    try:
        delta._from_delta_dict(payload)
        merged = True
    except Exception as e:
        exc_class = type(e).__name__
        exc_msg = str(e)[:200]

    # Snapshot after
    safe_imports_after = _snapshot_safe_imports()
    config_after = _snapshot_config()
    attrs_after = _snapshot_delta_attrs(delta)

    # Detect pollution
    imports_added = sorted(set(safe_imports_after) - set(safe_imports_before))
    imports_removed = sorted(set(safe_imports_before) - set(safe_imports_after))
    config_changed = {
        k: {"before": config_before[k], "after": config_after.get(k)}
        for k in config_before
        if config_before[k] != config_after.get(k)
    }
    attrs_changed = {
        k: {"before": attrs_before[k], "after": attrs_after[k]}
        for k in attrs_before
        if attrs_before[k] != attrs_after[k]
    }

    # Check if dangerous imports became allowed
    dangerous_imports_allowed = [
        m for m in ["os", "subprocess", "pickle", "marshal", "ctypes", "importlib"]
        if delta._safe_import(m) or delta._safe_import(f"builtins.{m}")
    ]

    # Map to oracle-compatible fields
    # dangerous_imports_allowed → globals_polluted (they represent RCE-reachable state)
    globals_polluted = dangerous_imports_allowed
    # class_attrs_changed: config changes act like class-level pollution
    class_attrs_changed = config_changed
    # Estimate chain depth from payload structure
    chain_depth = _estimate_depth(payload)
    # Detect dunder traversal in payload keys
    dunder_traversed = _extract_dunders(payload)

    result = {
        "merged": merged,
        "error": exc_msg,
        "merge_impl": delta_class_name,  # oracle expects merge_impl
        "delta_class": delta_class_name,
        # Oracle-compatible fields
        "globals_polluted": globals_polluted,
        "globals_polluted_count": len(globals_polluted),
        "class_attrs_changed": class_attrs_changed,
        "class_attrs_changed_count": len(class_attrs_changed),
        "attrs_changed": attrs_changed,
        "attrs_changed_count": len(attrs_changed),
        "chain_depth": chain_depth,
        "dunder_traversed": dunder_traversed,
        "dunder_traversed_count": len(dunder_traversed),
        "exception_class": exc_class,
        # DeepDiff-specific fields
        "safe_to_import_changed": bool(imports_added or imports_removed),
        "safe_to_import_added": imports_added,
        "safe_to_import_removed": imports_removed,
        "dangerous_imports_allowed": dangerous_imports_allowed,
        "dangerous_imports_count": len(dangerous_imports_allowed),
        "config_changed": config_changed,
        "config_changed_count": len(config_changed),
    }

    # Restore state
    Delta._SAFE_TO_IMPORT = list(SAFE_TO_IMPORT)
    _DELTA_CONFIG.update({"log_errors": True, "raise_errors": False,
                          "verify_symmetry": False, "serializer": "json",
                          "deserializer": "json"})

    return result


def main():
    raw = sys.stdin.buffer.read()
    if not raw:
        print(json.dumps({"merged": False, "error": "empty_input", "delta_class": "unknown"}))
        return
    result = process_input(raw)
    print(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
