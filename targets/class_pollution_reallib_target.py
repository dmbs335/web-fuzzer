#!/usr/bin/env python3
"""Class pollution target for real Python merge libraries.

Tests actual installed libraries for class pollution vulnerabilities:
- mergedeep: deep merge utility (~400 stars)
- munch: dict subclass with attribute access (~700 stars)
- addict: dict subclass with auto-vivification (~2.4K stars)

Each library merges user-controlled JSON into a victim object.
Differential: compare which libraries allow pollution vs block it.

Input format:
    {"payload": {"__class__": {"admin": true}}, "lib": "all"}
"""
from __future__ import annotations

import copy
import json
import sys
from typing import Any


# ── Victim classes ───────────────────────────────────────────

class VictimUser:
    """Target class with security-relevant attributes."""
    admin = False
    is_admin = False
    role = "user"
    debug = False
    secret_key = "default-secret"
    level = 1
    permissions: list = []

    def __init__(self, name: str = "testuser"):
        self.name = name


_CLASS_ATTRS = ["admin", "is_admin", "role", "debug", "secret_key", "level", "permissions"]
_SECURITY_ATTRS = {"admin", "is_admin", "role", "secret_key", "debug"}


def _snapshot_class() -> dict:
    return {k: getattr(VictimUser, k, None) for k in _CLASS_ATTRS}


def _snapshot_instance(obj: object) -> dict:
    return {k: getattr(obj, k, None) for k in _CLASS_ATTRS}


def _diff(before: dict, after: dict) -> dict:
    changed = {}
    for k in before:
        b, a = before[k], after.get(k)
        if b != a:
            bv = b if isinstance(b, (str, int, float, bool, type(None))) else str(b)[:100]
            av = a if isinstance(a, (str, int, float, bool, type(None))) else str(a)[:100]
            changed[k] = {"before": bv, "after": av}
    return changed


def _restore_class(snapshot: dict) -> None:
    for k, v in snapshot.items():
        try:
            setattr(VictimUser, k, v)
        except (AttributeError, TypeError):
            pass


# ── Library-specific merge implementations ───────────────────

def _test_mergedeep(payload: dict) -> dict:
    """Test mergedeep.merge() with dict targets."""
    try:
        from mergedeep import merge
    except ImportError:
        return {"error": "mergedeep not installed", "merged": False}

    victim_dict = {
        "admin": False, "role": "user", "debug": False,
        "secret_key": "default", "level": 1,
    }
    before = dict(victim_dict)

    try:
        merge(victim_dict, payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"

    changed = _diff(before, victim_dict)

    # Check if dunder keys were merged (they shouldn't be in dict-only mode)
    dunder_keys_merged = [k for k in victim_dict if isinstance(k, str) and k.startswith("__")]

    return {
        "merged": merged, "error": error,
        "attrs_changed": changed, "attrs_changed_count": len(changed),
        "dunder_keys_merged": dunder_keys_merged,
        "dunder_keys_count": len(dunder_keys_merged),
    }


def _test_mergedeep_object(payload: dict) -> dict:
    """Test mergedeep with object.__dict__ as target — the dangerous pattern."""
    try:
        from mergedeep import merge
    except ImportError:
        return {"error": "mergedeep not installed", "merged": False}

    victim = VictimUser()
    cls_before = _snapshot_class()
    inst_before = _snapshot_instance(victim)

    try:
        # The dangerous pattern: merge into __dict__
        merge(victim.__dict__, payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"

    cls_after = _snapshot_class()
    inst_after = _snapshot_instance(victim)
    class_attrs_changed = _diff(cls_before, cls_after)
    attrs_changed = _diff(inst_before, inst_after)

    _restore_class(cls_before)

    return {
        "merged": merged, "error": error,
        "class_attrs_changed": class_attrs_changed,
        "class_attrs_changed_count": len(class_attrs_changed),
        "attrs_changed": attrs_changed,
        "attrs_changed_count": len(attrs_changed),
    }


def _test_munch(payload: dict) -> dict:
    """Test Munch(**kwargs) — kwargs pass directly to __init__ → update()."""
    try:
        from munch import Munch, munchify
    except ImportError:
        return {"error": "munch not installed", "merged": False}

    try:
        # Pattern 1: Munch(user_data) — common in config loading
        m = Munch(payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"
        m = None

    # Check what keys were accepted
    accepted_keys = list(m.keys()) if m else []
    dunder_keys = [k for k in accepted_keys if isinstance(k, str) and k.startswith("__")]
    has_class_key = "__class__" in accepted_keys

    # Check if __class__ traversal happened
    class_polluted = False
    if m and has_class_key:
        # If __class__ was set as a dict key, check if it affected the class
        try:
            class_polluted = type(m).__name__ != "Munch"
        except Exception:
            pass

    return {
        "merged": merged, "error": error,
        "accepted_keys_count": len(accepted_keys),
        "dunder_keys": dunder_keys,
        "dunder_keys_count": len(dunder_keys),
        "has_class_key": has_class_key,
        "class_polluted": class_polluted,
        "attrs_changed": {},
        "attrs_changed_count": 0,
        "class_attrs_changed": {},
        "class_attrs_changed_count": 0,
    }


def _test_addict(payload: dict) -> dict:
    """Test addict.Dict(user_data) — recursive dict with attribute access."""
    try:
        from addict import Dict as Addict
    except ImportError:
        return {"error": "addict not installed", "merged": False}

    try:
        d = Addict(payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"
        d = None

    accepted_keys = list(d.keys()) if d else []
    dunder_keys = [k for k in accepted_keys if isinstance(k, str) and k.startswith("__")]

    # Addict has __setattr__ guard: class attrs are read-only
    setattr_blocked = False
    if d:
        try:
            d.__class__ = "test"
        except (AttributeError, TypeError):
            setattr_blocked = True

    return {
        "merged": merged, "error": error,
        "accepted_keys_count": len(accepted_keys),
        "dunder_keys": dunder_keys,
        "dunder_keys_count": len(dunder_keys),
        "setattr_blocked": setattr_blocked,
        "attrs_changed": {},
        "attrs_changed_count": 0,
        "class_attrs_changed": {},
        "class_attrs_changed_count": 0,
    }


def _test_pydash_dict(payload: dict) -> dict:
    """Test pydash.set_ with dict target — path-based traversal."""
    try:
        import pydash
    except ImportError:
        return {"error": "pydash not installed", "merged": False}

    victim_dict = {
        "admin": False, "role": "user", "debug": False,
        "secret_key": "default", "level": 1,
    }
    before = dict(victim_dict)

    try:
        # pydash uses dot-separated paths; flatten payload keys as paths
        for key, value in payload.items():
            pydash.set_(victim_dict, key, value)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"

    changed = _diff(before, victim_dict)
    dunder_keys = [k for k in victim_dict if isinstance(k, str) and k.startswith("__")]

    return {
        "merged": merged, "error": error,
        "attrs_changed": changed, "attrs_changed_count": len(changed),
        "dunder_keys_merged": dunder_keys, "dunder_keys_count": len(dunder_keys),
    }


def _test_pydash_object(payload: dict) -> dict:
    """Test pydash.set_ with object target — the dangerous pattern."""
    try:
        import pydash
    except ImportError:
        return {"error": "pydash not installed", "merged": False}

    victim = VictimUser()
    cls_before = _snapshot_class()
    inst_before = _snapshot_instance(victim)

    try:
        for key, value in payload.items():
            pydash.set_(victim, key, value)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"

    cls_after = _snapshot_class()
    inst_after = _snapshot_instance(victim)
    class_attrs_changed = _diff(cls_before, cls_after)
    attrs_changed = _diff(inst_before, inst_after)

    _restore_class(cls_before)

    return {
        "merged": merged, "error": error,
        "class_attrs_changed": class_attrs_changed,
        "class_attrs_changed_count": len(class_attrs_changed),
        "attrs_changed": attrs_changed,
        "attrs_changed_count": len(attrs_changed),
    }


def _test_deepmerge(payload: dict) -> dict:
    """Test deepmerge.always_merger with dict targets."""
    try:
        from deepmerge import always_merger
    except ImportError:
        return {"error": "deepmerge not installed", "merged": False}

    victim_dict = {
        "admin": False, "role": "user", "debug": False,
        "secret_key": "default", "level": 1,
    }
    before = dict(victim_dict)

    try:
        always_merger.merge(victim_dict, payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"

    changed = _diff(before, victim_dict)
    dunder_keys = [k for k in victim_dict if isinstance(k, str) and k.startswith("__")]

    return {
        "merged": merged, "error": error,
        "attrs_changed": changed, "attrs_changed_count": len(changed),
        "dunder_keys_merged": dunder_keys, "dunder_keys_count": len(dunder_keys),
    }


def _test_deepmerge_object(payload: dict) -> dict:
    """Test deepmerge.always_merger with object.__dict__ as target."""
    try:
        from deepmerge import always_merger
    except ImportError:
        return {"error": "deepmerge not installed", "merged": False}

    victim = VictimUser()
    cls_before = _snapshot_class()
    inst_before = _snapshot_instance(victim)

    try:
        always_merger.merge(victim.__dict__, payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"

    cls_after = _snapshot_class()
    inst_after = _snapshot_instance(victim)
    class_attrs_changed = _diff(cls_before, cls_after)
    attrs_changed = _diff(inst_before, inst_after)

    _restore_class(cls_before)

    return {
        "merged": merged, "error": error,
        "class_attrs_changed": class_attrs_changed,
        "class_attrs_changed_count": len(class_attrs_changed),
        "attrs_changed": attrs_changed,
        "attrs_changed_count": len(attrs_changed),
    }


def _test_benedict(payload: dict) -> dict:
    """Test python-benedict merge — recursive dict merge with no dunder filter."""
    try:
        from benedict import benedict as Benedict
    except ImportError:
        return {"error": "python-benedict not installed", "merged": False}

    victim_dict = {
        "admin": False, "role": "user", "debug": False,
        "secret_key": "default", "level": 1,
    }
    before = dict(victim_dict)

    try:
        b = Benedict(victim_dict)
        b.merge(payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"
        b = victim_dict

    after = dict(b) if hasattr(b, 'items') else victim_dict
    changed = _diff(before, after)
    dunder_keys = [k for k in after if isinstance(k, str) and k.startswith("__")]

    return {
        "merged": merged, "error": error,
        "attrs_changed": changed, "attrs_changed_count": len(changed),
        "dunder_keys_merged": dunder_keys, "dunder_keys_count": len(dunder_keys),
    }


def _test_box(payload: dict) -> dict:
    """Test python-box merge_update — recursive dict merge."""
    try:
        from box import Box
    except ImportError:
        return {"error": "python-box not installed", "merged": False}

    victim_dict = {
        "admin": False, "role": "user", "debug": False,
        "secret_key": "default", "level": 1,
    }
    before = dict(victim_dict)

    try:
        b = Box(victim_dict)
        b.merge_update(payload)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"
        b = Box(victim_dict)

    after = b.to_dict()
    changed = _diff(before, after)
    dunder_keys = [k for k in after if isinstance(k, str) and k.startswith("__")]

    return {
        "merged": merged, "error": error,
        "attrs_changed": changed, "attrs_changed_count": len(changed),
        "dunder_keys_merged": dunder_keys, "dunder_keys_count": len(dunder_keys),
    }


def _test_glom_object(payload: dict) -> dict:
    """Test glom.assign with object target — dot-path traversal like pydash."""
    try:
        import glom
    except ImportError:
        return {"error": "glom not installed", "merged": False}

    victim = VictimUser()
    cls_before = _snapshot_class()
    inst_before = _snapshot_instance(victim)

    try:
        for key, value in payload.items():
            glom.assign(victim, key, value)
        merged = True
        error = None
    except Exception as e:
        merged = False
        error = f"{type(e).__name__}: {str(e)[:150]}"

    cls_after = _snapshot_class()
    inst_after = _snapshot_instance(victim)
    class_attrs_changed = _diff(cls_before, cls_after)
    attrs_changed = _diff(inst_before, inst_after)

    _restore_class(cls_before)

    return {
        "merged": merged, "error": error,
        "class_attrs_changed": class_attrs_changed,
        "class_attrs_changed_count": len(class_attrs_changed),
        "attrs_changed": attrs_changed,
        "attrs_changed_count": len(attrs_changed),
    }


# ── Library registry ─────────────────────────────────────────

LIBRARIES = {
    "mergedeep": _test_mergedeep,
    "mergedeep_object": _test_mergedeep_object,
    "munch": _test_munch,
    "addict": _test_addict,
    "pydash_dict": _test_pydash_dict,
    "pydash_object": _test_pydash_object,
    "deepmerge": _test_deepmerge,
    "deepmerge_object": _test_deepmerge_object,
    "benedict": _test_benedict,
    "box": _test_box,
    "glom_object": _test_glom_object,
}


# ── Helpers ──────────────────────────────────────────────────

def _estimate_depth(payload: dict, depth: int = 0) -> int:
    max_d = depth
    for key, value in payload.items():
        if isinstance(key, str) and key.startswith("__") and key.endswith("__"):
            if isinstance(value, dict):
                max_d = max(max_d, _estimate_depth(value, depth + 1))
            else:
                max_d = max(max_d, depth + 1)
    return max_d


def _extract_dunders(payload: dict) -> list[str]:
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


# ── Main processing ──────────────────────────────────────────

def process_input(raw: bytes) -> dict:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"merged": False, "error": "invalid_json", "merge_impl": "unknown"}

    payload = data.get("payload", {})
    lib_name = data.get("lib", "mergedeep_object")

    if not isinstance(payload, dict):
        return {"merged": False, "error": "payload_not_dict", "merge_impl": lib_name}

    test_fn = LIBRARIES.get(lib_name)
    if test_fn is None:
        return {"merged": False, "error": f"unknown_lib:{lib_name}", "merge_impl": lib_name}

    lib_result = test_fn(copy.deepcopy(payload))

    # Oracle-compatible fields
    chain_depth = _estimate_depth(payload)
    dunder_traversed = _extract_dunders(payload)
    globals_polluted = []

    # Merge lib-specific results with oracle-compatible fields
    result = {
        "merged": lib_result.get("merged", False),
        "error": lib_result.get("error"),
        "merge_impl": lib_name,
        "globals_polluted": globals_polluted,
        "globals_polluted_count": 0,
        "class_attrs_changed": lib_result.get("class_attrs_changed", {}),
        "class_attrs_changed_count": lib_result.get("class_attrs_changed_count", 0),
        "attrs_changed": lib_result.get("attrs_changed", {}),
        "attrs_changed_count": lib_result.get("attrs_changed_count", 0),
        "chain_depth": chain_depth,
        "dunder_traversed": dunder_traversed,
        "dunder_traversed_count": len(dunder_traversed),
        "exception_class": None,
        # Library-specific extras
        "lib": lib_name,
        "dunder_keys_merged": lib_result.get("dunder_keys_merged", []),
        "dunder_keys_count": lib_result.get("dunder_keys_count", 0),
    }

    return result


def main():
    raw = sys.stdin.buffer.read()
    if not raw:
        print(json.dumps({"merged": False, "error": "empty_input", "merge_impl": "unknown"}))
        return
    result = process_input(raw)
    print(json.dumps(result, default=str))


if __name__ == "__main__":
    main()
