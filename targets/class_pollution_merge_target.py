#!/usr/bin/env python3
"""Class pollution merge target harness.

Embeds multiple merge implementations and tests them for pollution.
Reads JSON from stdin, applies the merge, compares before/after state.

Input format:
    {"merge_fn": "recursive_merge", "payload": {"__class__": {"admin": true}}}

Output format:
    {
        "merged": true,
        "error": null,
        "merge_impl": "recursive_merge",
        "attrs_changed": {"admin": {"before": false, "after": true}},
        "class_attrs_changed": {"admin": {"before": null, "after": true}},
        "globals_polluted": ["SECRET_KEY"],
        "chain_depth": 2,
        "dunder_traversed": ["__class__"],
        "exception_class": null
    }
"""
from __future__ import annotations

import copy
import json
import sys
import types

# ── Sentinel for tracking globals pollution ─────────────────────
_WATCHED_GLOBALS = {
    "SECRET_KEY": "default-secret-do-not-use",
    "DEBUG": False,
    "ALLOWED_HOSTS": ["localhost"],
    "DATABASE_URL": "sqlite:///db.sqlite3",
}
# Install watched globals into this module
for _k, _v in _WATCHED_GLOBALS.items():
    globals()[_k] = _v


# ── Victim class with known initial state ───────────────────────
class VictimUser:
    """Class with exploitable class-level attributes."""
    admin = False
    is_admin = False
    _is_superuser = False
    is_authenticated = False
    role = "user"
    level = 1
    debug = False
    allowed = False
    secret_key = "default"
    permissions: list = []

    def __init__(self, name: str = "testuser"):
        self.name = name


class VictimConfig:
    """Configuration class — parent for VictimUser in MRO tests."""
    debug = False
    secret = "config-default"
    log_level = "WARNING"


class VictimUserWithConfig(VictimConfig, VictimUser):
    """Multi-inheritance victim for MRO/bases testing."""
    pass


# ── Class attribute snapshot helpers ────────────────────────────
_CLASS_ATTRS_TO_WATCH = [
    "admin", "is_admin", "_is_superuser", "is_authenticated",
    "role", "level", "debug", "allowed", "secret_key", "permissions",
]


def _snapshot_class_attrs(cls: type) -> dict:
    return {k: getattr(cls, k, None) for k in _CLASS_ATTRS_TO_WATCH}


def _snapshot_instance_attrs(obj: object) -> dict:
    return {k: getattr(obj, k, None) for k in _CLASS_ATTRS_TO_WATCH}


def _snapshot_globals() -> dict:
    return {k: globals().get(k) for k in _WATCHED_GLOBALS}


def _diff_snapshot(before: dict, after: dict) -> dict:
    changed = {}
    for k in before:
        b, a = before[k], after.get(k)
        if b != a:
            changed[k] = {"before": _safe_repr(b), "after": _safe_repr(a)}
    return changed


def _safe_repr(v):
    """JSON-safe representation of a value."""
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [_safe_repr(x) for x in v[:10]]
    if isinstance(v, dict):
        return {str(k): _safe_repr(val) for k, val in list(v.items())[:10]}
    return str(v)[:200]


# ── Dangerous sinks for reachability analysis ──────────────────
_DANGEROUS_MODULES = {"os", "subprocess", "sys", "pickle", "marshal", "ctypes", "importlib"}
_DANGEROUS_BUILTINS = {"eval", "exec", "__import__", "compile"}


def _classify_sink(obj) -> str | None:
    """Classify a reachable object's exploitability."""
    if callable(obj):
        return "callable"
    if isinstance(obj, types.ModuleType):
        return "module"
    if isinstance(obj, dict):
        return "dict"
    if isinstance(obj, (list, tuple)):
        return "sequence"
    return None


# ── Dunder traversal tracker ───────────────────────────────────
class DunderTracker:
    """Tracks dunder traversal with full access path recording (GHunter-inspired)."""

    def __init__(self):
        self.traversed: list[str] = []
        self.max_depth = 0
        self._path_stack: list[str] = []  # current traversal path
        self.access_paths: list[list[str]] = []  # all completed paths
        self.globals_reachable: list[str] = []  # dangerous globals found
        self.sink_types: dict[str, str] = {}  # global_name → type classification

    def record(self, key: str, depth: int):
        # Maintain path stack
        while len(self._path_stack) > depth:
            self._path_stack.pop()
        self._path_stack.append(key)

        if key.startswith("__") and key.endswith("__"):
            if key not in self.traversed:
                self.traversed.append(key)
            self.max_depth = max(self.max_depth, depth)

        # Snapshot current path
        self.access_paths.append(list(self._path_stack))

    def analyze_globals_reachability(self, obj: object) -> None:
        """Analyze what dangerous globals are reachable from obj's __init__.__globals__."""
        try:
            init_fn = getattr(type(obj), "__init__", None)
            if init_fn is None:
                return
            globs = getattr(init_fn, "__globals__", None)
            if not isinstance(globs, dict):
                return

            for name, val in globs.items():
                # Check dangerous modules
                if name in _DANGEROUS_MODULES:
                    if name not in self.globals_reachable:
                        self.globals_reachable.append(name)
                    self.sink_types[name] = _classify_sink(val) or "unknown"
                # Check dangerous builtins
                if name == "__builtins__":
                    builtins_dict = val if isinstance(val, dict) else getattr(val, "__dict__", {})
                    for bname in _DANGEROUS_BUILTINS:
                        if bname in builtins_dict:
                            full = f"__builtins__.{bname}"
                            if full not in self.globals_reachable:
                                self.globals_reachable.append(full)
                            self.sink_types[full] = "callable"
                # Check config-like globals
                if name in _WATCHED_GLOBALS:
                    if name not in self.globals_reachable:
                        self.globals_reachable.append(name)
                    self.sink_types[name] = _classify_sink(val) or "value"
        except (AttributeError, TypeError):
            pass

    def deepest_path(self) -> list[str]:
        """Return the longest access path recorded."""
        if not self.access_paths:
            return []
        return max(self.access_paths, key=len)

    def access_path_hash(self) -> str:
        """Hash of the deepest path for coverage discrimination."""
        import hashlib
        path = self.deepest_path()
        return hashlib.md5("|".join(path).encode()).hexdigest()[:8] if path else "empty"


# ── Merge implementations ──────────────────────────────────────

def recursive_merge(src: dict, dst: object, tracker: DunderTracker | None = None,
                    _depth: int = 0) -> None:
    """VULNERABLE: No dunder filtering — standard class pollution vector."""
    for key, value in src.items():
        if tracker:
            tracker.record(key, _depth)

        if hasattr(dst, "__getitem__"):
            if isinstance(value, dict):
                existing = None
                try:
                    existing = dst[key]
                except (KeyError, TypeError, IndexError):
                    pass
                if existing is not None and (hasattr(existing, "__getitem__") or hasattr(existing, "__dict__")):
                    recursive_merge(value, existing, tracker, _depth + 1)
                else:
                    try:
                        dst[key] = value
                    except (TypeError, KeyError):
                        pass
            else:
                try:
                    dst[key] = value
                except (TypeError, KeyError):
                    pass
        elif hasattr(dst, key) and isinstance(value, dict):
            recursive_merge(value, getattr(dst, key), tracker, _depth + 1)
        else:
            try:
                setattr(dst, key, value)
            except (AttributeError, TypeError):
                pass


def recursive_merge_filtered(src: dict, dst: object, tracker: DunderTracker | None = None,
                              _depth: int = 0) -> None:
    """SAFE: Filters dunder attributes — blocks class pollution chains."""
    for key, value in src.items():
        if tracker:
            tracker.record(key, _depth)

        # Block dunder traversal
        if isinstance(key, str) and key.startswith("__"):
            continue

        if hasattr(dst, "__getitem__"):
            if isinstance(value, dict):
                existing = None
                try:
                    existing = dst[key]
                except (KeyError, TypeError, IndexError):
                    pass
                if existing is not None and (hasattr(existing, "__getitem__") or hasattr(existing, "__dict__")):
                    recursive_merge_filtered(value, existing, tracker, _depth + 1)
                else:
                    try:
                        dst[key] = value
                    except (TypeError, KeyError):
                        pass
            else:
                try:
                    dst[key] = value
                except (TypeError, KeyError):
                    pass
        elif hasattr(dst, key) and isinstance(value, dict):
            recursive_merge_filtered(value, getattr(dst, key), tracker, _depth + 1)
        else:
            try:
                setattr(dst, key, value)
            except (AttributeError, TypeError):
                pass


def setattr_loop(src: dict, dst: object, tracker: DunderTracker | None = None,
                 _depth: int = 0) -> None:
    """PARTIALLY VULNERABLE: Flat setattr without recursion."""
    for key, value in src.items():
        if tracker:
            tracker.record(key, _depth)
        try:
            setattr(dst, key, value)
        except (AttributeError, TypeError):
            pass


def dict_update_recursive(src: dict, dst: object, tracker: DunderTracker | None = None,
                           _depth: int = 0) -> None:
    """SAFE FOR CLASSES: Only works on dict-like objects (no setattr)."""
    if not hasattr(dst, "__getitem__"):
        return
    for key, value in src.items():
        if tracker:
            tracker.record(key, _depth)
        if isinstance(value, dict):
            existing = None
            try:
                existing = dst[key]
            except (KeyError, TypeError, IndexError):
                pass
            if existing is not None and hasattr(existing, "__getitem__"):
                dict_update_recursive(value, existing, tracker, _depth + 1)
            else:
                try:
                    dst[key] = value
                except (TypeError, KeyError):
                    pass
        else:
            try:
                dst[key] = value
            except (TypeError, KeyError):
                pass


MERGE_FUNCTIONS = {
    "recursive_merge": recursive_merge,
    "recursive_merge_filtered": recursive_merge_filtered,
    "setattr_loop": setattr_loop,
    "dict_update_recursive": dict_update_recursive,
}


# ── Main execution logic ───────────────────────────────────────

def process_input(raw: bytes) -> dict:
    """Process one pollution test case, return results dict."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return {"merged": False, "error": "invalid_json", "merge_impl": "unknown"}

    merge_fn_name = data.get("merge_fn", "recursive_merge")
    payload = data.get("payload", {})

    if not isinstance(payload, dict):
        return {"merged": False, "error": "payload_not_dict", "merge_impl": merge_fn_name}

    merge_fn = MERGE_FUNCTIONS.get(merge_fn_name)
    if merge_fn is None:
        return {"merged": False, "error": f"unknown_merge_fn:{merge_fn_name}", "merge_impl": merge_fn_name}

    # Snapshot before state
    victim = VictimUserWithConfig(name="testuser")
    cls_before = _snapshot_class_attrs(VictimUserWithConfig)
    inst_before = _snapshot_instance_attrs(victim)
    globals_before = _snapshot_globals()

    tracker = DunderTracker()

    exc_class = None
    exc_msg = None
    merged = False

    try:
        merge_fn(payload, victim, tracker=tracker)
        merged = True
    except Exception as e:
        exc_class = type(e).__name__
        exc_msg = str(e)[:200]

    # Analyze globals reachability (GHunter-inspired)
    tracker.analyze_globals_reachability(victim)

    # Snapshot after state
    cls_after = _snapshot_class_attrs(VictimUserWithConfig)
    inst_after = _snapshot_instance_attrs(victim)
    globals_after = _snapshot_globals()

    # Compute diffs
    attrs_changed = _diff_snapshot(inst_before, inst_after)
    class_attrs_changed = _diff_snapshot(cls_before, cls_after)
    globals_changed = _diff_snapshot(globals_before, globals_after)
    globals_polluted = list(globals_changed.keys())

    result = {
        "merged": merged,
        "error": exc_msg,
        "merge_impl": merge_fn_name,
        "attrs_changed": attrs_changed,
        "class_attrs_changed": class_attrs_changed,
        "globals_polluted": globals_polluted,
        "globals_polluted_count": len(globals_polluted),
        "attrs_changed_count": len(attrs_changed),
        "class_attrs_changed_count": len(class_attrs_changed),
        "chain_depth": tracker.max_depth,
        "dunder_traversed": tracker.traversed,
        "dunder_traversed_count": len(tracker.traversed),
        "exception_class": exc_class,
        # Phase 2: Execution-guided fields (GHunter/Dasty inspired)
        "access_path": tracker.deepest_path(),
        "access_path_hash": tracker.access_path_hash(),
        "globals_reachable": tracker.globals_reachable,
        "globals_reachable_count": len(tracker.globals_reachable),
        "sink_types": tracker.sink_types,
        "sink_types_hash": "|".join(sorted(set(tracker.sink_types.values()))) if tracker.sink_types else "",
    }

    # Restore class state to prevent cross-iteration contamination
    for k, v in cls_before.items():
        try:
            setattr(VictimUserWithConfig, k, v)
        except (AttributeError, TypeError):
            pass
    for k, v in _WATCHED_GLOBALS.items():
        globals()[k] = v

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
