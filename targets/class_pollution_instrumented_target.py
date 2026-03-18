#!/usr/bin/env python3
"""Instrumented class pollution target with runtime taint tracking.

Phase 4: GHunter-inspired dynamic analysis via:
1. __setattr__ metaclass hook — tracks every attribute write with caller info
2. sys.settrace — records function call/line coverage during merge execution
3. Combined output: merge result + execution trace + setattr log

Input/output format same as class_pollution_merge_target.py, with extra fields:
    "setattr_trace": [{"attr": "admin", "value": true, "caller": "recursive_merge", "depth": 2, "is_dunder": false}],
    "call_trace": ["recursive_merge:206", "recursive_merge:218", "setattr:233"],
    "lines_covered": 42,
    "branches_hit": ["setattr_reached", "dunder_traversed", "globals_accessed"],
    "trace_hash": "a1b2c3d4"
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import types
from dataclasses import dataclass, field

# Import the base target for reuse
from class_pollution_merge_target import (
    MERGE_FUNCTIONS,
    VictimConfig,
    VictimUser,
    _CLASS_ATTRS_TO_WATCH,
    _WATCHED_GLOBALS,
    _diff_snapshot,
    _safe_repr,
    _snapshot_class_attrs,
    _snapshot_globals,
    _snapshot_instance_attrs,
)


# ── Setattr Trace Entry ──────────────────────────────────────
@dataclass
class SetattrEntry:
    attr: str
    value_type: str
    caller_func: str
    caller_line: int
    depth: int
    is_dunder: bool
    obj_type: str

    def to_dict(self) -> dict:
        return {
            "attr": self.attr,
            "value_type": self.value_type,
            "caller": self.caller_func,
            "caller_line": self.caller_line,
            "depth": self.depth,
            "is_dunder": self.is_dunder,
            "obj_type": self.obj_type,
        }


# ── Trace Collector ──────────────────────────────────────────
class TraceCollector:
    """Collects setattr calls and line-level coverage during merge execution."""

    def __init__(self):
        self.setattr_log: list[SetattrEntry] = []
        self.call_trace: list[str] = []
        self.lines_covered: set[int] = set()
        self.funcs_entered: set[str] = set()
        self._depth = 0
        self._active = False
        # Semantic branch tracking
        self.branches_hit: set[str] = set()

    def start(self) -> None:
        self._active = True
        self._depth = 0
        sys.settrace(self._trace_func)

    def stop(self) -> None:
        self._active = False
        sys.settrace(None)

    def record_setattr(self, obj: object, attr: str, value: object) -> None:
        """Record a setattr call with caller context."""
        if not self._active:
            return

        frame = sys._getframe(1)
        caller_func = frame.f_code.co_name
        caller_line = frame.f_lineno

        is_dunder = isinstance(attr, str) and attr.startswith("__") and attr.endswith("__")

        entry = SetattrEntry(
            attr=attr,
            value_type=type(value).__name__,
            caller_func=caller_func,
            caller_line=caller_line,
            depth=self._depth,
            is_dunder=is_dunder,
            obj_type=type(obj).__name__,
        )
        self.setattr_log.append(entry)

        # Semantic branch tracking
        self.branches_hit.add("setattr_reached")
        if is_dunder:
            self.branches_hit.add("dunder_traversed")
            self.branches_hit.add(f"dunder:{attr}")
        if attr in _CLASS_ATTRS_TO_WATCH:
            self.branches_hit.add("class_attr_written")
            self.branches_hit.add(f"attr:{attr}")

    def _trace_func(self, frame, event, arg):
        """sys.settrace callback for line/call coverage."""
        if not self._active:
            return None

        filename = frame.f_code.co_filename
        # Only trace our merge target files
        if "class_pollution" not in filename and "merge" not in filename:
            return None

        if event == "call":
            func_name = frame.f_code.co_name
            self.funcs_entered.add(func_name)
            self.call_trace.append(f"{func_name}:{frame.f_lineno}")
            self._depth += 1
            if self._depth > 20:
                return None  # prevent excessive depth
            return self._trace_func

        if event == "line":
            self.lines_covered.add(frame.f_lineno)
            return self._trace_func

        if event == "return":
            self._depth = max(0, self._depth - 1)
            return self._trace_func

        return self._trace_func

    def trace_hash(self) -> str:
        """Hash of the execution trace for coverage discrimination."""
        data = "|".join(sorted(self.branches_hit))
        data += "|" + str(len(self.lines_covered))
        data += "|" + str(len(self.setattr_log))
        return hashlib.md5(data.encode()).hexdigest()[:8]

    def to_dict(self) -> dict:
        return {
            "setattr_trace": [e.to_dict() for e in self.setattr_log[:50]],
            "setattr_count": len(self.setattr_log),
            "call_trace": self.call_trace[:100],
            "call_trace_count": len(self.call_trace),
            "lines_covered": len(self.lines_covered),
            "funcs_entered": sorted(self.funcs_entered),
            "branches_hit": sorted(self.branches_hit),
            "branches_hit_count": len(self.branches_hit),
            "trace_hash": self.trace_hash(),
        }


# ── Instrumented Merge Wrappers ──────────────────────────────
# Wrap each merge function to intercept setattr calls

def _make_instrumented_setattr(collector: TraceCollector):
    """Create an instrumented setattr that logs to the collector."""
    original_setattr = builtins_setattr

    def instrumented_setattr(obj, name, value):
        collector.record_setattr(obj, name, value)
        original_setattr(obj, name, value)

    return instrumented_setattr


# Save reference to real setattr
import builtins
builtins_setattr = builtins.setattr


# ── Instrumented VictimUser ──────────────────────────────────
# Use a metaclass to intercept __setattr__ on victim classes

_thread_local = threading.local()


class InstrumentedMeta(type):
    """Metaclass that intercepts __setattr__ for taint tracking."""

    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        original_setattr = cls.__setattr__

        def traced_setattr(self, attr, value):
            collector = getattr(_thread_local, "collector", None)
            if collector is not None:
                collector.record_setattr(self, attr, value)
            original_setattr(self, attr, value)

        cls.__setattr__ = traced_setattr
        return cls


class InstrumentedUser(metaclass=InstrumentedMeta):
    """Instrumented version of VictimUser."""
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


class InstrumentedConfig(metaclass=InstrumentedMeta):
    """Instrumented version of VictimConfig."""
    debug = False
    secret = "config-default"
    log_level = "WARNING"


class InstrumentedUserWithConfig(InstrumentedConfig, InstrumentedUser):
    """Instrumented multi-inheritance victim."""
    pass


# ── Main Processing ──────────────────────────────────────────

def process_input(raw: bytes) -> dict:
    """Process one pollution test case with full instrumentation."""
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

    # Create instrumented victim
    victim = InstrumentedUserWithConfig(name="testuser")

    # Snapshot before state
    cls_before = _snapshot_class_attrs(InstrumentedUserWithConfig)
    inst_before = _snapshot_instance_attrs(victim)
    globals_before = _snapshot_globals()

    # Set up trace collector
    collector = TraceCollector()
    _thread_local.collector = collector

    exc_class = None
    exc_msg = None
    merged = False

    try:
        collector.start()
        merge_fn(payload, victim)
        merged = True
    except Exception as e:
        exc_class = type(e).__name__
        exc_msg = str(e)[:200]
    finally:
        collector.stop()
        _thread_local.collector = None

    # Check globals access
    for gname in _WATCHED_GLOBALS:
        if globals().get(gname) != _WATCHED_GLOBALS[gname]:
            collector.branches_hit.add("globals_accessed")
            collector.branches_hit.add(f"global:{gname}")

    # Snapshot after state
    cls_after = _snapshot_class_attrs(InstrumentedUserWithConfig)
    inst_after = _snapshot_instance_attrs(victim)
    globals_after = _snapshot_globals()

    # Compute diffs
    attrs_changed = _diff_snapshot(inst_before, inst_after)
    class_attrs_changed = _diff_snapshot(cls_before, cls_after)
    globals_changed = _diff_snapshot(globals_before, globals_after)
    globals_polluted = list(globals_changed.keys())

    # Build result (compatible with base target + instrumentation extras)
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
        "chain_depth": collector._depth,
        "dunder_traversed": [e.attr for e in collector.setattr_log if e.is_dunder],
        "dunder_traversed_count": sum(1 for e in collector.setattr_log if e.is_dunder),
        "exception_class": exc_class,
        # Phase 4: instrumentation fields
        **collector.to_dict(),
    }

    # Restore class state
    for k, v in cls_before.items():
        try:
            builtins_setattr(InstrumentedUserWithConfig, k, v)
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
