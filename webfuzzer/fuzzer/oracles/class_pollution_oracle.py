"""Class pollution single-target security oracle.

Detects successful class pollution in one target's output:
  - Globals written (os, subprocess, SECRET_KEY, __builtins__)  -> CRITICAL
  - Class attributes changed (admin, role, is_superuser)        -> HIGH/CRITICAL
  - Instance attributes changed via pollution chain             -> HIGH
  - Dunder chain reachability without state change              -> MEDIUM
"""
from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity

# Security-relevant attributes that indicate privilege escalation
SECURITY_ATTRS = frozenset({
    "admin", "is_admin", "_is_superuser", "is_authenticated",
    "role", "permissions", "allowed", "secret_key",
})

# Dangerous globals indicating RCE potential
DANGEROUS_GLOBALS = frozenset({
    "os", "subprocess", "sys", "__builtins__", "eval", "exec",
    "pickle", "marshal", "ctypes", "importlib",
})


def _parse_output(stdout: bytes) -> dict | None:
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "merged" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


class ClassPollutionOracle:
    """Single-target oracle for class pollution detection."""

    name = "class_pollution"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        parsed = result.parsed_json()
        if parsed is None:
            parsed = _parse_output(result.stdout)
        if parsed is None or not parsed.get("merged"):
            return None

        merge_impl = parsed.get("merge_impl", "unknown")
        globals_polluted = parsed.get("globals_polluted", [])
        class_attrs_changed = parsed.get("class_attrs_changed", {})
        attrs_changed = parsed.get("attrs_changed", {})
        chain_depth = parsed.get("chain_depth", 0)
        dunder_traversed = parsed.get("dunder_traversed", [])
        # Phase 2: execution-guided fields
        access_path = parsed.get("access_path", [])
        access_path_hash = parsed.get("access_path_hash", "")
        globals_reachable = parsed.get("globals_reachable", [])
        sink_types = parsed.get("sink_types", {})

        # Phase 2: classify callable sinks for severity boost
        has_callable_sink = "callable" in sink_types.values()

        # Priority 1: Dangerous globals polluted (RCE potential)
        dangerous_hit = [g for g in globals_polluted if g in DANGEROUS_GLOBALS]
        if dangerous_hit:
            return Finding(
                title=f"Class pollution: dangerous globals written ({', '.join(dangerous_hit)})",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:globals_dangerous:{merge_impl}:{sorted(dangerous_hit)[0]}:{access_path_hash}",
                metadata={
                    "category": "globals_write",
                    "pollution_type": "globals_dangerous",
                    "merge_impl": merge_impl,
                    "globals_polluted": globals_polluted,
                    "chain_depth": chain_depth,
                    "dunder_traversed": dunder_traversed,
                    "access_path": access_path,
                    "sink_types": sink_types,
                },
            )

        # Priority 2: Non-dangerous globals polluted
        if globals_polluted:
            return Finding(
                title=f"Class pollution: globals written ({', '.join(globals_polluted[:3])})",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:globals_write:{merge_impl}:{sorted(globals_polluted)[0]}:{access_path_hash}",
                metadata={
                    "category": "globals_write",
                    "pollution_type": "globals_non_dangerous",
                    "merge_impl": merge_impl,
                    "globals_polluted": globals_polluted,
                    "chain_depth": chain_depth,
                    "access_path": access_path,
                },
            )

        # Priority 3: Security-relevant class attributes changed
        security_class_changed = [k for k in class_attrs_changed if k in SECURITY_ATTRS]
        if security_class_changed:
            return Finding(
                title=f"Class pollution: security class attrs changed ({', '.join(security_class_changed)})",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:class_attr_security:{merge_impl}:{sorted(security_class_changed)[0]}:{access_path_hash}",
                metadata={
                    "category": "class_attr_pollution",
                    "pollution_type": "class_attr_security",
                    "merge_impl": merge_impl,
                    "class_attrs_changed": class_attrs_changed,
                    "chain_depth": chain_depth,
                    "access_path": access_path,
                },
            )

        # Priority 4: Non-security class attributes changed
        if class_attrs_changed:
            changed_keys = list(class_attrs_changed.keys())
            return Finding(
                title=f"Class pollution: class attrs changed ({', '.join(changed_keys[:3])})",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:class_attr:{merge_impl}:{sorted(changed_keys)[0]}:{access_path_hash}",
                metadata={
                    "category": "class_attr_pollution",
                    "pollution_type": "class_attr_generic",
                    "merge_impl": merge_impl,
                    "class_attrs_changed": class_attrs_changed,
                    "access_path": access_path,
                },
            )

        # Priority 5: Instance attributes changed via dunder chain
        security_inst_changed = [k for k in attrs_changed if k in SECURITY_ATTRS]
        if security_inst_changed and "__class__" in dunder_traversed:
            return Finding(
                title=f"Class pollution: instance attrs changed via dunder chain ({', '.join(security_inst_changed)})",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:inst_attr_dunder:{merge_impl}:{sorted(security_inst_changed)[0]}:{access_path_hash}",
                metadata={
                    "category": "instance_attr_pollution",
                    "pollution_type": "instance_via_dunder",
                    "merge_impl": merge_impl,
                    "attrs_changed": attrs_changed,
                    "dunder_traversed": dunder_traversed,
                    "access_path": access_path,
                },
            )

        # Priority 5.5: Callable sinks reachable via globals (RCE path confirmed)
        callable_sinks = [k for k, v in sink_types.items() if v == "callable"]
        if callable_sinks and globals_reachable:
            return Finding(
                title=f"Class pollution: callable sinks reachable ({', '.join(callable_sinks[:3])})",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:callable_sink:{merge_impl}:{sorted(callable_sinks)[0]}:{access_path_hash}",
                metadata={
                    "category": "sink_reachability",
                    "pollution_type": "callable_sink",
                    "merge_impl": merge_impl,
                    "callable_sinks": callable_sinks,
                    "globals_reachable": globals_reachable,
                    "chain_depth": chain_depth,
                    "access_path": access_path,
                },
            )

        # Priority 6: Deep dunder traversal with __globals__ reached
        if "__globals__" in dunder_traversed and chain_depth >= 2:
            return Finding(
                title=f"Class pollution: __globals__ reachable (depth={chain_depth})",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:globals_reachable:{merge_impl}:{chain_depth}:{access_path_hash}",
                metadata={
                    "category": "dunder_reachability",
                    "pollution_type": "globals_reachable",
                    "merge_impl": merge_impl,
                    "chain_depth": chain_depth,
                    "dunder_traversed": dunder_traversed,
                    "access_path": access_path,
                    "globals_reachable": globals_reachable,
                },
            )

        # Priority 7: Dunder traversal without state change
        if dunder_traversed and chain_depth >= 1:
            return Finding(
                title=f"Class pollution: dunder traversal allowed ({', '.join(dunder_traversed[:3])})",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                fingerprint=f"cp:dunder_traversal:{merge_impl}:{chain_depth}:{dunder_traversed[0]}:{access_path_hash}",
                metadata={
                    "category": "dunder_reachability",
                    "pollution_type": "dunder_traversal",
                    "merge_impl": merge_impl,
                    "chain_depth": chain_depth,
                    "dunder_traversed": dunder_traversed,
                    "access_path": access_path,
                },
            )

        return None
