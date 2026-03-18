"""JNDI ObjectFactory abuse single-target security oracle.

Detects dangerous behavior from JNDI Reference resolution:
  - Factory-mediated code execution (EL, Groovy, JShell, BeanShell, MVEL)
  - JDBC driver exploitation (H2, HSQLDB, PostgreSQL, MySQL)
  - File write primitives (MemoryUserDatabaseFactory)
  - JNDI re-lookup chains
  - Unexpected class instantiation / classloading

Target output JSON format:
    {
        "resolved": true/false,
        "factory_loaded": true/false,
        "factory_class": "org.apache.naming.factory.BeanFactory",
        "reference_class": "javax.el.ELProcessor",
        "bean_created": true/false,
        "method_invoked": "eval",
        "sink_reached": "cmd_exec" or null,
        "sinks_hit": ["cmd_exec", "reflection"],
        "process_spawned": true/false,
        "jndi_lookup": true/false,
        "file_write": true/false,
        "network_connected": true/false,
        "class_loaded": true/false,
        "jdbc_connected": true/false,
        "jdbc_driver": "org.h2.Driver" or null,
        "sql_executed": true/false,
        "exception_class": null or "java.lang.ClassNotFoundException",
        "exception": null or "error message",
        "duration_ms": 15,
        "jdk_version": "17.0.2",
        "security_manager": false
    }
"""

from __future__ import annotations

import hashlib
import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _factory_family(factory_class: str) -> str:
    """Normalize factory class to a family bucket for dedup."""
    if not factory_class:
        return "_unknown_"
    short = factory_class.rsplit(".", 1)[-1]
    low = short.lower()

    if "beanfactory" in low:
        return "bean_factory"
    if "datasource" in low or "dbcp" in low or "hikari" in low or "druid" in low:
        return "datasource_factory"
    if "memoryuserdatabase" in low:
        return "file_write_factory"
    if "websphere" in low or "clientj2c" in low:
        return "websphere_factory"
    if "methodinvoking" in low:
        return "spring_factory"
    return short.lower()


def _sink_family(sinks: set[str]) -> str:
    """Normalize sinks to a canonical key for dedup."""
    if not sinks:
        return "no_sink"
    ordered = []
    for s in ("cmd_exec", "jndi_lookup", "script_exec", "class_load",
              "file_write", "jdbc_exec", "network", "reflection"):
        if s in sinks:
            ordered.append(s)
    for s in sorted(sinks):
        if s not in ordered:
            ordered.append(s)
    return "+".join(ordered)


_CRITICAL_SINKS = {"cmd_exec", "jndi_lookup", "script_exec", "el_exec"}
_HIGH_SINKS = {"jdbc_exec", "sql_exec", "file_write", "class_load"}

_SINK_SEVERITY: dict[str, Severity] = {
    "cmd_exec": Severity.CRITICAL,
    "jndi_lookup": Severity.CRITICAL,
    "script_exec": Severity.CRITICAL,
    "el_exec": Severity.CRITICAL,
    "jdbc_exec": Severity.HIGH,
    "sql_exec": Severity.HIGH,
    "file_write": Severity.HIGH,
    "class_load": Severity.HIGH,
    "network": Severity.MEDIUM,
    "reflection": Severity.MEDIUM,
}


def _parse_jndi_output(stdout: bytes) -> dict | None:
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and (
            "resolved" in data
            or "factory_loaded" in data
            or "sink_reached" in data
        ):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _get_all_sinks(parsed: dict) -> set[str]:
    """Extract all sinks from parsed output."""
    sinks: set[str] = set()
    sinks_hit = parsed.get("sinks_hit", [])
    if isinstance(sinks_hit, list):
        sinks.update(sinks_hit)
    primary = parsed.get("sink_reached")
    if primary:
        sinks.add(primary)
    for flag, sink_name in [
        ("process_spawned", "cmd_exec"),
        ("jndi_lookup", "jndi_lookup"),
        ("file_write", "file_write"),
        ("network_connected", "network"),
        ("class_loaded", "class_load"),
        ("sql_executed", "sql_exec"),
        ("jdbc_connected", "jdbc_exec"),
    ]:
        if parsed.get(flag):
            sinks.add(sink_name)
    return sinks


def _best_sink(sinks: set[str]) -> str | None:
    """Return highest-priority sink from a set."""
    for s in ("cmd_exec", "jndi_lookup", "script_exec", "el_exec",
              "jdbc_exec", "sql_exec", "file_write", "class_load",
              "network", "reflection"):
        if s in sinks:
            return s
    return next(iter(sinks)) if sinks else None


def _chain_hash(parsed: dict, sinks: set[str]) -> str:
    """Build a dedup fingerprint from factory, sinks, and method."""
    factory = parsed.get("factory_class", "")
    ref_class = parsed.get("reference_class", "")
    method = parsed.get("method_invoked", "")
    ff = _factory_family(factory)
    sf = _sink_family(sinks)
    key = f"{ff}|{sf}|{method}|{ref_class}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


class JndiOracle:
    """Single-target JNDI ObjectFactory abuse security oracle."""

    name = "jndi"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0 and not result.stdout:
            return None

        parsed = _parse_jndi_output(result.stdout)
        if parsed is None:
            return None

        # Only interested if factory loaded and resolved
        if not parsed.get("factory_loaded") and not parsed.get("resolved"):
            return None

        all_sinks = _get_all_sinks(parsed)
        if not all_sinks:
            return None

        best = _best_sink(all_sinks)
        critical = all_sinks & _CRITICAL_SINKS
        high = all_sinks & _HIGH_SINKS

        if critical:
            severity = Severity.CRITICAL
        elif high:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        factory = parsed.get("factory_class", "")
        ref_class = parsed.get("reference_class", "")
        method = parsed.get("method_invoked", "")
        ff = _factory_family(factory)
        sf = _sink_family(all_sinks)

        # Side effects
        side_effects = []
        for flag in ("process_spawned", "jndi_lookup", "file_write",
                      "network_connected", "class_loaded", "sql_executed",
                      "jdbc_connected"):
            if parsed.get(flag):
                side_effects.append(flag)

        return Finding(
            title=f"JNDI factory abuse: {ff} → {sf}",
            severity=severity,
            input=inp,
            result=result,
            oracle_name=self.name,
            fingerprint=_chain_hash(parsed, all_sinks),
            metadata={
                "category": f"jndi_{ff}_{best}",
                "factory_class": factory,
                "reference_class": ref_class,
                "method_invoked": method,
                "all_sinks": sorted(all_sinks),
                "side_effects": side_effects,
                "jdk_version": parsed.get("jdk_version", ""),
                "security_manager": parsed.get("security_manager", False),
                "diff_pattern_hash": _chain_hash(parsed, all_sinks),
            },
        )
