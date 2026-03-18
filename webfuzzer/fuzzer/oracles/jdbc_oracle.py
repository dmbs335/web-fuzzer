"""JDBC connection exploitation single-target security oracle.

Detects dangerous behavior from JDBC connection string manipulation:
  - Command execution via driver-specific URL parameters (H2 RUNSCRIPT, HSQLDB)
  - Deserialization via autoDeserialize, socketFactory, sspi tricks
  - Arbitrary SQL execution through pool lifecycle hooks
  - File read/write via driver-specific features (LOAD DATA, COPY, etc.)
  - Class loading via custom socketFactory, connectionInitSql
  - Network SSRF via driver connection to attacker-controlled host

Target output JSON format:
    {
        "connected": true/false,
        "driver_class": "org.h2.Driver",
        "pool_type": "hikari" or "dbcp2" or "tomcat" or "druid" or null,
        "pool_created": true/false,
        "lifecycle_hook_type": "connectionInitSql" or "validationQuery" or null,
        "lifecycle_hook_executed": true/false,
        "url_params": {"allowLoadLocalInfile": "true", ...},
        "sink_reached": "cmd_exec" or null,
        "sinks_hit": ["cmd_exec", "file_read"],
        "process_spawned": true/false,
        "sql_executed": true/false,
        "file_write": true/false,
        "file_read": true/false,
        "network_connected": true/false,
        "class_loaded": true/false,
        "deserialized": true/false,
        "exception_class": null or "java.sql.SQLException",
        "exception": null or "error message",
        "duration_ms": 15,
        "auth_method": "password" or "trust" or "empty" or null
    }
"""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity

logger = logging.getLogger(__name__)


# ── Driver family normalization ───────────────────────────────────

def _driver_family(driver_class: str) -> str:
    """Normalize JDBC driver FQCN to a short family bucket for dedup."""
    if not driver_class:
        return "_unknown_"
    low = driver_class.lower()

    if "h2" in low:
        return "h2"
    if "hsqldb" in low or "hsql" in low:
        return "hsqldb"
    if "mysql" in low or "mariadb" in low:
        return "mysql"
    if "postgresql" in low or "pgjdbc" in low:
        return "pgsql"
    if "oracle" in low:
        return "oracle"
    if "sqlserver" in low or "jtds" in low or "mssql" in low:
        return "mssql"
    if "sqlite" in low:
        return "sqlite"
    if "derby" in low:
        return "derby"
    if "db2" in low:
        return "db2"
    if "firebird" in low:
        return "firebird"

    # Fallback to last segment of class name
    short = driver_class.rsplit(".", 1)[-1]
    return short.lower()


# ── Sink helpers ──────────────────────────────────────────────────

_CRITICAL_SINKS = {"cmd_exec", "deser"}
_HIGH_SINKS = {"sql_exec", "file_write", "class_load", "file_read"}

# Sink combinations that are RCE-equivalent even without cmd_exec/deser:
#   file_write + sql_exec  → webshell drop (SQLite ATTACH, H2 CSVWRITE + CREATE ALIAS)
#   class_load + sql_exec  → arbitrary class instantiation via SQL (H2 CREATE TRIGGER)
#   class_load + file_write → load attacker class from written file
_RCE_EQUIVALENT_COMBOS: list[frozenset[str]] = [
    frozenset({"file_write", "sql_exec"}),
    frozenset({"class_load", "sql_exec"}),
    frozenset({"class_load", "file_write"}),
]

_SINK_SEVERITY: dict[str, Severity] = {
    "cmd_exec": Severity.CRITICAL,
    "deser": Severity.CRITICAL,
    "sql_exec": Severity.HIGH,
    "file_write": Severity.HIGH,
    "file_read": Severity.HIGH,
    "class_load": Severity.HIGH,
    "network": Severity.MEDIUM,
}


def _sink_family(sinks: set[str]) -> str:
    """Pick the highest-severity sink as the canonical family key."""
    if not sinks:
        return "no_sink"
    for s in ("cmd_exec", "deser", "sql_exec", "file_write",
              "file_read", "class_load", "network"):
        if s in sinks:
            return s
    return sorted(sinks)[0]


def _sink_severity(sink: str) -> Severity:
    """Map a single sink name to its severity."""
    return _SINK_SEVERITY.get(sink, Severity.MEDIUM)


# ── Output parsing ────────────────────────────────────────────────

def _parse_jdbc_output(stdout: bytes) -> dict | None:
    """Parse JSON output from JDBC target with validation."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and (
            "connected" in data
            or "driver_class" in data
            or "sink_reached" in data
            or "pool_created" in data
        ):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _get_all_sinks(parsed: dict) -> set[str]:
    """Extract all sinks from parsed JDBC output."""
    sinks: set[str] = set()
    sinks_hit = parsed.get("sinks_hit", [])
    if isinstance(sinks_hit, list):
        sinks.update(sinks_hit)
    primary = parsed.get("sink_reached")
    if primary:
        sinks.add(primary)
    for flag, sink_name in [
        ("process_spawned", "cmd_exec"),
        ("deserialized", "deser"),
        ("deser_triggered", "deser"),
        ("sql_executed", "sql_exec"),
        ("file_write", "file_write"),
        ("file_read", "file_read"),
        ("network_connected", "network"),
        ("class_loaded", "class_load"),
    ]:
        if parsed.get(flag):
            sinks.add(sink_name)
    return sinks


# ── Dedup fingerprint ─────────────────────────────────────────────

def _chain_hash(parsed: dict, sinks: set[str]) -> str:
    """Generate a dedup fingerprint from driver, sinks, pool, and hook."""
    driver = parsed.get("driver_class", "")
    pool = parsed.get("pool_type", "") or ""
    hook = parsed.get("lifecycle_hook_type", "") or ""
    df = _driver_family(driver)
    sf = _sink_family(sinks)
    key = f"{df}|{sf}|{pool}|{hook}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


# ── Human-readable descriptions ──────────────────────────────────

_SINK_DESCRIPTIONS: dict[str, str] = {
    "cmd_exec": "command execution",
    "deser": "deserialization",
    "sql_exec": "arbitrary SQL execution",
    "file_write": "file write",
    "file_read": "file read",
    "class_load": "class loading",
    "network": "network access",
}


def _attack_vector(parsed: dict) -> str:
    """Derive human-readable attack vector from parsed output."""
    hook = parsed.get("lifecycle_hook_type")
    if hook:
        return f"{hook} hook"
    url_params = parsed.get("url_params")
    if url_params and isinstance(url_params, dict):
        keys = sorted(url_params.keys())
        if keys:
            return f"URL param ({', '.join(keys[:3])})"
    return "direct connection"


# ── Oracle class ──────────────────────────────────────────────────

class JdbcOracle:
    """Single-target JDBC connection exploitation security oracle."""

    name = "jdbc"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0 and not result.stdout:
            return None

        parsed = _parse_jdbc_output(result.stdout)
        if parsed is None:
            return None

        all_sinks = _get_all_sinks(parsed)

        # connected=True alone is NOT a finding
        # pool_created=True alone is NOT a finding
        # sql_executed=True IS a finding (HIGH)
        # process_spawned=True is always CRITICAL
        if not all_sinks:
            return None

        critical = all_sinks & _CRITICAL_SINKS
        high = all_sinks & _HIGH_SINKS

        # Check RCE-equivalent sink combos (e.g. file_write+sql_exec → webshell)
        rce_combo = any(combo <= all_sinks for combo in _RCE_EQUIVALENT_COMBOS)

        if critical or rce_combo:
            severity = Severity.CRITICAL
        elif high:
            severity = Severity.HIGH
        else:
            severity = Severity.MEDIUM

        driver = parsed.get("driver_class", "")
        df = _driver_family(driver)
        best = _sink_family(all_sinks)
        sink_desc = _SINK_DESCRIPTIONS.get(best, best)
        vector = _attack_vector(parsed)

        # Side effects
        side_effects = []
        for flag in ("process_spawned", "deserialized", "sql_executed",
                      "file_write", "file_read", "network_connected",
                      "class_loaded"):
            if parsed.get(flag):
                side_effects.append(flag)

        pool_type = parsed.get("pool_type", "") or ""
        hook_type = parsed.get("lifecycle_hook_type", "") or ""
        url_params = parsed.get("url_params", {})
        url_param_keys = sorted(url_params.keys()) if isinstance(url_params, dict) else []

        return Finding(
            title=f"JDBC {df}: {sink_desc} via {vector}",
            severity=severity,
            input=inp,
            result=result,
            oracle_name=self.name,
            fingerprint=_chain_hash(parsed, all_sinks),
            metadata={
                "category": f"jdbc_{df}_{best}",
                "driver_family": df,
                "driver_class": driver,
                "pool_type": pool_type,
                "url_params_keys": url_param_keys,
                "sinks_hit": sorted(all_sinks),
                "side_effects": side_effects,
                "lifecycle_hook_type": hook_type,
                "connected": parsed.get("connected", False),
                "sql_executed": parsed.get("sql_executed", False),
                "diff_pattern_hash": _chain_hash(parsed, all_sinks),
            },
        )
