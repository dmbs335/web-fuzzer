"""JDBC connection exploitation differential strategies for cross-environment comparison.

Compares JDBC driver and connection pool behavior across different:
  - Driver versions (H2 1.x vs 2.x, MySQL Connector/J 5 vs 8)
  - Connection pool implementations (HikariCP, DBCP2, Tomcat JDBC, Druid)
  - Database server versions (PostgreSQL 12 vs 16, MySQL 5.7 vs 8.0)
  - Security configurations (allowLoadLocalInfile, autoDeserialize)
  - Runtime environments (JDK versions, SecurityManager presence)

Strategies (DiffStrategy protocol — compare(inp, primary, reference, ref_index)):
  1. DriverBehaviorDivergence: same URL, different sink reach across drivers
  2. PoolLifecycleDivergence: lifecycle hook executes on one env but not another
  3. ConnectionPropertyDivergence: dangerous property honored on one side only
  4. SQLPayloadDivergence: SQL executes differently across environments
  5. AuthBypassDivergence: weak credentials accepted on one side only
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity

logger = logging.getLogger(__name__)


# ── Shared helpers ────────────────────────────────────────────────

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


def _has_dangerous_behavior(parsed: dict) -> bool:
    """Return True if any dangerous sink was reached."""
    if parsed.get("sink_reached"):
        return True
    for k in ("process_spawned", "deserialized", "sql_executed",
              "file_write", "file_read", "class_loaded",
              "network_connected"):
        if parsed.get(k):
            return True
    return False


def _get_sinks(parsed: dict) -> set[str]:
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
        ("sql_executed", "sql_exec"),
        ("file_write", "file_write"),
        ("file_read", "file_read"),
        ("network_connected", "network"),
        ("class_loaded", "class_load"),
    ]:
        if parsed.get(flag):
            sinks.add(sink_name)
    return sinks


_CRITICAL_SINKS = {"cmd_exec", "deser"}
_HIGH_SINKS = {"sql_exec", "file_write", "file_read", "class_load"}

# RCE-equivalent sink combos — promote to critical when both present
_RCE_EQUIVALENT_COMBOS: list[frozenset[str]] = [
    frozenset({"file_write", "sql_exec"}),
    frozenset({"class_load", "sql_exec"}),
    frozenset({"class_load", "file_write"}),
]


def _sinks_severity(sinks: set[str]) -> Severity:
    """Determine severity from a set of sinks, including RCE-equivalent combos."""
    if sinks & _CRITICAL_SINKS:
        return Severity.CRITICAL
    if any(combo <= sinks for combo in _RCE_EQUIVALENT_COMBOS):
        return Severity.CRITICAL
    if sinks & _HIGH_SINKS:
        return Severity.HIGH
    return Severity.MEDIUM


def _driver_family(driver_class: str) -> str:
    """Normalize JDBC driver FQCN to a short family name."""
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
    return driver_class.rsplit(".", 1)[-1].lower()


def _input_preview(inp: Input) -> str:
    """Short preview of input data for metadata."""
    return inp.data[:300].decode("utf-8", errors="replace")


# ── Strategy 1: Driver Behavior Divergence ────────────────────────

class DriverBehaviorDivergenceStrategy:
    """Detects when same JDBC URL reaches a dangerous sink on one env but not another.

    This catches driver-version-specific exploitation: e.g., H2 1.x allows
    RUNSCRIPT FROM but H2 2.x blocks it, or MySQL Connector/J 5 honors
    allowLoadLocalInfile by default but 8 does not.
    """

    name = "jdbc_driver_behavior"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> list[Finding] | None:
        pp = _parse_jdbc_output(primary.stdout)
        rp = _parse_jdbc_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_sinks = _get_sinks(pp)
        ref_sinks = _get_sinks(rp)

        primary_only = primary_sinks - ref_sinks
        ref_only = ref_sinks - primary_sinks

        if not primary_only and not ref_only:
            return None

        findings: list[Finding] = []

        if primary_only:
            severity = _sinks_severity(primary_only)
            best = sorted(primary_only)[0]
            driver = pp.get("driver_class", "")
            findings.append(Finding(
                title=(
                    f"JDBC Driver Divergence: {best} on primary "
                    f"({_driver_family(driver)})"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "primary_only": sorted(primary_only),
                    "ref_index": ref_index,
                    "mechanism": "driver_sink_divergence",
                    "primary_driver": pp.get("driver_class"),
                    "ref_driver": rp.get("driver_class"),
                    "input_preview": _input_preview(inp),
                },
            ))

        if ref_only:
            severity = _sinks_severity(ref_only)
            best = sorted(ref_only)[0]
            driver = rp.get("driver_class", "")
            findings.append(Finding(
                title=(
                    f"JDBC Driver Divergence: {best} on ref_{ref_index} "
                    f"({_driver_family(driver)})"
                ),
                severity=severity,
                input=inp,
                result=reference,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "ref_only": sorted(ref_only),
                    "ref_index": ref_index,
                    "mechanism": "driver_sink_divergence",
                    "primary_driver": pp.get("driver_class"),
                    "ref_driver": rp.get("driver_class"),
                    "input_preview": _input_preview(inp),
                },
            ))

        return findings if findings else None


# ── Strategy 2: Pool Lifecycle Divergence ─────────────────────────

class PoolLifecycleDivergenceStrategy:
    """Detects when a connection pool lifecycle hook executes on one env but not another.

    Connection pools (HikariCP, DBCP2, Tomcat JDBC, Druid) support lifecycle
    hooks like connectionInitSql, validationQuery, initSQL that execute SQL
    during pool initialization or connection validation.  If one pool
    implementation executes the hook but another ignores it, the attacker
    can exploit the permissive pool for SQL injection via configuration.
    """

    name = "jdbc_pool_lifecycle"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        pp = _parse_jdbc_output(primary.stdout)
        rp = _parse_jdbc_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_hook = pp.get("lifecycle_hook_executed", False)
        ref_hook = rp.get("lifecycle_hook_executed", False)

        if primary_hook == ref_hook:
            return None

        hook_type = (pp.get("lifecycle_hook_type") or
                     rp.get("lifecycle_hook_type") or "unknown")

        if primary_hook and not ref_hook:
            # Check if hook execution led to dangerous behavior
            severity = Severity.HIGH if _has_dangerous_behavior(pp) else Severity.MEDIUM
            return Finding(
                title=(
                    f"Pool Lifecycle Divergence: {hook_type} executed "
                    f"on primary"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "hook_type": hook_type,
                    "primary_hook_executed": True,
                    "ref_hook_executed": False,
                    "primary_pool": pp.get("pool_type"),
                    "ref_pool": rp.get("pool_type"),
                    "primary_sinks": sorted(_get_sinks(pp)),
                    "ref_index": ref_index,
                    "mechanism": "pool_lifecycle_divergence",
                    "input_preview": _input_preview(inp),
                },
            )

        if not primary_hook and ref_hook:
            severity = Severity.HIGH if _has_dangerous_behavior(rp) else Severity.MEDIUM
            return Finding(
                title=(
                    f"Pool Lifecycle Divergence: {hook_type} executed "
                    f"on ref_{ref_index}"
                ),
                severity=severity,
                input=inp,
                result=reference,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "hook_type": hook_type,
                    "primary_hook_executed": False,
                    "ref_hook_executed": True,
                    "primary_pool": pp.get("pool_type"),
                    "ref_pool": rp.get("pool_type"),
                    "ref_sinks": sorted(_get_sinks(rp)),
                    "ref_index": ref_index,
                    "mechanism": "pool_lifecycle_divergence",
                    "input_preview": _input_preview(inp),
                },
            )

        return None


# ── Strategy 3: Connection Property Divergence ────────────────────

class ConnectionPropertyDivergenceStrategy:
    """Detects when a dangerous connection property is honored on one side only.

    JDBC drivers support URL parameters that can enable dangerous features:
      - MySQL: autoDeserialize, allowLoadLocalInfile, allowUrlInLocalInfile
      - PostgreSQL: socketFactory, socketFactoryArg, sspiServiceClass
      - H2: INIT (RUNSCRIPT), TRACE_LEVEL_SYSTEM_OUT
      - HSQLDB: shutdown, allow_full_path

    If one driver version honors the property but another strips or ignores
    it, the permissive version is exploitable.
    """

    name = "jdbc_conn_property"

    # Properties that can lead to dangerous behavior
    _DANGEROUS_PROPERTIES = {
        "autoDeserialize", "allowLoadLocalInfile", "allowUrlInLocalInfile",
        "socketFactory", "socketFactoryArg", "sspiServiceClass",
        "INIT", "TRACE_LEVEL_SYSTEM_OUT", "shutdown", "allow_full_path",
        "connectionInitSql", "initSQL", "validationQuery",
        "loggerLevel", "loggerFile",
    }

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> list[Finding] | None:
        pp = _parse_jdbc_output(primary.stdout)
        rp = _parse_jdbc_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_dangerous = _has_dangerous_behavior(pp)
        ref_dangerous = _has_dangerous_behavior(rp)

        # Both dangerous or both safe → no interesting divergence
        if primary_dangerous == ref_dangerous:
            return None

        # Check if URL params include dangerous properties
        primary_params = pp.get("url_params", {})
        ref_params = rp.get("url_params", {})
        if not isinstance(primary_params, dict):
            primary_params = {}
        if not isinstance(ref_params, dict):
            ref_params = {}

        all_params = set(primary_params.keys()) | set(ref_params.keys())
        dangerous_used = all_params & self._DANGEROUS_PROPERTIES

        if not dangerous_used:
            return None

        findings: list[Finding] = []

        if primary_dangerous and not ref_dangerous:
            # Primary is exploitable, reference is not
            primary_sinks = _get_sinks(pp)
            severity = _sinks_severity(primary_sinks)
            for prop in sorted(dangerous_used):
                findings.append(Finding(
                    title=(
                        f"Connection Property Divergence: {prop} "
                        f"honored on primary"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="jdbc_diff",
                    metadata={
                        "strategy": self.name,
                        "property": prop,
                        "primary_value": str(primary_params.get(prop, "")),
                        "ref_value": str(ref_params.get(prop, "")),
                        "primary_sinks": sorted(primary_sinks),
                        "primary_driver": pp.get("driver_class"),
                        "ref_driver": rp.get("driver_class"),
                        "ref_index": ref_index,
                        "mechanism": "conn_property_divergence",
                        "input_preview": _input_preview(inp),
                    },
                ))

        if not primary_dangerous and ref_dangerous:
            ref_sinks = _get_sinks(rp)
            severity = _sinks_severity(ref_sinks)
            for prop in sorted(dangerous_used):
                findings.append(Finding(
                    title=(
                        f"Connection Property Divergence: {prop} "
                        f"honored on ref_{ref_index}"
                    ),
                    severity=severity,
                    input=inp,
                    result=reference,
                    oracle_name="jdbc_diff",
                    metadata={
                        "strategy": self.name,
                        "property": prop,
                        "primary_value": str(primary_params.get(prop, "")),
                        "ref_value": str(ref_params.get(prop, "")),
                        "ref_sinks": sorted(ref_sinks),
                        "primary_driver": pp.get("driver_class"),
                        "ref_driver": rp.get("driver_class"),
                        "ref_index": ref_index,
                        "mechanism": "conn_property_divergence",
                        "input_preview": _input_preview(inp),
                    },
                ))

        return findings if findings else None


# ── Strategy 4: SQL Payload Divergence ────────────────────────────

class SQLPayloadDivergenceStrategy:
    """Detects when the same SQL payload reaches different sinks across environments.

    Some databases allow SQL to escape into OS commands (e.g., H2 CREATE ALIAS,
    PostgreSQL COPY PROGRAM, MySQL INTO OUTFILE).  If the same SQL reaches
    cmd_exec on one env but only sql_exec on another, the permissive env
    has a higher-impact vulnerability.
    """

    name = "jdbc_sql_payload"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> list[Finding] | None:
        pp = _parse_jdbc_output(primary.stdout)
        rp = _parse_jdbc_output(reference.stdout)
        if pp is None or rp is None:
            return None

        # Only relevant when at least one side executed SQL
        primary_sql = pp.get("sql_executed", False)
        ref_sql = rp.get("sql_executed", False)

        if not primary_sql and not ref_sql:
            return None

        primary_sinks = _get_sinks(pp)
        ref_sinks = _get_sinks(rp)

        # Divergence: SQL executed on one side but not the other
        if primary_sql and not ref_sql:
            severity = _sinks_severity(primary_sinks)
            best = sorted(primary_sinks)[0] if primary_sinks else "sql_exec"
            return [Finding(
                title=(
                    f"SQL Payload Divergence: {best} on primary"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "primary_sql_executed": True,
                    "ref_sql_executed": False,
                    "ref_index": ref_index,
                    "mechanism": "sql_payload_divergence",
                    "primary_driver": pp.get("driver_class"),
                    "ref_driver": rp.get("driver_class"),
                    "input_preview": _input_preview(inp),
                },
            )]

        if not primary_sql and ref_sql:
            severity = _sinks_severity(ref_sinks)
            best = sorted(ref_sinks)[0] if ref_sinks else "sql_exec"
            return [Finding(
                title=(
                    f"SQL Payload Divergence: {best} on ref_{ref_index}"
                ),
                severity=severity,
                input=inp,
                result=reference,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "primary_sql_executed": False,
                    "ref_sql_executed": True,
                    "ref_index": ref_index,
                    "mechanism": "sql_payload_divergence",
                    "primary_driver": pp.get("driver_class"),
                    "ref_driver": rp.get("driver_class"),
                    "input_preview": _input_preview(inp),
                },
            )]

        # Both executed SQL but different sinks reached
        primary_only = primary_sinks - ref_sinks
        ref_only = ref_sinks - primary_sinks

        if not primary_only and not ref_only:
            return None

        findings: list[Finding] = []

        if primary_only:
            severity = _sinks_severity(primary_only)
            best = sorted(primary_only)[0]
            findings.append(Finding(
                title=(
                    f"SQL Payload Divergence: {best} on primary"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "primary_only": sorted(primary_only),
                    "ref_index": ref_index,
                    "mechanism": "sql_sink_escalation",
                    "primary_driver": pp.get("driver_class"),
                    "ref_driver": rp.get("driver_class"),
                    "input_preview": _input_preview(inp),
                },
            ))

        if ref_only:
            severity = _sinks_severity(ref_only)
            best = sorted(ref_only)[0]
            findings.append(Finding(
                title=(
                    f"SQL Payload Divergence: {best} on ref_{ref_index}"
                ),
                severity=severity,
                input=inp,
                result=reference,
                oracle_name="jdbc_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "ref_only": sorted(ref_only),
                    "ref_index": ref_index,
                    "mechanism": "sql_sink_escalation",
                    "primary_driver": pp.get("driver_class"),
                    "ref_driver": rp.get("driver_class"),
                    "input_preview": _input_preview(inp),
                },
            ))

        return findings if findings else None


# ── Strategy 5: Auth Bypass Divergence ────────────────────────────

class AuthBypassDivergenceStrategy:
    """Detects when weak/empty credentials are accepted on one env but rejected on another.

    Some database configurations (trust auth in PostgreSQL, embedded H2,
    HSQLDB in-memory) accept connections without proper credentials.  If
    one environment accepts weak credentials while another rejects them,
    it indicates a security configuration gap.
    """

    name = "jdbc_auth_bypass"

    _WEAK_AUTH_METHODS = {"trust", "empty", "none", ""}

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        pp = _parse_jdbc_output(primary.stdout)
        rp = _parse_jdbc_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_connected = pp.get("connected", False)
        ref_connected = rp.get("connected", False)

        # Only interesting when connection status diverges
        if primary_connected == ref_connected:
            return None

        primary_auth = str(pp.get("auth_method", "") or "").lower()
        ref_auth = str(rp.get("auth_method", "") or "").lower()

        # Check if the connecting side used weak auth
        if primary_connected and not ref_connected:
            if primary_auth in self._WEAK_AUTH_METHODS:
                severity = Severity.HIGH
                return Finding(
                    title=(
                        f"Auth Bypass: connection accepted on primary "
                        f"with weak credentials"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="jdbc_diff",
                    metadata={
                        "strategy": self.name,
                        "primary_connected": True,
                        "ref_connected": False,
                        "primary_auth": primary_auth,
                        "ref_auth": ref_auth,
                        "primary_driver": pp.get("driver_class"),
                        "ref_driver": rp.get("driver_class"),
                        "ref_index": ref_index,
                        "mechanism": "auth_bypass_divergence",
                        "primary_sinks": sorted(_get_sinks(pp)),
                        "input_preview": _input_preview(inp),
                    },
                )

        if not primary_connected and ref_connected:
            if ref_auth in self._WEAK_AUTH_METHODS:
                severity = Severity.HIGH
                return Finding(
                    title=(
                        f"Auth Bypass: connection accepted on ref_{ref_index} "
                        f"with weak credentials"
                    ),
                    severity=severity,
                    input=inp,
                    result=reference,
                    oracle_name="jdbc_diff",
                    metadata={
                        "strategy": self.name,
                        "primary_connected": False,
                        "ref_connected": True,
                        "primary_auth": primary_auth,
                        "ref_auth": ref_auth,
                        "primary_driver": pp.get("driver_class"),
                        "ref_driver": rp.get("driver_class"),
                        "ref_index": ref_index,
                        "mechanism": "auth_bypass_divergence",
                        "ref_sinks": sorted(_get_sinks(rp)),
                        "input_preview": _input_preview(inp),
                    },
                )

        return None


# ── Strategy aggregation ──────────────────────────────────────────

def get_jdbc_strategies() -> list:
    """Return JDBC-focused differential strategies plus defaults."""
    from .diff_oracle import DEFAULT_STRATEGIES

    return DEFAULT_STRATEGIES + [
        DriverBehaviorDivergenceStrategy(),
        PoolLifecycleDivergenceStrategy(),
        ConnectionPropertyDivergenceStrategy(),
        SQLPayloadDivergenceStrategy(),
        AuthBypassDivergenceStrategy(),
    ]
