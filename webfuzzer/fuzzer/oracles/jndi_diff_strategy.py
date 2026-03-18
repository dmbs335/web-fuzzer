"""JNDI ObjectFactory differential strategies for cross-environment comparison.

Compares JNDI Reference resolution behavior across different:
  - JDK versions (8u191 boundary, 11+, 17+, 21+)
  - Application server environments (Tomcat 9 vs 10, JBoss, WebLogic)
  - Security configurations (SecurityManager on/off, trustURLCodebase)
  - Classpath compositions (different ObjectFactory sets)

Strategies (DiffStrategy protocol — compare(inp, primary, reference, ref_index)):
  1. FactoryResolutionDivergence: factory loads on one env but not another
  2. SinkReachDivergence: code execution on one env but not another
  3. SecurityBypassDivergence: SecurityManager blocks on one but not another
  4. JDBCDriverDivergence: JDBC exploitation works on one env but not another
  5. JDKVersionDivergence: behavior difference across JDK versions
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


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


def _has_dangerous_behavior(parsed: dict) -> bool:
    if parsed.get("sink_reached"):
        return True
    for k in ("process_spawned", "jndi_lookup", "file_write",
              "class_loaded", "network_connected", "sql_executed",
              "jdbc_connected"):
        if parsed.get(k):
            return True
    return False


def _get_sinks(parsed: dict) -> set[str]:
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


_CRITICAL_SINKS = {"cmd_exec", "jndi_lookup", "script_exec", "el_exec"}
_HIGH_SINKS = {"jdbc_exec", "sql_exec", "file_write", "class_load"}


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


# ── Strategy 1: Factory Resolution Divergence ─────────────────

class FactoryResolutionDivergenceStrategy:
    """Detects when a factory loads on one env but not another."""

    name = "jndi_factory_resolution"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        pp = _parse_jndi_output(primary.stdout)
        rp = _parse_jndi_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_loaded = pp.get("factory_loaded", False)
        ref_loaded = rp.get("factory_loaded", False)

        if primary_loaded == ref_loaded:
            return None

        if primary_loaded and not ref_loaded:
            severity = Severity.HIGH if _has_dangerous_behavior(pp) else Severity.MEDIUM
            factory = pp.get("factory_class", "")
            return Finding(
                title=f"JNDI factory loads on primary but not ref_{ref_index}",
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_factory": factory,
                    "primary_loaded": True,
                    "ref_loaded": False,
                    "ref_index": ref_index,
                    "mechanism": "factory_classpath_divergence",
                    "primary_sinks": sorted(_get_sinks(pp)),
                    "input_preview": _input_preview(inp),
                },
            )

        if not primary_loaded and ref_loaded:
            factory = rp.get("factory_class", "")
            severity = Severity.HIGH if _has_dangerous_behavior(rp) else Severity.MEDIUM
            return Finding(
                title=f"JNDI factory loads on ref_{ref_index} but not primary",
                severity=severity,
                input=inp,
                result=reference,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "ref_factory": factory,
                    "primary_loaded": False,
                    "ref_loaded": True,
                    "ref_index": ref_index,
                    "mechanism": "factory_classpath_divergence",
                    "ref_sinks": sorted(_get_sinks(rp)),
                    "input_preview": _input_preview(inp),
                },
            )

        return None


# ── Strategy 2: Sink Reach Divergence ─────────────────────────

class SinkReachDivergenceStrategy:
    """Detects when a dangerous sink is reached on one env but not another."""

    name = "jndi_sink_reach"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> list[Finding] | None:
        pp = _parse_jndi_output(primary.stdout)
        rp = _parse_jndi_output(reference.stdout)
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
            critical = primary_only & _CRITICAL_SINKS
            high = primary_only & _HIGH_SINKS
            severity = Severity.CRITICAL if critical else (
                Severity.HIGH if high else Severity.MEDIUM)
            findings.append(Finding(
                title=f"JNDI sink divergence: primary reaches {sorted(primary_only)}",
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "primary_only": sorted(primary_only),
                    "ref_index": ref_index,
                    "mechanism": "primary_sink_not_on_ref",
                    "factory": pp.get("factory_class"),
                    "method": pp.get("method_invoked"),
                    "input_preview": _input_preview(inp),
                },
            ))

        if ref_only:
            critical = ref_only & _CRITICAL_SINKS
            high = ref_only & _HIGH_SINKS
            severity = Severity.CRITICAL if critical else (
                Severity.HIGH if high else Severity.MEDIUM)
            findings.append(Finding(
                title=f"JNDI sink divergence: ref_{ref_index} reaches {sorted(ref_only)}",
                severity=severity,
                input=inp,
                result=reference,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sinks": sorted(primary_sinks),
                    "ref_sinks": sorted(ref_sinks),
                    "ref_only": sorted(ref_only),
                    "ref_index": ref_index,
                    "mechanism": "ref_sink_not_on_primary",
                    "factory": rp.get("factory_class"),
                    "input_preview": _input_preview(inp),
                },
            ))

        return findings if findings else None


# ── Strategy 3: Security Bypass Divergence ────────────────────

class SecurityBypassDivergenceStrategy:
    """Detects SecurityManager/policy bypass across environments."""

    name = "jndi_security_bypass"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        pp = _parse_jndi_output(primary.stdout)
        rp = _parse_jndi_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_sm = pp.get("security_manager", False)
        ref_sm = rp.get("security_manager", False)
        primary_dangerous = _has_dangerous_behavior(pp)
        ref_dangerous = _has_dangerous_behavior(rp)

        # Same security config → no divergence of interest here
        if primary_sm == ref_sm:
            return None

        if primary_sm and not ref_sm and not primary_dangerous and ref_dangerous:
            return Finding(
                title=f"JNDI: SM blocks on primary, bypassed on ref_{ref_index}",
                severity=Severity.HIGH,
                input=inp,
                result=reference,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sm": True,
                    "ref_sm": False,
                    "ref_sinks": sorted(_get_sinks(rp)),
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        if not primary_sm and ref_sm and primary_dangerous and not ref_dangerous:
            return Finding(
                title=f"JNDI: SM blocks on ref_{ref_index}, bypassed on primary",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_sm": False,
                    "ref_sm": True,
                    "primary_sinks": sorted(_get_sinks(pp)),
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        return None


# ── Strategy 4: JDBC Driver Divergence ────────────────────────

class JDBCDriverDivergenceStrategy:
    """Detects JDBC driver exploitation divergence."""

    name = "jndi_jdbc_driver"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        pp = _parse_jndi_output(primary.stdout)
        rp = _parse_jndi_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_sql = pp.get("sql_executed", False)
        ref_sql = rp.get("sql_executed", False)
        primary_jdbc = pp.get("jdbc_connected", False)
        ref_jdbc = rp.get("jdbc_connected", False)
        primary_driver = pp.get("jdbc_driver", "")
        ref_driver = rp.get("jdbc_driver", "")

        if primary_sql and not ref_sql:
            return Finding(
                title=f"JNDI JDBC: SQL exec on primary but not ref_{ref_index}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_driver": primary_driver,
                    "ref_driver": ref_driver,
                    "mechanism": "sql_exec_divergence",
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        if not primary_sql and ref_sql:
            return Finding(
                title=f"JNDI JDBC: SQL exec on ref_{ref_index} but not primary",
                severity=Severity.HIGH,
                input=inp,
                result=reference,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_driver": primary_driver,
                    "ref_driver": ref_driver,
                    "mechanism": "sql_exec_divergence",
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        if primary_jdbc and not ref_jdbc:
            return Finding(
                title=f"JNDI JDBC: connects on primary but not ref_{ref_index}",
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_driver": primary_driver,
                    "ref_driver": ref_driver,
                    "mechanism": "jdbc_connect_divergence",
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        return None


# ── Strategy 5: JDK Version Divergence ────────────────────────

class JDKVersionDivergenceStrategy:
    """Detects behavior differences tied to JDK version boundaries."""

    name = "jndi_jdk_version"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        pp = _parse_jndi_output(primary.stdout)
        rp = _parse_jndi_output(reference.stdout)
        if pp is None or rp is None:
            return None

        primary_ver = pp.get("jdk_version", "")
        ref_ver = rp.get("jdk_version", "")
        if primary_ver == ref_ver:
            return None

        primary_dangerous = _has_dangerous_behavior(pp)
        ref_dangerous = _has_dangerous_behavior(rp)
        if primary_dangerous == ref_dangerous:
            return None

        if primary_dangerous:
            return Finding(
                title=f"JNDI: exploitable on JDK {primary_ver} but not {ref_ver}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_jdk": primary_ver,
                    "ref_jdk": ref_ver,
                    "primary_sinks": sorted(_get_sinks(pp)),
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )
        else:
            return Finding(
                title=f"JNDI: exploitable on JDK {ref_ver} but not {primary_ver}",
                severity=Severity.HIGH,
                input=inp,
                result=reference,
                oracle_name="jndi_diff",
                metadata={
                    "strategy": self.name,
                    "primary_jdk": primary_ver,
                    "ref_jdk": ref_ver,
                    "ref_sinks": sorted(_get_sinks(rp)),
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )


# ── Strategy aggregation ──────────────────────────────────────

def get_jndi_strategies() -> list:
    """Return JNDI-focused differential strategies plus defaults."""
    from .diff_oracle import DEFAULT_STRATEGIES

    return DEFAULT_STRATEGIES + [
        FactoryResolutionDivergenceStrategy(),
        SinkReachDivergenceStrategy(),
        SecurityBypassDivergenceStrategy(),
        JDBCDriverDivergenceStrategy(),
        JDKVersionDivergenceStrategy(),
    ]
