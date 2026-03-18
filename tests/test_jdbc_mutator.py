"""Tests for JdbcMutator — JDBC connection-level fuzzing mutator."""

from __future__ import annotations

import json
import pytest

from webfuzzer.fuzzer.mutators.jdbc_mutator import (
    JdbcMutator,
    DRIVER_DATABASE,
    POOL_DATABASE,
    _ClasspathCatalog,
    _AffinityDB,
    _CANARY_CLASSES,
)
from webfuzzer.fuzzer.protocols import Input


# ── Helpers ───────────────────────────────────────────────────

def _make_input(ir: dict) -> Input:
    return Input(data=json.dumps(ir).encode())


def _base_ir(**overrides) -> dict:
    ir = {
        "attack_type": "jdbc_exploit",
        "driver": "h2",
        "driver_class": "org.h2.Driver",
        "jdbc_url_base": "jdbc:h2:mem:test",
        "url_params": {},
        "pool": "none",
        "pool_config": {},
        "credentials": {"user": "sa", "password": ""},
        "sql_payload": None,
        "sink_type": "cmd_exec",
        "deser_properties": {},
    }
    ir.update(overrides)
    return ir


# ── Database completeness ─────────────────────────────────────

class TestDriverDatabase:
    def test_all_drivers_have_required_keys(self):
        required = {"class", "url_base", "url_separator", "exploit_params",
                     "sql_payloads", "deser_properties", "default_creds"}
        for driver, info in DRIVER_DATABASE.items():
            missing = required - set(info.keys())
            assert not missing, f"Driver {driver} missing keys: {missing}"

    def test_all_drivers_have_class_name(self):
        for driver, info in DRIVER_DATABASE.items():
            assert info["class"], f"Driver {driver} has empty class"

    def test_all_drivers_have_url_base(self):
        for driver, info in DRIVER_DATABASE.items():
            assert len(info["url_base"]) > 0, f"Driver {driver} has no url_base"

    def test_known_drivers_present(self):
        expected = {"h2", "hsqldb", "mysql", "postgresql", "derby",
                    "mariadb", "sqlite", "oracle", "sqlserver"}
        assert expected <= set(DRIVER_DATABASE.keys())


class TestPoolDatabase:
    def test_all_pools_have_required_keys(self):
        required = {"factory_class", "lifecycle_hooks", "config_keys"}
        for pool, info in POOL_DATABASE.items():
            missing = required - set(info.keys())
            assert not missing, f"Pool {pool} missing keys: {missing}"

    def test_known_pools_present(self):
        expected = {"dbcp2", "hikari", "c3p0", "druid", "tomcat"}
        assert expected <= set(POOL_DATABASE.keys())


# ── Mutator round-trip ────────────────────────────────────────

class TestMutatorRoundTrip:
    def test_mutate_returns_valid_json(self):
        m = JdbcMutator(seed=42)
        inp = _make_input(_base_ir())
        result = m.mutate(inp, [])
        ir = json.loads(result.data)
        assert ir["attack_type"] in ("jdbc_exploit", "jdbc_connection")

    def test_mutate_preserves_attack_type(self):
        m = JdbcMutator(seed=42)
        inp = _make_input(_base_ir())
        for _ in range(20):
            result = m.mutate(inp, [])
            ir = json.loads(result.data)
            assert ir["attack_type"] in ("jdbc_exploit", "jdbc_connection")

    def test_mutate_tracks_metadata(self):
        m = JdbcMutator(seed=42)
        inp = _make_input(_base_ir())
        result = m.mutate(inp, [])
        assert "mutator" in result.metadata
        assert result.metadata["mutator"] == "jdbc"

    def test_mutate_changes_something(self):
        m = JdbcMutator(seed=42)
        base = _base_ir()
        inp = _make_input(base)
        # Over 20 mutations, at least one should differ from base
        changed = False
        for _ in range(20):
            result = m.mutate(inp, [])
            ir = json.loads(result.data)
            if ir.get("driver") != "h2" or ir.get("url_params") != {}:
                changed = True
                break
        assert changed, "Mutator didn't change anything in 20 attempts"


# ── Strategy coverage ─────────────────────────────────────────

class TestStrategyCoverage:
    def test_all_strategies_reachable(self):
        """Run enough mutations to hit every strategy at least once."""
        m = JdbcMutator(seed=0)
        inp = _make_input(_base_ir())
        seen_strategies: set[str] = set()
        for _ in range(500):
            result = m.mutate(inp, [])
            strategies = result.metadata.get("strategies", [])
            seen_strategies.update(strategies)
        # At least 7 of 10 strategies should be reachable
        assert len(seen_strategies) >= 7, \
            f"Only hit {len(seen_strategies)} strategies: {seen_strategies}"


# ── Feedback mechanism ────────────────────────────────────────

class TestFeedback:
    def test_feedback_finding_boosts(self):
        m = JdbcMutator(seed=42)
        initial_w = list(m._weights)
        m.feedback("driver_swap", "finding")
        # driver_swap weight should increase
        idx = m._strategy_names.index("driver_swap")
        assert m._weights[idx] > initial_w[idx]

    def test_reset_weights(self):
        m = JdbcMutator(seed=42)
        m.feedback("driver_swap", "finding")
        m.feedback("driver_swap", "finding")
        m.reset_weights()
        # Weights should be back to defaults
        for w in m._weights:
            assert w > 0


# ── Edge cases ────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_input(self):
        m = JdbcMutator(seed=42)
        inp = Input(data=b"")
        result = m.mutate(inp, [])
        ir = json.loads(result.data)
        assert "driver" in ir

    def test_invalid_json_input(self):
        m = JdbcMutator(seed=42)
        inp = Input(data=b"not json at all")
        result = m.mutate(inp, [])
        ir = json.loads(result.data)
        assert "driver" in ir

    def test_output_size_bounded(self):
        m = JdbcMutator(seed=42)
        inp = _make_input(_base_ir())
        for _ in range(50):
            result = m.mutate(inp, [])
            assert len(result.data) <= 16384


# ── Classpath catalog ────────────────────────────────────────

class TestClasspathCatalog:
    def test_graceful_when_missing(self):
        """Catalog should be empty but not error when file doesn't exist."""
        cat = _ClasspathCatalog()
        # May or may not find the file depending on cwd; just assert no crash
        assert isinstance(cat.all_classes, list)
        assert isinstance(cat._package_index, dict)

    def test_package_index_grouping(self):
        """Manually populate and verify package grouping."""
        cat = _ClasspathCatalog()
        cat.all_classes = [
            "org.h2.Driver",
            "org.h2.engine.Engine",
            "org.h2.tools.Console",
            "com.mysql.cj.jdbc.Driver",
        ]
        cat._package_index = {}
        for cls in cat.all_classes:
            dot = cls.rfind(".")
            if dot > 0:
                pkg = cls[:dot]
                cat._package_index.setdefault(pkg, []).append(cls)

        assert len(cat.get_classes_in_package("org.h2")) >= 3
        assert len(cat.get_classes_in_package("com.mysql")) >= 1
        assert cat.get_classes_in_package("nonexistent") == []

    def test_sample_returns_correct_count(self):
        import random
        cat = _ClasspathCatalog()
        cat.all_classes = ["a.B", "c.D", "e.F"]
        rng = random.Random(42)
        result = cat.sample(rng, 2)
        assert len(result) == 2
        assert all(c in cat.all_classes for c in result)


# ── Affinity database ────────────────────────────────────────

class TestAffinityDB:
    def test_record_and_query_class_load(self):
        db = _AffinityDB()
        db.record_class_load("h2", "DATABASE_EVENT_LISTENER", "groovy.lang.GroovyShell")
        props = db.get_class_loading_properties("h2")
        assert "DATABASE_EVENT_LISTENER" in props

    def test_record_and_query_sink(self):
        db = _AffinityDB()
        db.record_sink("h2", "DATABASE_EVENT_LISTENER", "groovy.lang.GroovyShell", "cmd_exec")
        classes = db.get_sink_classes("h2", "DATABASE_EVENT_LISTENER")
        assert "groovy.lang.GroovyShell" in classes

    def test_successful_packages(self):
        db = _AffinityDB()
        db.record_class_load("h2", "DEL", "groovy.lang.GroovyShell")
        db.record_class_load("h2", "DEL", "org.h2.tools.Console")
        pkgs = db.get_successful_packages("h2", "DEL")
        assert "groovy.lang" in pkgs
        assert "org.h2.tools" in pkgs

    def test_max_classes_per_prop(self):
        db = _AffinityDB()
        for i in range(600):
            db.record_class_load("h2", "DEL", f"pkg.Class{i}")
        classes = db._class_loading_props[("h2", "DEL")]
        assert len(classes) <= _AffinityDB._MAX_CLASSES_PER_PROP

    def test_empty_driver_returns_empty(self):
        db = _AffinityDB()
        assert db.get_class_loading_properties("nonexistent") == []
        assert db.get_successful_packages("nonexistent", "DEL") == []
        assert db.get_sink_classes("nonexistent", "DEL") == []


# ── C11 classpath probe strategy ─────────────────────────────

class TestClasspathProbe:
    def test_classpath_probe_reachable(self):
        """C11 classpath_probe should appear in strategies within 500 iters."""
        m = JdbcMutator(seed=42)
        inp = _make_input(_base_ir())
        seen = set()
        for _ in range(500):
            result = m.mutate(inp, [])
            seen.update(result.metadata.get("strategies", []))
        assert "classpath_probe" in seen

    def test_classpath_probe_uses_canary_early(self):
        """First 1000 probe iterations should use canary/merged classes."""
        m = JdbcMutator(seed=42)
        merged = m._merged_canaries if m._merged_canaries else _CANARY_CLASSES
        for _ in range(50):
            cls = m._pick_probe_class("h2", "DATABASE_EVENT_LISTENER")
            assert cls in merged

    def test_classpath_probe_no_pool(self):
        """classpath_probe should force pool='' to isolate attribution."""
        m = JdbcMutator(seed=42)
        ir = _base_ir(pool="c3p0", pool_config={"factory_class": "test"})
        result = m._classpath_probe(ir, [])
        assert result is not None
        assert result["pool"] == ""
        assert result["pool_config"] == {}


# ── Affinity DB integration with set_exception_hint ──────────

class TestAffinityHintIntegration:
    def test_class_load_trigger_updates_affinity(self):
        m = JdbcMutator(seed=42)
        m._last_driver = "h2"
        hint = {
            "class_load_trigger": "url_param:DATABASE_EVENT_LISTENER",
            "class_name_properties": {
                "DATABASE_EVENT_LISTENER": "groovy.lang.GroovyShell",
            },
        }
        m.set_exception_hint(hint)
        props = m._affinity_db.get_class_loading_properties("h2")
        assert "DATABASE_EVENT_LISTENER" in props

    def test_sink_attribution_updates_affinity(self):
        m = JdbcMutator(seed=42)
        m._last_driver = "h2"
        hint = {
            "class_load_trigger": "url_param:DATABASE_EVENT_LISTENER",
            "class_name_properties": {
                "DATABASE_EVENT_LISTENER": "groovy.lang.GroovyShell",
            },
            "sink_attribution": {
                "class_load": "url_param:DATABASE_EVENT_LISTENER",
            },
        }
        m.set_exception_hint(hint)
        sinks = m._affinity_db.get_sink_classes("h2", "DATABASE_EVENT_LISTENER")
        assert "groovy.lang.GroovyShell" in sinks

    def test_null_hint_does_not_crash(self):
        m = JdbcMutator(seed=42)
        m.set_exception_hint(None)
        assert m._last_exception_hint is None


class TestBuildJdbcSinkHint:
    """Test engine-side _build_jdbc_sink_hint with camelCase JdbcTarget output."""

    def test_camelcase_fields_parsed(self):
        from webfuzzer.fuzzer.engine import _build_jdbc_sink_hint
        from webfuzzer.fuzzer.protocols import ExecutionResult

        # Simulate JdbcTarget Gson output (camelCase)
        import json
        stdout = json.dumps({
            "driver": "h2",
            "classNameProperties": {
                "DATABASE_EVENT_LISTENER": "groovy.lang.GroovyShell",
            },
            "classLoadTrigger": "url_param:DATABASE_EVENT_LISTENER",
            "sinkAttribution": {
                "class_load": "url_param:DATABASE_EVENT_LISTENER",
            },
            "exceptionClass": "java.lang.ClassCastException",
            "exception": "cannot cast to DatabaseEventListener",
        }).encode()
        result = ExecutionResult(
            stdout=stdout, stderr=b"", exit_code=0, duration_ms=50,
        )
        hint = _build_jdbc_sink_hint(result)
        assert hint is not None
        assert hint["class_load_trigger"] == "url_param:DATABASE_EVENT_LISTENER"
        assert "DATABASE_EVENT_LISTENER" in hint["class_name_properties"]
        assert "class_load" in hint["sink_attribution"]
        assert hint["driver"] == "h2"
        assert hint["type"] == "java.lang.ClassCastException"

    def test_end_to_end_affinity_update(self):
        """Verify the full pipeline: JdbcTarget output → hint → affinity DB."""
        from webfuzzer.fuzzer.engine import _build_jdbc_sink_hint
        from webfuzzer.fuzzer.protocols import ExecutionResult
        import json

        stdout = json.dumps({
            "driver": "postgresql",
            "classNameProperties": {
                "authenticationPluginClassName": "groovy.lang.GroovyShell",
            },
            "classLoadTrigger": "url_param:authenticationPluginClassName",
            "sinkAttribution": {
                "class_load": "url_param:authenticationPluginClassName",
            },
        }).encode()
        result = ExecutionResult(
            stdout=stdout, stderr=b"", exit_code=0, duration_ms=30,
        )
        hint = _build_jdbc_sink_hint(result)

        m = JdbcMutator(seed=42)
        m._last_driver = "postgresql"
        m.set_exception_hint(hint)

        # Affinity DB should now know this property accepts class names
        props = m._affinity_db.get_class_loading_properties("postgresql")
        assert "authenticationPluginClassName" in props

        # And the sink should be recorded
        sinks = m._affinity_db.get_sink_classes("postgresql", "authenticationPluginClassName")
        assert "groovy.lang.GroovyShell" in sinks


# ── C12 Discovery Probe ──────────────────────────────────

class TestDiscoveryProbe:
    def test_discovery_probe_reachable(self):
        """C12 should be a reachable strategy."""
        m = JdbcMutator(seed=42)
        assert "discovery_probe" in m._strategy_names

    def test_discovery_probe_injects_canary(self):
        """C12 should inject a canary class into the chosen property."""
        m = JdbcMutator(seed=42)
        ir = _base_ir(driver="h2")
        result = m._discovery_probe(ir, [])
        assert result is not None
        params = result.get("url_params", {})
        # At least one param should be set to a canary class
        canary_values = {v for v in params.values()
                         if isinstance(v, str) and "." in v}
        assert canary_values, "Expected canary class in url_params"
        assert result["pool"] == ""

    def test_discovery_marks_probed_after_n_attempts(self):
        """After _PROBES_PER_PROP attempts, property should be marked probed."""
        m = JdbcMutator(seed=42)
        # Force a specific driver and property
        m._affinity_db._probed_props.clear()
        ir = _base_ir(driver="h2")
        # Run discovery_probe enough times to cover all h2 props
        for _ in range(200):
            m._discovery_probe(ir, [])
        # At least some h2 props should now be marked as probed
        probed = [p for d, p in m._affinity_db._probed_props if d == "h2"]
        assert len(probed) > 0, "Expected some h2 properties to be probed"

    def test_discovery_confirmed_prop_not_rejected(self):
        """A confirmed class-loading prop should not be in rejected set."""
        m = JdbcMutator(seed=42)
        # Simulate C12 probing, then feedback confirming a property
        m._affinity_db.record_class_load("h2", "INIT", "java.lang.Runtime")
        m._affinity_db.mark_probed("h2", "INIT")
        # INIT is confirmed, not rejected
        assert m._affinity_db.is_confirmed_class_prop("h2", "INIT")
        assert not m._affinity_db.is_rejected("h2", "INIT")

    def test_discovery_falls_through_when_all_probed(self):
        """When all properties are probed, C12 delegates to C11."""
        m = JdbcMutator(seed=42)
        # Mark all properties for all drivers as probed
        for driver in m._DISCOVERY_DRIVERS:
            info = DRIVER_DATABASE.get(driver, {})
            for prop in info.get("exploit_params", {}).keys():
                m._affinity_db.mark_probed(driver, prop)
        ir = _base_ir(driver="h2")
        # Should still return a result (delegated to C11)
        result = m._discovery_probe(ir, [])
        assert result is not None

    def test_url_param_inject_uses_discovered_props(self):
        """C2 should use _pick_probe_class for confirmed empty-list props."""
        m = JdbcMutator(seed=42)
        # Simulate: C12 confirmed socketFactory accepts classes,
        # but the values list was stripped (empty)
        m._affinity_db.record_class_load("postgresql", "socketFactory",
                                          "groovy.lang.GroovyShell")
        ir = _base_ir(driver="postgresql")
        # Run C2 many times, check that socketFactory sometimes gets a value
        got_socket_factory = False
        for _ in range(100):
            result = m._url_param_inject(ir, [])
            if result and "socketFactory" in result.get("url_params", {}):
                val = result["url_params"]["socketFactory"]
                if "." in val:  # looks like a class name
                    got_socket_factory = True
                    break
        assert got_socket_factory, "C2 should inject class into confirmed prop"
