from argparse import Namespace
from pathlib import Path

from webfuzzer.app.factories.differential import configure_differential_oracles
from webfuzzer.app.factories.mutators import build_mutators
from webfuzzer.app.factories.oracles import build_oracles
from webfuzzer.app.factories.targets import build_targets
from webfuzzer.app.persistent_targets import (
    persistent_timeout_for_cmd,
    to_persistent_cmd,
)
from webfuzzer.core.registry import GrammarRegistry
from webfuzzer.fuzzer.targets.persistent_target import PersistentTarget


class TestPgwireFactories:
    def test_build_mutator(self):
        mutators = build_mutators(
            "pgwire",
            GrammarRegistry(),
            "pgsql_wire_session",
            None,
            seed=1,
        )
        assert len(mutators) == 1
        assert mutators[0].name == "pgwire"
        assert mutators[0].mode == "hybrid"

    def test_build_mutator_uses_campaign_mode(self):
        mutators = build_mutators(
            "pgwire",
            GrammarRegistry(),
            "pgsql_wire_session",
            None,
            seed=1,
            campaign_mode="pgwire_research",
        )
        assert mutators[0].mode == "research"

    def test_build_oracle_placeholder_filtered(self):
        assert build_oracles("pgwire") == []

    def test_configure_diff_oracle_uses_pgwire_strategies(self):
        setup = configure_differential_oracles(
            oracles=[],
            oracle_csv="pgwire",
            reference_targets=[],
        )
        diff_oracle = setup.oracles[-1]
        names = {strategy.name for strategy in diff_oracle.strategies}
        assert names == {
            "pgwire_framing",
            "pgwire_error_code_gap",
            "pgwire_state_machine_gap",
            "pgwire_execution_progress_gap",
            "pgwire_smuggle_indicator",
        }

    def test_build_targets_sets_output_env_for_pgwire_target(self):
        args = Namespace(
            target_cmd="python targets/pgsql_wire_target.py --host 127.0.0.1 --port 5432 {input}",
            diff_cmd=[],
            grammar="pgsql_wire_session",
            persistent=False,
            concolic=False,
            concolic_mode="",
            target_coverage=False,
            output_dir=Path("C:/tmp/pgwire-out"),
        )

        def _no_persistent(*args, **kwargs):
            return None

        def _timeout(*args, **kwargs):
            return 1.0

        assembly = build_targets(
            args,
            requested_oracle_names={"pgwire"},
            to_persistent_cmd=_no_persistent,
            persistent_timeout_for_cmd=_timeout,
        )
        assert assembly.target.env == {
            "WEBFUZZER_OUTPUT_DIR": str(Path("C:/tmp/pgwire-out"))
        }

    def test_build_targets_auto_enable_persistent_for_pgwire(self):
        args = Namespace(
            target_cmd="python targets/pgsql_wire_target.py --host 127.0.0.1 --port 5432 {input}",
            diff_cmd=[],
            grammar="pgsql_wire_session",
            persistent=False,
            concolic=False,
            concolic_mode="",
            target_coverage=False,
            output_dir=Path("C:/tmp/pgwire-out"),
        )

        assembly = build_targets(
            args,
            requested_oracle_names={"pgwire"},
            to_persistent_cmd=to_persistent_cmd,
            persistent_timeout_for_cmd=persistent_timeout_for_cmd,
        )

        assert assembly.use_persistent is True
        assert isinstance(assembly.target, PersistentTarget)
        assert assembly.target.env == {
            "WEBFUZZER_OUTPUT_DIR": str(Path("C:/tmp/pgwire-out"))
        }
        assert "targets/pgsql_wire_target_module.py" in assembly.target.command
        assert "--host 127.0.0.1 --port 5432" in assembly.target.command
