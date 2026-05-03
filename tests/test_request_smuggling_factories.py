from argparse import Namespace
from pathlib import Path

from webfuzzer.app.factories.targets import build_targets
from webfuzzer.app.factories.differential import configure_differential_oracles
from webfuzzer.app.factories.mutators import build_mutators
from webfuzzer.app.factories.oracles import build_oracles
from webfuzzer.app.persistent_targets import to_persistent_cmd
from webfuzzer.core.registry import GrammarRegistry
from webfuzzer.fuzzer.targets.persistent_target import PersistentTarget


class TestRequestSmugglingFactories:
    def test_build_mutator(self):
        mutators = build_mutators(
            "request_smuggling",
            GrammarRegistry(),
            "request_smuggling_stream",
            None,
            seed=1,
        )
        assert len(mutators) == 1
        assert mutators[0].name == "request_smuggling"
        assert mutators[0].mode == "hybrid"

    def test_build_mutator_uses_campaign_mode(self):
        mutators = build_mutators(
            "request_smuggling",
            GrammarRegistry(),
            "request_smuggling_stream",
            None,
            seed=1,
            campaign_mode="hrs_research",
        )
        assert mutators[0].mode == "research"

    def test_build_oracle_placeholder_filtered(self):
        oracles = build_oracles("request_smuggling")
        assert oracles == []

    def test_configure_diff_oracle_uses_request_smuggling_strategies(self):
        setup = configure_differential_oracles(
            oracles=[],
            oracle_csv="request_smuggling",
            reference_targets=[],
        )
        diff_oracle = setup.oracles[-1]
        names = {strategy.name for strategy in diff_oracle.strategies}
        assert "request_smuggling_framing" in names
        assert "request_smuggling_canary" in names
        assert "request_smuggling_pause_probe" in names
        assert "request_smuggling_chunk_gap" in names
        assert "request_smuggling_routing_gap" in names
        assert "request_smuggling_trailer_effective_header_gap" in names
        assert "request_smuggling_connection_locked" in names

    def test_build_targets_sets_output_env_for_request_smuggling_target(self):
        args = Namespace(
            target_cmd="python targets/request_smuggling_target.py --host 127.0.0.1 --port 18081 {input}",
            diff_cmd=[],
            grammar="json",
            persistent=False,
            concolic=False,
            concolic_mode="",
            target_coverage=False,
            output_dir=Path("C:/tmp/hrs-out"),
        )

        def _no_persistent(*args, **kwargs):
            return None

        def _timeout(*args, **kwargs):
            return 1.0

        assembly = build_targets(
            args,
            requested_oracle_names={"request_smuggling"},
            to_persistent_cmd=_no_persistent,
            persistent_timeout_for_cmd=_timeout,
        )
        assert assembly.target.env == {"WEBFUZZER_OUTPUT_DIR": str(Path("C:/tmp/hrs-out"))}

    def test_request_smuggling_target_maps_to_native_persistent(self):
        cmd = "python targets/request_smuggling_target.py --host 127.0.0.1 --port 18088 {input}"
        persistent = to_persistent_cmd(cmd)
        assert persistent is not None
        assert "targets/request_smuggling_target.py" in persistent
        assert "--persistent" in persistent

    def test_build_targets_passes_output_env_to_persistent_request_smuggling_target(self):
        args = Namespace(
            target_cmd="python targets/request_smuggling_target.py --host 127.0.0.1 --port 18088 {input}",
            diff_cmd=[],
            grammar="request_smuggling_stream",
            persistent=False,
            concolic=False,
            concolic_mode="",
            target_coverage=False,
            output_dir=Path("C:/tmp/hrs-out"),
        )

        def _timeout(*args, **kwargs):
            return 2.0

        assembly = build_targets(
            args,
            requested_oracle_names={"request_smuggling"},
            to_persistent_cmd=to_persistent_cmd,
            persistent_timeout_for_cmd=_timeout,
        )
        assert isinstance(assembly.target, PersistentTarget)
        assert assembly.target.env == {"WEBFUZZER_OUTPUT_DIR": str(Path("C:/tmp/hrs-out"))}
