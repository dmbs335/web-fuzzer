from webfuzzer.fuzzer.mutators.pgwire_mutator import PgwireMutator
from webfuzzer.fuzzer.protocols import Input


class TestPgwireMutator:
    def test_emits_transcript_with_metadata(self):
        mutator = PgwireMutator(seed=7, mode="hybrid")
        out = mutator.mutate(Input(data=b"seed"), [])
        assert out.data.startswith(b"WFPG1\nM ")
        assert b'"transport_mode":"pgsql_v3"' in out.data
        assert b'\nA {"op":"startup"' in out.data
        assert out.metadata["mutator"] == "pgwire"
        assert out.metadata["variant_family"]
        assert out.metadata["delivery_mode"] in {
            "single",
            "split_header",
            "pause_midframe",
        }

    def test_stable_hint_keeps_family(self):
        mutator = PgwireMutator(seed=3, mode="stable")
        out = mutator.mutate(
            Input(data=b"x", metadata={"variant_family": "simple_query_stacked"}),
            [],
        )
        assert out.metadata["variant_family"] == "simple_query_stacked"
        assert b"wf_canary" in out.data
        assert out.metadata["pgwire_mode"] == "stable"

    def test_research_mode_emits_axis_metadata(self):
        mutator = PgwireMutator(seed=19, mode="research")
        out = mutator.mutate(Input(data=b"x"), [])
        assert out.metadata["pgwire_mode"] == "research"
        assert out.metadata["axis_framing"]
        assert out.metadata["axis_state"]
        assert out.metadata["axis_delivery"]
        assert out.metadata["axis_query"]
        assert out.metadata["axis_startup"]

    def test_stable_ssl_probe_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(data=b"x", metadata={"variant_family": "ssl_probe"}),
            [],
        )
        assert out.metadata["variant_family"] == "ssl_probe"
        assert out.metadata["probe_mode"] == "ssl_request"
        assert b'"op":"ssl_request"' in out.data

    def test_stable_gss_then_query_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(data=b"x", metadata={"variant_family": "gss_then_query"}),
            [],
        )
        assert out.metadata["variant_family"] == "gss_then_query"
        assert out.metadata["probe_mode"] == "gssenc_request"
        assert out.metadata["axis_state"] == "probe_then_startup"
        assert b'"op":"gssenc_request"' in out.data
        assert b'"op":"query"' in out.data

    def test_stable_gss_then_extended_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(data=b"x", metadata={"variant_family": "gss_then_extended"}),
            [],
        )
        assert out.metadata["variant_family"] == "gss_then_extended"
        assert out.metadata["axis_state"] == "probe_then_extended"
        assert b'"op":"gssenc_request"' in out.data
        assert b'"op":"parse"' in out.data
        assert b'"op":"bind"' in out.data
        assert b'"op":"execute"' in out.data

    def test_stable_gss_then_extended_split_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(data=b"x", metadata={"variant_family": "gss_then_extended_split"}),
            [],
        )
        assert out.metadata["variant_family"] == "gss_then_extended_split"
        assert out.metadata["delivery_mode"] == "split_header"
        assert out.metadata["axis_delivery"] == "split_header"
        assert b'"op":"gssenc_request"' in out.data
        assert b'"op":"execute"' in out.data

    def test_stable_gss_then_duplicate_startup_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(data=b"x", metadata={"variant_family": "gss_then_duplicate_startup"}),
            [],
        )
        assert out.metadata["variant_family"] == "gss_then_duplicate_startup"
        assert out.metadata["axis_state"] == "duplicate_startup_after_probe"
        assert out.metadata["startup_mode"] == "dup_user"
        assert out.data.count(b'\nA {"op":"startup"') == 2

    def test_stable_gss_then_extended_len_plus_4_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(
                data=b"x",
                metadata={"variant_family": "gss_then_extended_len_plus_4"},
            ),
            [],
        )
        assert out.metadata["variant_family"] == "gss_then_extended_len_plus_4"
        assert out.metadata["frame_corruption"] == "query_len_plus_4"
        assert out.metadata["axis_framing"] == "len_plus_4"

    def test_stable_gss_then_extended_extra_sync_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(
                data=b"x",
                metadata={"variant_family": "gss_then_extended_extra_sync"},
            ),
            [],
        )
        assert out.metadata["variant_family"] == "gss_then_extended_extra_sync"
        assert out.data.count(b'"op":"sync"') == 2

    def test_stable_probe_then_sync_family(self):
        mutator = PgwireMutator(seed=5, mode="stable")
        out = mutator.mutate(
            Input(data=b"x", metadata={"variant_family": "probe_then_sync"}),
            [],
        )
        assert out.metadata["variant_family"] == "probe_then_sync"
        assert out.metadata["axis_state"] == "probe_then_sync"
        assert out.metadata["axis_query"] == "sync_only"
        assert b'"op":"gssenc_request"' in out.data
        assert b'"op":"sync"' in out.data
