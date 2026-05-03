from dataclasses import dataclass, field as dc_field

from webfuzzer.fuzzer.mutators.request_smuggling_mutator import (
    RequestSmugglingMutator,
    WireFragment,
    _parse_wire_fragment,
)
from webfuzzer.fuzzer.protocols import Input


# ---------------------------------------------------------------------------
# Lightweight Seed stub for corpus-aware tests
# ---------------------------------------------------------------------------
@dataclass
class _StubSeed:
    input: Input
    feature_set: set = dc_field(default_factory=set)


class TestRequestSmugglingMutator:
    def test_builds_request_stream_with_phase2_metadata(self):
        mutator = RequestSmugglingMutator(seed=7, mode="hybrid")
        out = mutator.mutate(Input(data=b"seed"), [])
        assert b"HTTP/1.1" in out.data
        assert b"X-WF-Request-ID:" in out.data
        assert b"X-WF-Delivery:" in out.data
        assert b"X-WF-Probe:" in out.data
        assert b"X-WF-Axis-Framing:" in out.data
        assert b"/__canary__/" in out.data
        assert out.metadata["mutator"] == "request_smuggling"
        assert out.metadata["transport_mode"] in {"h1_raw", "h2_raw"}
        assert out.metadata["request_smuggling_mode"] in {"stable", "research"}
        assert out.metadata["delivery_mode"] in {
            "oneshot_h1",
            "pause_probe_h1",
            "halfclose_probe_h1",
            "h2_raw",
        }
        assert "request_id" in out.metadata
        assert "canary_path" in out.metadata
        assert "axis_projection" in out.metadata
        assert "stream_shape" in out.metadata

    def test_h2_hint_biases_family(self):
        mutator = RequestSmugglingMutator(seed=1, mode="hybrid")
        out = mutator.mutate(Input(data=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), [])
        assert out.metadata["variant_family"] in {
            "h2_cl",
            "h2_te",
            "h2_0",
            "h2_dup_authority",
            "h2_header_gap",
            "h2_end_stream_gap",
        }
        assert out.metadata["transport_mode"] == "h2_raw"
        assert out.metadata["delivery_mode"] == "h2_raw"
        assert out.metadata["h2_mode"] != "none"
        assert out.metadata["impact_hint"].startswith("/")

    def test_generates_zero_length_family(self):
        mutator = RequestSmugglingMutator(seed=3, mode="stable", havoc_intensity=0.0)
        inp = Input(data=b"x", metadata={"variant_family": "cl_0"})
        out = mutator.mutate(inp, [])
        assert out.metadata["variant_family"] == "cl_0"
        assert "CL.0" in out.metadata["taxonomy_tags"]
        assert b"Content-Length: 0" in out.data
        assert out.metadata["request_smuggling_mode"] == "stable"

    def test_0_cl_uses_obfuscated_content_length_header(self):
        mutator = RequestSmugglingMutator(seed=13, mode="stable", havoc_intensity=0.0)
        inp = Input(data=b"x", metadata={"variant_family": "0_cl"})
        out = mutator.mutate(inp, [])
        assert out.metadata["variant_family"] == "0_cl"
        assert out.data.startswith(b"GET ")
        assert b"Content-Length : " in out.data

    def test_generates_chunk_family_metadata(self):
        mutator = RequestSmugglingMutator(seed=5, mode="stable")
        inp = Input(data=b"x", metadata={"variant_family": "chunk_ext"})
        out = mutator.mutate(inp, [])
        assert out.metadata["variant_family"] == "chunk_ext"
        assert out.metadata["chunk_shape"] == "chunk_ext"
        assert "chunk_extension" in out.metadata["taxonomy_tags"]

    def test_trailer_merge_seed_carries_trailer_override(self):
        mutator = RequestSmugglingMutator(seed=15, mode="stable", havoc_intensity=0.0)
        inp = Input(data=b"x", metadata={"variant_family": "trailer_merge"})
        out = mutator.mutate(inp, [])
        assert out.metadata["variant_family"] == "trailer_merge"
        assert b"Trailer: X-Original-URL, X-Trailer-Canary" in out.data
        assert b"X-Original-URL: /front-cache/base" in out.data
        assert b"X-Original-URL: /trailer-cache/" in out.data

    def test_generates_pause_probe_metadata(self):
        mutator = RequestSmugglingMutator(seed=9, mode="stable")
        inp = Input(data=b"x", metadata={"variant_family": "pause_prefix"})
        out = mutator.mutate(inp, [])
        assert out.metadata["delivery_mode"] == "pause_probe_h1"
        assert out.metadata["probe_mode"] == "pause_prefix"
        assert out.metadata["pause_ms"] > 0

    def test_generates_halfclose_probe_metadata(self):
        mutator = RequestSmugglingMutator(seed=11, mode="stable")
        inp = Input(data=b"x", metadata={"variant_family": "halfclose"})
        out = mutator.mutate(inp, [])
        assert out.metadata["delivery_mode"] == "halfclose_probe_h1"
        assert out.metadata["probe_mode"] == "halfclose"

    def test_research_mode_emits_axis_first_metadata(self):
        mutator = RequestSmugglingMutator(seed=23, mode="research")
        out = mutator.mutate(Input(data=b"seed"), [])
        assert out.metadata["request_smuggling_mode"] == "research"
        assert out.metadata["axis_framing"] in {"CL", "TE", "0", "H2"}
        assert out.metadata["axis_leniency"]
        assert out.metadata["axis_chunk"]
        assert out.metadata["axis_connection"]
        assert out.metadata["axis_timing"]
        assert out.metadata["axis_routing"]
        assert out.metadata["stream_shape"]
        assert b"X-WF-Mode: research" in out.data

    def test_hybrid_mode_keeps_variant_family_summary(self):
        mutator = RequestSmugglingMutator(seed=29, mode="hybrid")
        out = mutator.mutate(Input(data=b"seed"), [])
        assert out.metadata["variant_family"]

    # ------------------------------------------------------------------
    # Phase 3: corpus-aware mutation, wire havoc, fragment parsing
    # ------------------------------------------------------------------

    def test_empty_corpus_no_crash(self):
        """mutate() works fine with an empty corpus list."""
        mutator = RequestSmugglingMutator(seed=42, mode="stable")
        out = mutator.mutate(Input(data=b"seed"), [])
        assert b"X-WF-Request-ID:" in out.data
        assert b"/__canary__/" in out.data

    def test_corpus_fragment_extraction(self):
        """_parse_wire_fragment extracts family, headers, body, trailers."""
        # Build a known wire via the mutator.
        mutator = RequestSmugglingMutator(seed=99, mode="stable")
        inp = Input(data=b"x", metadata={"variant_family": "trailer_merge"})
        out = mutator.mutate(inp, [])

        frag = _parse_wire_fragment(out.data)
        assert frag is not None
        assert frag.family == "trailer_merge"
        assert frag.delimiter in (b"\r\n", b"\n")
        # Should have extracted at least one content header (e.g., Transfer-Encoding).
        assert len(frag.headers) > 0
        # Trailer merge family produces trailers.
        assert any(b"X-Original-URL" in t or b"X-Trailer-Canary" in t for t in frag.trailers)

    def test_fragment_parse_returns_none_for_garbage(self):
        assert _parse_wire_fragment(b"not http at all") is None
        assert _parse_wire_fragment(b"") is None

    def test_corpus_aware_mutate_uses_seeds(self):
        """When corpus seeds are provided, mutate() does not crash and
        still produces valid wire with control headers."""
        mutator = RequestSmugglingMutator(seed=7, mode="stable")
        # Generate a few corpus seeds.
        corpus = []
        for i in range(5):
            m = RequestSmugglingMutator(seed=i, mode="stable")
            wire = m.mutate(Input(data=b"x"), [])
            corpus.append(_StubSeed(input=wire, feature_set={f"edge_{i}"}))

        out = mutator.mutate(Input(data=b"seed"), corpus)
        assert b"X-WF-Request-ID:" in out.data
        assert b"/__canary__/" in out.data

    def test_wire_havoc_preserves_control_headers(self):
        """Even at maximum intensity, X-WF-Request-ID must survive."""
        mutator = RequestSmugglingMutator(seed=50, mode="stable", havoc_intensity=1.0)
        inp = Input(data=b"x", metadata={"variant_family": "cl_te"})
        for _ in range(20):
            out = mutator.mutate(inp, [])
            assert b"X-WF-Request-ID:" in out.data

    def test_wire_havoc_preserves_canary(self):
        """The canary request block must survive havoc."""
        mutator = RequestSmugglingMutator(seed=51, mode="stable", havoc_intensity=1.0)
        inp = Input(data=b"x", metadata={"variant_family": "te_cl"})
        for _ in range(20):
            out = mutator.mutate(inp, [])
            assert b"/__canary__/" in out.data

    def test_havoc_disabled_when_intensity_zero(self):
        """With havoc_intensity=0, output should be identical to template."""
        m1 = RequestSmugglingMutator(seed=70, mode="stable", havoc_intensity=0.0)
        m2 = RequestSmugglingMutator(seed=70, mode="stable", havoc_intensity=0.0)
        inp = Input(data=b"x", metadata={"variant_family": "cl_te"})
        out1 = m1.mutate(inp, [])
        out2 = m2.mutate(inp, [])
        assert out1.data == out2.data

    def test_family_feedback_biases_selection(self):
        """After boosting a family's hit count, it should be selected more often."""
        mutator = RequestSmugglingMutator(seed=33, mode="stable", havoc_intensity=0.0)
        # Heavily bias toward chunk_bare_lf.
        mutator._family_hits["chunk_bare_lf"] = 1000
        counts = {"chunk_bare_lf": 0, "other": 0}
        for _ in range(200):
            out = mutator.mutate(Input(data=b"seed"), [])
            if out.metadata["variant_family"] == "chunk_bare_lf":
                counts["chunk_bare_lf"] += 1
            else:
                counts["other"] += 1
        # Should be selected significantly more than uniform baseline (~1/26).
        assert counts["chunk_bare_lf"] > 30, f"Expected bias but got {counts}"

    def test_hrs_deep_preset_exists(self):
        from webfuzzer.app.campaigns import CAMPAIGN_PRESETS
        assert "hrs_deep" in CAMPAIGN_PRESETS
        preset = CAMPAIGN_PRESETS["hrs_deep"]
        assert preset["campaign_mode"] == "hrs_deep"
        assert preset["adaptive_coverage"] is True
        assert preset["adaptive_level"] == 2

    def test_havoc_intensity_mapping(self):
        from webfuzzer.app.factories.mutators import _hrs_havoc_intensity
        assert _hrs_havoc_intensity("hrs_stable") == 0.10
        assert _hrs_havoc_intensity("hrs_research") == 0.15
        assert _hrs_havoc_intensity("hrs_hybrid") == 0.15
        assert _hrs_havoc_intensity("hrs_deep") == 0.25
        assert _hrs_havoc_intensity("novel") == 0.0
