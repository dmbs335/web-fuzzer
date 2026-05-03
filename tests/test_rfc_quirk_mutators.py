"""Unit tests for the rfc_spec_quirks mutation lane (WAF Bypass v5.0)."""

from __future__ import annotations

from collections import Counter

import pytest

from webfuzzer.fuzzer.mutators.waf_bypass_mutator import (
    WafBypassMutator,
    _LANES,
    _TAG_MAP,
    _AXIS_MAP,
    _STABLE_LANE_WEIGHTS,
)
from webfuzzer.fuzzer.protocols import Input

_RFC_FAMILIES = [
    "rfc_vt_ff_separator",
    "rfc_absolute_target",
    "rfc_trailer_inject",
    "rfc_param_continuation",
    "rfc_obs_text_header",
    "rfc_method_case",
    "rfc_host_case",
]

_SEED = Input(data=b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n")


class TestRfcSpecQuirksLane:
    def test_lane_exists_with_7_families(self):
        assert "rfc_spec_quirks" in _LANES
        assert list(_LANES["rfc_spec_quirks"]) == _RFC_FAMILIES

    def test_all_families_in_tag_map(self):
        for fam in _RFC_FAMILIES:
            assert fam in _TAG_MAP, f"{fam} missing from _TAG_MAP"

    def test_all_families_in_axis_map(self):
        for fam in _RFC_FAMILIES:
            assert fam in _AXIS_MAP, f"{fam} missing from _AXIS_MAP"
            assert len(_AXIS_MAP[fam]) == 5, f"{fam} axis tuple must have 5 elements"

    def test_lane_weight_present_and_sums_to_one(self):
        assert "rfc_spec_quirks" in _STABLE_LANE_WEIGHTS
        total = sum(_STABLE_LANE_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9, f"weights sum to {total}, expected 1.0"

    def test_rfc_axis_evasion_technique(self):
        """All rfc families use 'rfc_spec' as evasion technique axis."""
        for fam in _RFC_FAMILIES:
            assert _AXIS_MAP[fam][0] == "rfc_spec", (
                f"{fam} evasion axis should be 'rfc_spec', got {_AXIS_MAP[fam][0]}"
            )

    def test_all_rfc_families_observable_in_smoke(self):
        """All 7 RFC families appear in a 10 000-input smoke run."""
        m = WafBypassMutator(seed=7, mode="hybrid")
        observed: Counter[str] = Counter()
        for _ in range(10_000):
            out = m.mutate(_SEED, corpus=[])
            observed[out.metadata.get("variant_family", "?")] += 1
        missing = [f for f in _RFC_FAMILIES if observed.get(f, 0) == 0]
        assert not missing, f"Missing RFC families after 10k inputs: {missing}"


class TestRfcBuilderWireFormat:
    """Wire-level assertions for individual RFC builder outputs.

    Uses the private builder methods directly to avoid surface transforms
    (applied by mutate()) corrupting the structural markers we're asserting on.
    """

    _BASE_HEADERS = [
        "Host: target.local",
        "User-Agent: wf-wafbypass/1.0",
        "Accept: */*",
    ]
    _KWARGS = dict(
        payload="<script>alert(1)</script>",
        canary="CANARY123",
        request_id="req001",
        base_headers=_BASE_HEADERS,
    )

    def _build(self, family: str, seed: int = 42) -> bytes:
        m = WafBypassMutator(seed=seed, mode="hybrid")
        builder = getattr(m, f"_build_{family}", None)
        assert builder is not None, f"No builder for {family}"
        return builder(**self._KWARGS)

    def test_rfc_trailer_inject_has_final_chunk_and_trailer(self):
        wire = self._build("rfc_trailer_inject")
        assert b"0\r\n" in wire, "final chunk (0\\r\\n) missing"
        assert b"X-Custom-Input:" in wire, "trailer header missing"
        # Chain transformers may insert control bytes into the Trailer value;
        # check for the header name prefix rather than exact match.
        assert b"Trailer:" in wire, "Trailer declaration missing"

    def test_rfc_param_continuation_uses_star_syntax(self):
        wire = self._build("rfc_param_continuation")
        assert b"boundary*0=" in wire, "RFC 2231 boundary*0= not found"
        assert b"boundary*1=" in wire, "RFC 2231 boundary*1= not found"

    def test_rfc_absolute_target_request_line(self):
        wire = self._build("rfc_absolute_target")
        first_line = wire.split(b"\r\n")[0]
        assert b"http://" in first_line, (
            f"request-line should contain absolute-form URI: {first_line!r}"
        )

    def test_rfc_absolute_target_host_mismatch(self):
        wire = self._build("rfc_absolute_target")
        # Chain transformers may insert control bytes inside the host value;
        # check that "mismatch" appears in the wire rather than exact match.
        assert b"mismatch" in wire, (
            "Host header should contain 'mismatch' for absolute-form bypass"
        )

    def test_rfc_vt_ff_separator_has_control_byte(self):
        wire = self._build("rfc_vt_ff_separator")
        # VT (0x0B) or FF (0x0C) must appear in the headers section
        header_section = wire.split(b"\r\n\r\n")[0]
        assert b"\x0b" in header_section or b"\x0c" in header_section, (
            "VT or FF byte not found in headers section"
        )

    def test_rfc_method_case_not_uppercase(self):
        # Must eventually produce a non-standard-case method
        m = WafBypassMutator(seed=13, mode="hybrid")
        found_mixed = False
        for _ in range(20_000):
            out = m.mutate(_SEED, corpus=[])
            if out.metadata.get("variant_family") == "rfc_method_case":
                first_line = out.data.split(b"\r\n")[0].decode("latin-1", errors="replace")
                method = first_line.split(" ")[0]
                if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
                    found_mixed = True
                    break
        assert found_mixed, "rfc_method_case never produced a non-standard-case method"

    def test_rfc_host_case_has_uppercase_host(self):
        wire = self._build("rfc_host_case")
        # Host header value should NOT be all lowercase "target.local"
        host_line = next(
            (line for line in wire.split(b"\r\n") if line.lower().startswith(b"host:")),
            None,
        )
        assert host_line is not None, "Host header not found"
        host_value = host_line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
        assert host_value != "target.local", (
            f"host should be case-varied, got: {host_value!r}"
        )

    def test_rfc_obs_text_header_has_high_bytes(self):
        wire = self._build("rfc_obs_text_header")
        header_section = wire.split(b"\r\n\r\n")[0]
        # At least one byte in 0x80-0xFF range in headers
        assert any(b > 0x7F for b in header_section), (
            "obs-text (0x80-0xFF) not found in headers"
        )


# ── H2 composed & grammar builder tests ─────────────────────────────

class TestH2ComposedAndGrammar:
    """Wire-level assertions for h2_composed and h2_grammar families."""

    def test_h2_composed_in_lane(self):
        assert "h2_composed" in _LANES["h2_downgrade"]

    def test_h2_grammar_in_lane(self):
        assert "h2_grammar" in _LANES["h2_downgrade"]

    def test_h2_composed_in_tag_and_axis_maps(self):
        assert "h2_composed" in _TAG_MAP
        assert "h2_composed" in _AXIS_MAP
        assert len(_AXIS_MAP["h2_composed"]) == 5

    def test_h2_grammar_in_tag_and_axis_maps(self):
        assert "h2_grammar" in _TAG_MAP
        assert "h2_grammar" in _AXIS_MAP
        assert len(_AXIS_MAP["h2_grammar"]) == 5

    def test_h2_composed_produces_h2_wire(self):
        from webfuzzer.fuzzer.mutators.h2_frames import H2_CLIENT_PREFACE
        m = WafBypassMutator(seed=42, mode="hybrid")
        wire = m._build_h2_composed(
            payload="<script>alert(1)</script>", canary="CANARY123",
            request_id="req001", base_headers=["Host: target.local"],
        )
        assert wire.startswith(H2_CLIENT_PREFACE)
        assert len(wire) > 50

    def test_h2_grammar_produces_h2_wire_fallback(self):
        from webfuzzer.fuzzer.mutators.h2_frames import H2_CLIENT_PREFACE
        m = WafBypassMutator(seed=42, mode="hybrid")  # no registry
        wire = m._build_h2_grammar(
            payload="test", canary="C123",
            request_id="r1", base_headers=[],
        )
        assert wire.startswith(H2_CLIENT_PREFACE)

    def test_h2_grammar_with_registry(self):
        from webfuzzer.core.registry import GrammarRegistry
        from webfuzzer.fuzzer.mutators.h2_frames import H2_CLIENT_PREFACE
        reg = GrammarRegistry()
        reg.load_builtins()
        m = WafBypassMutator(seed=42, mode="hybrid", registry=reg)
        wire = m._build_h2_grammar(
            payload="' OR 1=1--", canary="C456",
            request_id="r2", base_headers=[],
        )
        assert wire.startswith(H2_CLIENT_PREFACE)
        assert len(wire) > 50

    def test_h2_composed_observable_in_smoke(self):
        m = WafBypassMutator(seed=99, mode="hybrid")
        found = False
        for _ in range(15_000):
            out = m.mutate(_SEED, corpus=[])
            if out.metadata.get("variant_family") == "h2_composed":
                found = True
                break
        assert found, "h2_composed never appeared in 15k iterations"

    def test_pick_h2_muts_exclusion(self):
        from webfuzzer.fuzzer.mutators.waf_bypass_mutator import _pick_h2_muts
        import random
        rng = random.Random(42)
        for _ in range(1000):
            muts = _pick_h2_muts(rng, 4)
            assert len(set(muts) & {"dup_method", "dup_path", "dup_authority"}) <= 1
            assert len(set(muts) & {"te_forbidden", "cl_zero"}) <= 1
            assert len(set(muts) & {"path_inject", "header_inject_crlf"}) <= 1
