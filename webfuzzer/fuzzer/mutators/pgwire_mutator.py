"""PostgreSQL wire-protocol transcript mutator.

The mutator emits ASCII transcript artifacts that the pgwire target harness
turns into real PostgreSQL v3 wire messages. This keeps per-input control
metadata close to the payload while staying easy to diff and replay.
"""

from __future__ import annotations

import json
import random
import string
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ...core.registry import GrammarRegistry
    from ..corpus import Seed


_LANES: dict[str, tuple[str, ...]] = {
    "handshake": (
        "ssl_probe",
        "gss_probe",
        "cancel_probe",
        "gss_then_query",
        "ssl_then_query",
        "gss_then_extended",
        "ssl_then_extended",
        "cancel_then_startup",
        "duplicate_startup_after_probe",
        "probe_then_sync",
        "gss_then_extended_split",
        "gss_then_extended_pause",
        "gss_then_duplicate_startup",
        "gss_then_extended_len_plus_4",
        "gss_then_extended_extra_sync",
    ),
    "startup": (
        "startup_plain",
        "startup_dup_user",
        "startup_dup_db",
        "startup_unknown_param",
        "startup_len_minus_1",
        "startup_len_plus_4",
    ),
    "simple_query": (
        "simple_query_baseline",
        "simple_query_stacked",
        "simple_query_split",
    ),
    "extended_query": (
        "extended_query_basic",
        "extended_query_sync_after_error",
    ),
    "smuggle": (
        "smuggle_query_undercount",
        "smuggle_query_append",
        "smuggle_parse_undercount",
        "smuggle_bind_oversized",
        "smuggle_pipeline_desync",
        "smuggle_ext_parse_undercount",
        "smuggle_ext_bind_swallow",
        "smuggle_ext_sync_inject",
        "smuggle_ext_execute_wrong_portal",
        "smuggle_ext_close_wrong_stmt",
    ),
}

_ALL_FAMILIES = tuple(family for families in _LANES.values() for family in families)

_MODE_WEIGHTS = {
    "stable": (1.0, 0.0),
    "research": (0.0, 1.0),
    "hybrid": (0.45, 0.55),
    "smuggle": (0.0, 1.0),
}

_SMUGGLE_CANARIES = (
    "SELECT 1337 AS wf_smuggled",
    "SET application_name TO 'smuggled'",
    "SELECT current_user",
    "SELECT pg_backend_pid()",
    "RESET ALL",
)

_RESEARCH_WEIGHTS = {
    "framing_mode": {
        "valid": 0.52,
        "len_minus_1": 0.18,
        "len_plus_4": 0.16,
        "trailing_bytes": 0.14,
    },
    "state_mode": {
        "handshake_probe": 0.12,
        "probe_then_startup": 0.12,
        "probe_then_extended": 0.10,
        "cancel_then_startup": 0.08,
        "duplicate_startup_after_probe": 0.08,
        "probe_then_sync": 0.08,
        "simple_query": 0.44,
        "extended_query": 0.26,
        "sync_after_error": 0.18,
    },
    "delivery_mode": {
        "single": 0.60,
        "split_header": 0.24,
        "pause_midframe": 0.16,
    },
    "query_mode": {
        "baseline": 0.36,
        "stacked": 0.28,
        "unterminated": 0.16,
        "named_statement": 0.20,
    },
    "startup_mode": {
        "plain": 0.66,
        "dup_user": 0.19,
        "missing_db": 0.15,
    },
    "handshake_mode": {
        "ssl": 0.45,
        "gss": 0.25,
        "cancel": 0.30,
    },
    "startup_shape": {
        "plain": 0.58,
        "dup_user": 0.14,
        "dup_db": 0.12,
        "unknown_param": 0.16,
    },
    "smuggle_mode": {
        "none": 0.30,
        "query_undercount": 0.10,
        "query_append": 0.06,
        "parse_undercount": 0.06,
        "bind_oversized": 0.05,
        "pipeline_desync": 0.05,
        "ext_parse_undercount": 0.10,
        "ext_bind_swallow": 0.08,
        "ext_sync_inject": 0.08,
        "ext_execute_wrong_portal": 0.06,
        "ext_close_wrong_stmt": 0.06,
    },
}


def _rand_id(rng: random.Random) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(10))


def _pick_weighted(rng: random.Random, weighted: dict[str, float]) -> str:
    names = tuple(weighted)
    weights = tuple(weighted[name] for name in names)
    return rng.choices(names, weights=weights, k=1)[0]


@dataclass(frozen=True)
class PgwireSpec:
    framing_mode: str
    state_mode: str
    delivery_mode: str
    query_mode: str
    startup_mode: str
    handshake_mode: str
    startup_shape: str
    smuggle_mode: str


class PgwireMutator:
    """Template-first mutator for PostgreSQL wire transcripts."""

    name = "pgwire"

    def __init__(
        self,
        seed: int | None = None,
        registry: "GrammarRegistry | None" = None,
        grammar_name: str = "pgsql_wire_session",
        mode: str = "hybrid",
    ) -> None:
        del registry, grammar_name
        self.rng = random.Random(seed)
        self.mode = mode if mode in _MODE_WEIGHTS else "hybrid"

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        del corpus
        lane_mode = self._pick_lane_mode(inp)
        if lane_mode == "stable":
            transcript, meta, lane = self._mutate_stable(inp)
        else:
            transcript, meta, lane = self._mutate_research(inp)
        return Input(
            data=transcript,
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "lane": lane,
                **meta,
            },
        )

    def _pick_lane_mode(self, inp: Input) -> str:
        hinted_mode = str(inp.metadata.get("pgwire_mode") or "").strip().lower()
        if hinted_mode in {"stable", "research"}:
            return hinted_mode
        stable_weight, research_weight = _MODE_WEIGHTS[self.mode]
        return self.rng.choices(
            ("stable", "research"),
            weights=(stable_weight, research_weight),
            k=1,
        )[0]

    def _pick_family(self, inp: Input) -> str:
        hinted = str(inp.metadata.get("variant_family") or "").strip()
        if hinted in _ALL_FAMILIES:
            return hinted
        lane = self.rng.choice(tuple(_LANES))
        return self.rng.choice(_LANES[lane])

    def _mutate_stable(self, inp: Input) -> tuple[bytes, dict[str, object], str]:
        family = self._pick_family(inp)
        lane = self._lane_for_family(family)
        request_id = _rand_id(self.rng)
        meta = self._family_metadata(family, request_id=request_id, mode="stable")
        actions = self._family_actions(family)
        return self._render_transcript(meta, actions), meta, lane

    def _mutate_research(self, inp: Input) -> tuple[bytes, dict[str, object], str]:
        smuggle_weights = _RESEARCH_WEIGHTS["smuggle_mode"]
        if self.mode == "smuggle":
            # In smuggle mode, never pick "none" — always smuggle.
            smuggle_weights = {k: v for k, v in smuggle_weights.items() if k != "none"}
        spec = PgwireSpec(
            framing_mode=_pick_weighted(self.rng, _RESEARCH_WEIGHTS["framing_mode"]),
            state_mode=_pick_weighted(self.rng, _RESEARCH_WEIGHTS["state_mode"]),
            delivery_mode=_pick_weighted(self.rng, _RESEARCH_WEIGHTS["delivery_mode"]),
            query_mode=_pick_weighted(self.rng, _RESEARCH_WEIGHTS["query_mode"]),
            startup_mode=_pick_weighted(self.rng, _RESEARCH_WEIGHTS["startup_mode"]),
            handshake_mode=_pick_weighted(self.rng, _RESEARCH_WEIGHTS["handshake_mode"]),
            startup_shape=_pick_weighted(self.rng, _RESEARCH_WEIGHTS["startup_shape"]),
            smuggle_mode=_pick_weighted(self.rng, smuggle_weights),
        )
        request_id = _rand_id(self.rng)
        family = self._derive_family(spec)
        meta = self._spec_metadata(spec, family=family, request_id=request_id)
        actions = self._spec_actions(spec)
        return self._render_transcript(meta, actions), meta, "research"

    def _lane_for_family(self, family: str) -> str:
        for lane, families in _LANES.items():
            if family in families:
                return lane
        return "unknown"

    def _family_metadata(
        self,
        family: str,
        *,
        request_id: str,
        mode: str,
    ) -> dict[str, object]:
        meta: dict[str, object] = {
            "request_id": request_id,
            "variant_family": family,
            "transport_mode": "pgsql_v3",
            "pgwire_mode": mode,
            "delivery_mode": "single",
            "probe_mode": "none",
            "pause_ms": 0,
            "split_offset": 5,
            "frame_corruption": "none",
            "startup_mode": "plain",
            "handshake_mode": "none",
            "axis_framing": "valid",
            "axis_state": "simple_query",
            "axis_delivery": "single",
            "axis_query": "baseline",
            "axis_startup": "plain",
        }
        if family == "ssl_probe":
            meta["probe_mode"] = "ssl_request"
            meta["handshake_mode"] = "ssl"
            meta["axis_state"] = "handshake_probe"
            meta["axis_query"] = "none"
        elif family == "gss_probe":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "handshake_probe"
            meta["axis_query"] = "none"
        elif family == "cancel_probe":
            meta["probe_mode"] = "cancel_request"
            meta["handshake_mode"] = "cancel"
            meta["axis_state"] = "handshake_probe"
            meta["axis_query"] = "none"
        elif family == "gss_then_query":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "probe_then_startup"
        elif family == "ssl_then_query":
            meta["probe_mode"] = "ssl_request"
            meta["handshake_mode"] = "ssl"
            meta["axis_state"] = "probe_then_startup"
        elif family == "gss_then_extended":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "probe_then_extended"
            meta["axis_query"] = "named_statement"
        elif family == "gss_then_extended_split":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "probe_then_extended"
            meta["axis_query"] = "named_statement"
            meta["delivery_mode"] = "split_header"
            meta["axis_delivery"] = "split_header"
        elif family == "gss_then_extended_pause":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "probe_then_extended"
            meta["axis_query"] = "named_statement"
            meta["delivery_mode"] = "pause_midframe"
            meta["axis_delivery"] = "pause_midframe"
            meta["pause_ms"] = 18
        elif family == "gss_then_duplicate_startup":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "duplicate_startup_after_probe"
            meta["axis_query"] = "named_statement"
            meta["startup_mode"] = "dup_user"
            meta["axis_startup"] = "dup_user"
        elif family == "gss_then_extended_len_plus_4":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "probe_then_extended"
            meta["axis_query"] = "named_statement"
            meta["frame_corruption"] = "query_len_plus_4"
            meta["axis_framing"] = "len_plus_4"
        elif family == "gss_then_extended_extra_sync":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "probe_then_extended"
            meta["axis_query"] = "named_statement"
        elif family == "ssl_then_extended":
            meta["probe_mode"] = "ssl_request"
            meta["handshake_mode"] = "ssl"
            meta["axis_state"] = "probe_then_extended"
            meta["axis_query"] = "named_statement"
        elif family == "cancel_then_startup":
            meta["probe_mode"] = "cancel_request"
            meta["handshake_mode"] = "cancel"
            meta["axis_state"] = "cancel_then_startup"
        elif family == "duplicate_startup_after_probe":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "duplicate_startup_after_probe"
            meta["startup_mode"] = "dup_user"
            meta["axis_startup"] = "dup_user"
        elif family == "probe_then_sync":
            meta["probe_mode"] = "gssenc_request"
            meta["handshake_mode"] = "gss"
            meta["axis_state"] = "probe_then_sync"
            meta["axis_query"] = "sync_only"
        elif family == "startup_dup_user":
            meta["startup_mode"] = "dup_user"
            meta["axis_startup"] = "dup_user"
        elif family == "startup_dup_db":
            meta["startup_mode"] = "dup_db"
            meta["axis_startup"] = "dup_db"
        elif family == "startup_unknown_param":
            meta["startup_mode"] = "unknown_param"
            meta["axis_startup"] = "unknown_param"
        elif family == "startup_len_minus_1":
            meta["frame_corruption"] = "startup_len_minus_1"
            meta["axis_framing"] = "len_minus_1"
        elif family == "startup_len_plus_4":
            meta["frame_corruption"] = "startup_len_plus_4"
            meta["axis_framing"] = "len_plus_4"
        elif family == "simple_query_stacked":
            meta["axis_query"] = "stacked"
        elif family == "simple_query_split":
            meta["delivery_mode"] = "split_header"
            meta["axis_delivery"] = "split_header"
        elif family == "extended_query_basic":
            meta["axis_state"] = "extended_query"
            meta["axis_query"] = "named_statement"
        elif family == "extended_query_sync_after_error":
            meta["axis_state"] = "sync_after_error"
            meta["probe_mode"] = "sync_after_error"
            meta["axis_query"] = "unterminated"
        elif family.startswith("smuggle_"):
            smuggle_variant = family[len("smuggle_"):]
            meta["smuggle_mode"] = smuggle_variant
            meta["smuggle_sql"] = self.rng.choice(_SMUGGLE_CANARIES)
            meta["smuggle_target_index"] = -1
            meta["frame_corruption"] = f"smuggle_{smuggle_variant}"
            meta["axis_framing"] = f"smuggle_{smuggle_variant}"
            if smuggle_variant in {
                "parse_undercount", "bind_oversized",
                "ext_parse_undercount", "ext_bind_swallow",
                "ext_sync_inject", "ext_execute_wrong_portal",
                "ext_close_wrong_stmt",
            }:
                meta["axis_state"] = "extended_query"
                meta["axis_query"] = "named_statement"
            else:
                meta["axis_state"] = "simple_query"
        return meta

    def _spec_metadata(
        self,
        spec: PgwireSpec,
        *,
        family: str,
        request_id: str,
    ) -> dict[str, object]:
        frame_corruption = {
            "valid": "none",
            "len_minus_1": "query_len_minus_1",
            "len_plus_4": "query_len_plus_4",
            "trailing_bytes": "query_trailing_bytes",
        }[spec.framing_mode]
        probe_mode = "sync_after_error" if spec.state_mode == "sync_after_error" else "none"
        pause_ms = 18 if spec.delivery_mode == "pause_midframe" else 0
        meta: dict[str, object] = {
            "request_id": request_id,
            "variant_family": family,
            "transport_mode": "pgsql_v3",
            "pgwire_mode": "research",
            "delivery_mode": spec.delivery_mode,
            "probe_mode": probe_mode,
            "pause_ms": pause_ms,
            "split_offset": 5,
            "frame_corruption": frame_corruption,
            "startup_mode": spec.startup_mode,
            "handshake_mode": (
                spec.handshake_mode
                if spec.state_mode in {
                    "handshake_probe",
                    "probe_then_startup",
                    "probe_then_extended",
                    "cancel_then_startup",
                    "duplicate_startup_after_probe",
                    "probe_then_sync",
                }
                else "none"
            ),
            "axis_framing": spec.framing_mode,
            "axis_state": spec.state_mode,
            "axis_delivery": spec.delivery_mode,
            "axis_query": "none" if spec.state_mode == "handshake_probe" else spec.query_mode,
            "axis_startup": spec.startup_shape,
            "smuggle_mode": spec.smuggle_mode,
        }
        if spec.smuggle_mode != "none":
            meta["smuggle_sql"] = self.rng.choice(_SMUGGLE_CANARIES)
            meta["smuggle_target_index"] = -1
            # Override frame_corruption for smuggling — smuggle controls framing.
            meta["frame_corruption"] = f"smuggle_{spec.smuggle_mode}"
        return meta

    def _derive_family(self, spec: PgwireSpec) -> str:
        if spec.smuggle_mode != "none":
            return f"smuggle_{spec.smuggle_mode}"
        if spec.state_mode == "handshake_probe":
            return {
                "ssl": "ssl_probe",
                "gss": "gss_probe",
                "cancel": "cancel_probe",
            }[spec.handshake_mode]
        if spec.state_mode == "probe_then_startup":
            return {
                "ssl": "ssl_then_query",
                "gss": "gss_then_query",
                "cancel": "gss_then_query",
            }[spec.handshake_mode]
        if spec.state_mode == "probe_then_extended":
            return {
                "ssl": "ssl_then_extended",
                "gss": "gss_then_extended",
                "cancel": "gss_then_extended",
            }[spec.handshake_mode]
        if spec.state_mode == "cancel_then_startup":
            return "cancel_then_startup"
        if spec.state_mode == "duplicate_startup_after_probe":
            return "duplicate_startup_after_probe"
        if spec.state_mode == "probe_then_sync":
            return "probe_then_sync"
        if spec.state_mode == "extended_query":
            return "extended_query_basic"
        if spec.state_mode == "sync_after_error":
            return "extended_query_sync_after_error"
        if spec.startup_shape == "dup_user":
            return "startup_dup_user"
        if spec.startup_shape == "dup_db":
            return "startup_dup_db"
        if spec.startup_shape == "unknown_param":
            return "startup_unknown_param"
        if spec.framing_mode == "len_minus_1":
            return "startup_len_minus_1"
        if spec.framing_mode == "len_plus_4":
            return "startup_len_plus_4"
        if spec.query_mode == "stacked":
            return "simple_query_stacked"
        if spec.delivery_mode == "split_header":
            return "simple_query_split"
        return "simple_query_baseline"

    def _family_actions(self, family: str) -> list[dict[str, object]]:
        if family == "ssl_probe":
            return [{"op": "ssl_request"}]
        if family == "gss_probe":
            return [{"op": "gssenc_request"}]
        if family == "cancel_probe":
            return [{"op": "cancel_request", "backend_pid": 1234, "secret_key": 5678}]
        if family == "gss_then_query":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family == "ssl_then_query":
            return [
                {"op": "ssl_request"},
                self._startup_action(),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family == "gss_then_extended":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "gss_then_extended_split":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "gss_then_extended_pause":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "gss_then_duplicate_startup":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                self._startup_action(startup_mode="dup_user"),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "gss_then_extended_len_plus_4":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "gss_then_extended_extra_sync":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "ssl_then_extended":
            return [
                {"op": "ssl_request"},
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "cancel_then_startup":
            return [
                {"op": "cancel_request", "backend_pid": 1234, "secret_key": 5678},
                self._startup_action(),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family == "duplicate_startup_after_probe":
            return [
                {"op": "gssenc_request"},
                self._startup_action(startup_mode="dup_user"),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family == "probe_then_sync":
            return [
                {"op": "gssenc_request"},
                self._startup_action(),
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "startup_dup_user":
            return [
                self._startup_action(startup_mode="dup_user"),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family == "startup_dup_db":
            return [
                self._startup_action(startup_mode="dup_db"),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family == "startup_unknown_param":
            return [
                self._startup_action(startup_mode="unknown_param"),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family.startswith("startup_"):
            return self._baseline_actions()
        if family == "simple_query_stacked":
            return [
                self._startup_action(),
                {
                    "op": "query",
                    "sql": "select 1;select 2 as wf_canary",
                },
                {"op": "terminate"},
            ]
        if family == "extended_query_basic":
            return [
                self._startup_action(),
                {
                    "op": "parse",
                    "statement": "wf_stmt",
                    "sql": "select 1",
                },
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "extended_query_sync_after_error":
            return [
                self._startup_action(),
                {
                    "op": "parse",
                    "statement": "wf_bad",
                    "sql": "select (",
                },
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family in {"smuggle_query_undercount", "smuggle_query_append"}:
            return [
                self._startup_action(),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if family == "smuggle_parse_undercount":
            return [
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "smuggle_bind_oversized":
            return [
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select $1::text"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "smuggle_pipeline_desync":
            return [
                self._startup_action(),
                {"op": "query", "sql": "select 1"},
                {"op": "query", "sql": "select 2"},
                {"op": "terminate"},
            ]
        if family == "smuggle_ext_parse_undercount":
            return [
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "smuggle_ext_bind_swallow":
            return [
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "smuggle_ext_sync_inject":
            return [
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "smuggle_ext_execute_wrong_portal":
            return [
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": "wf_portal"},
                {"op": "execute", "portal": "wf_nonexistent", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if family == "smuggle_ext_close_wrong_stmt":
            return [
                self._startup_action(),
                {"op": "parse", "statement": "wf_stmt", "sql": "select 1"},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "close", "kind": "S", "name": "wf_nonexistent"},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        return self._baseline_actions()

    def _spec_actions(self, spec: PgwireSpec) -> list[dict[str, object]]:
        if spec.smuggle_mode != "none":
            return self._family_actions(f"smuggle_{spec.smuggle_mode}")
        if spec.state_mode == "handshake_probe":
            if spec.handshake_mode == "ssl":
                return [{"op": "ssl_request"}]
            if spec.handshake_mode == "gss":
                return [{"op": "gssenc_request"}]
            return [{"op": "cancel_request", "backend_pid": 1234, "secret_key": 5678}]
        if spec.state_mode == "probe_then_startup":
            startup = self._startup_action(startup_mode=spec.startup_shape)
            probe = (
                {"op": "ssl_request"}
                if spec.handshake_mode == "ssl"
                else {"op": "gssenc_request"}
            )
            return [
                probe,
                startup,
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if spec.state_mode == "probe_then_extended":
            startup = self._startup_action(startup_mode=spec.startup_shape)
            probe = (
                {"op": "ssl_request"}
                if spec.handshake_mode == "ssl"
                else {"op": "gssenc_request"}
            )
            sql = "select 1" if spec.query_mode != "unterminated" else "select ("
            return [
                probe,
                startup,
                {"op": "parse", "statement": "wf_stmt", "sql": sql},
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if spec.state_mode == "cancel_then_startup":
            return [
                {"op": "cancel_request", "backend_pid": 1234, "secret_key": 5678},
                self._startup_action(startup_mode=spec.startup_shape),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if spec.state_mode == "duplicate_startup_after_probe":
            probe = (
                {"op": "ssl_request"}
                if spec.handshake_mode == "ssl"
                else {"op": "gssenc_request"}
            )
            return [
                probe,
                self._startup_action(startup_mode="dup_user"),
                {"op": "query", "sql": "select 1"},
                {"op": "terminate"},
            ]
        if spec.state_mode == "probe_then_sync":
            probe = (
                {"op": "ssl_request"}
                if spec.handshake_mode == "ssl"
                else {"op": "gssenc_request"}
            )
            return [
                probe,
                self._startup_action(startup_mode=spec.startup_shape),
                {"op": "sync"},
                {"op": "terminate"},
            ]
        startup = self._startup_action(startup_mode=spec.startup_shape)
        if spec.state_mode == "extended_query":
            sql = "select 1"
            if spec.query_mode == "unterminated":
                sql = "select ("
            return [
                startup,
                {
                    "op": "parse",
                    "statement": "wf_stmt",
                    "sql": sql,
                },
                {"op": "bind", "statement": "wf_stmt", "portal": ""},
                {"op": "execute", "portal": "", "max_rows": 0},
                {"op": "sync"},
                {"op": "terminate"},
            ]
        if spec.state_mode == "sync_after_error":
            return [
                startup,
                {
                    "op": "parse",
                    "statement": "wf_bad",
                    "sql": "select (",
                },
                {"op": "sync"},
                {"op": "terminate"},
            ]
        sql = "select 1"
        if spec.query_mode == "stacked":
            sql = "select 1;select 2 as wf_canary"
        elif spec.query_mode == "unterminated":
            sql = "select 'unterminated"
        return [
            startup,
            {"op": "query", "sql": sql},
            {"op": "terminate"},
        ]

    def _startup_action(self, *, startup_mode: str = "plain") -> dict[str, object]:
        params = {
            "user": "fuzz",
            "database": "test",
            "application_name": "webfuzzer",
        }
        if startup_mode == "dup_user":
            params["user_duplicate"] = "shadow"
        elif startup_mode == "dup_db":
            params["database_duplicate"] = "shadowdb"
        elif startup_mode == "unknown_param":
            params["extra_parameters"] = {"wf_unknown": "shadow"}
        elif startup_mode == "missing_db":
            params.pop("database", None)
        return {"op": "startup", "parameters": params}

    def _baseline_actions(self) -> list[dict[str, object]]:
        return [
            self._startup_action(),
            {"op": "query", "sql": "select 1"},
            {"op": "terminate"},
        ]

    def _render_transcript(
        self,
        meta: dict[str, object],
        actions: list[dict[str, object]],
    ) -> bytes:
        lines = ["WFPG1", "M " + json.dumps(meta, separators=(",", ":"), sort_keys=True)]
        lines.extend(
            "A " + json.dumps(action, separators=(",", ":"), sort_keys=True)
            for action in actions
        )
        return ("\n".join(lines) + "\n").encode("utf-8")
