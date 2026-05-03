"""PostgreSQL driver response mutator.

Generates JSON transcripts that control an evil PG server's behavior.
The evil server sends normal or mutated responses to driver libraries
(node-postgres, psycopg2, psycopg3) to find parsing and state machine bugs.

Mutation categories:
  - length: Message length field manipulation (undercount, overcount, overflow, negative, zero)
  - type: Message type byte swapping
  - structure: Message injection, duplication, dropping, truncation
  - boundary: Near-INT32_MAX lengths to test integer overflow in drivers
  - state: Wrong message ordering, missing ReadyForQuery, duplicate auth
"""

from __future__ import annotations

import json
import random
import string
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ...core.registry import GrammarRegistry
    from ..corpus import Seed


_DRIVERS = ("node-pg", "psycopg2", "psycopg3")
_QUERY_MODES = ("simple", "extended", "error")

# Mutation families and their weights
_FAMILIES: dict[str, float] = {
    "baseline":                 0.05,  # No mutations, control group
    "length_undercount":        0.10,
    "length_overcount":         0.08,
    "overflow_length":          0.12,  # Near-INT32_MAX — the CVE-2024-27304 pattern
    "negative_length":          0.10,  # Negative (signed) length
    "zero_length":              0.05,
    "type_swap_startup":        0.05,
    "type_swap_query":          0.08,
    "inject_extra_message":     0.07,
    "truncate_message":         0.06,
    "duplicate_message":        0.04,
    "drop_readyforquery":       0.05,  # Omit ReadyForQuery — state machine test
    "drop_auth_ok":             0.03,  # Omit AuthOk — state machine test
    "extra_readyforquery":      0.03,  # Duplicate ReadyForQuery
    "append_raw_garbage":       0.04,
    "combo":                    0.05,  # Multiple mutations combined
}

# Server message types for type swapping
_SERVER_MSG_TYPES = "RSTDCE12NnZK3"

# Interesting overflow values
_OVERFLOW_VALUES = [
    0x7FFFFFFF,      # INT32_MAX
    0x80000000,      # INT32_MIN as unsigned
    0xFFFFFFFF,      # UINT32_MAX (looks like -1 as signed)
    0xFFFFFFFE,      # UINT32_MAX - 1
    0x7FFFFFFE,      # INT32_MAX - 1
    0x100000000 - 4, # Would be 0 after +4
    0x40000000,      # 1GB
    0x3FFFFFFF,      # 1GB - 1
    4,               # Minimum valid length (just the length field itself)
    3,               # Below minimum
    1,               # Way below minimum
    0,               # Zero
]


@dataclass
class PgdriverMutator:
    """Mutator that generates evil PG server response transcripts."""

    name: str = "pgdriver"
    registry: GrammarRegistry | None = None

    def mutate(self, seed: Seed, _round: int = 0) -> Input:
        family = _weighted_choice(_FAMILIES)
        driver = random.choice(_DRIVERS)
        query_mode = random.choice(_QUERY_MODES)

        transcript: dict = {
            "driver": driver,
            "query_mode": query_mode,
            "query_text": _random_query(query_mode),
            "client_timeout_ms": 3000,
            "mutations": [],
            "mutation_family": family,
        }

        if query_mode == "extended":
            transcript["query_params"] = _random_params()
            transcript["statement_name"] = f"wf_{random.randint(0, 999)}"

        if family == "baseline":
            pass  # No mutations

        elif family == "length_undercount":
            transcript["mutations"].append({
                "kind": "length_undercount",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 5),
                "delta": -random.choice([1, 2, 4, 8, 100, 1000]),
            })

        elif family == "length_overcount":
            transcript["mutations"].append({
                "kind": "length_overcount",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 5),
                "delta": random.choice([1, 2, 4, 8, 100, 1000, 65536]),
            })

        elif family == "overflow_length":
            transcript["mutations"].append({
                "kind": "overflow_length",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 5),
                "value": random.choice(_OVERFLOW_VALUES),
            })

        elif family == "negative_length":
            transcript["mutations"].append({
                "kind": "negative_length",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 5),
                "value": random.choice([
                    0x80000000, 0xFFFFFFFF, 0xFFFFFFFE,
                    0x80000001, 0xDEADBEEF,
                ]),
            })

        elif family == "zero_length":
            transcript["mutations"].append({
                "kind": "zero_length",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 5),
            })

        elif family == "type_swap_startup":
            transcript["mutations"].append({
                "kind": "type_swap",
                "phase": "startup",
                "target_index": random.randint(0, 4),
                "new_type": random.choice(_SERVER_MSG_TYPES),
            })

        elif family == "type_swap_query":
            transcript["mutations"].append({
                "kind": "type_swap",
                "phase": "query",
                "target_index": random.randint(0, 3),
                "new_type": random.choice(_SERVER_MSG_TYPES),
            })

        elif family == "inject_extra_message":
            # Inject a plausible or garbage message
            inject_type = random.choice(["plausible", "garbage"])
            if inject_type == "plausible":
                inject_hex = random.choice([
                    _build_datarow_hex(["smuggled"]),
                    _build_error_hex("42000", "injected"),
                ])
            else:
                inject_hex = _random_hex(random.randint(5, 100))
            transcript["mutations"].append({
                "kind": "inject_after",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 4),
                "hex": inject_hex,
            })

        elif family == "truncate_message":
            transcript["mutations"].append({
                "kind": "truncate_message",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 4),
                "keep_bytes": random.randint(0, 10),
            })

        elif family == "duplicate_message":
            transcript["mutations"].append({
                "kind": "duplicate_message",
                "phase": random.choice(["startup", "query"]),
                "target_index": random.randint(0, 4),
            })

        elif family == "drop_readyforquery":
            # Drop the ReadyForQuery message — tests driver state machine
            transcript["mutations"].append({
                "kind": "drop_message",
                "phase": "query",
                "target_index": -1,  # Will be resolved: last message is usually Z
            })

        elif family == "drop_auth_ok":
            transcript["mutations"].append({
                "kind": "drop_message",
                "phase": "startup",
                "target_index": 0,  # AuthOk is first
            })

        elif family == "extra_readyforquery":
            # ReadyForQuery('I') = Z + len(5) + 'I' = 5a00000005 49
            transcript["mutations"].append({
                "kind": "inject_after",
                "phase": "query",
                "target_index": random.randint(0, 3),
                "hex": "5a0000000549",
            })

        elif family == "append_raw_garbage":
            garbage_len = random.choice([1, 4, 8, 16, 64, 256, 1024])
            transcript["mutations"].append({
                "kind": "append_raw",
                "phase": random.choice(["startup", "query"]),
                "hex": _random_hex(garbage_len),
            })

        elif family == "combo":
            # Apply 2-3 random mutations
            combo_count = random.randint(2, 3)
            for _ in range(combo_count):
                sub_family = random.choice([
                    "length_undercount", "length_overcount", "type_swap",
                    "truncate_message", "overflow_length",
                ])
                if sub_family == "length_undercount":
                    transcript["mutations"].append({
                        "kind": "length_undercount",
                        "phase": random.choice(["startup", "query"]),
                        "target_index": random.randint(0, 5),
                        "delta": -random.randint(1, 100),
                    })
                elif sub_family == "length_overcount":
                    transcript["mutations"].append({
                        "kind": "length_overcount",
                        "phase": random.choice(["startup", "query"]),
                        "target_index": random.randint(0, 5),
                        "delta": random.randint(1, 1000),
                    })
                elif sub_family == "type_swap":
                    transcript["mutations"].append({
                        "kind": "type_swap",
                        "phase": random.choice(["startup", "query"]),
                        "target_index": random.randint(0, 4),
                        "new_type": random.choice(_SERVER_MSG_TYPES),
                    })
                elif sub_family == "truncate_message":
                    transcript["mutations"].append({
                        "kind": "truncate_message",
                        "phase": random.choice(["startup", "query"]),
                        "target_index": random.randint(0, 4),
                        "keep_bytes": random.randint(0, 5),
                    })
                elif sub_family == "overflow_length":
                    transcript["mutations"].append({
                        "kind": "overflow_length",
                        "phase": random.choice(["startup", "query"]),
                        "target_index": random.randint(0, 5),
                        "value": random.choice(_OVERFLOW_VALUES),
                    })

        metadata = {
            "driver": driver,
            "query_mode": query_mode,
            "mutation_family": family,
            "mutation_count": len(transcript["mutations"]),
            "request_id": f"pgdriver-{family}-{random.randint(0, 99999):05d}",
        }

        return Input(
            data=json.dumps(transcript).encode("utf-8"),
            metadata=metadata,
        )


def _weighted_choice(weights: dict[str, float]) -> str:
    items = list(weights.keys())
    probs = list(weights.values())
    return random.choices(items, weights=probs, k=1)[0]


def _random_query(mode: str) -> str:
    if mode == "extended":
        return random.choice([
            "SELECT $1::int",
            "SELECT $1::text, $2::int",
            "SELECT 1",
            "INSERT INTO test VALUES ($1)",
        ])
    return random.choice([
        "SELECT 1",
        "SELECT 'hello'",
        "SELECT 1; SELECT 2",
        "SELECT * FROM pg_catalog.pg_tables LIMIT 1",
    ])


def _random_params() -> list:
    count = random.randint(0, 3)
    return [
        random.choice(["1", "hello", "42", "test", ""])
        for _ in range(count)
    ]


def _random_hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n * 2))


def _build_server_msg_hex(tag: int, payload: bytes) -> str:
    """Build a PG server message as hex string."""
    msg = bytes([tag]) + struct.pack("!I", len(payload) + 4) + payload
    return msg.hex()


def _build_datarow_hex(values: list[str]) -> str:
    """Build a DataRow message as hex."""
    parts = struct.pack("!H", len(values))
    for val in values:
        encoded = val.encode("utf-8")
        parts += struct.pack("!i", len(encoded)) + encoded
    return _build_server_msg_hex(ord("D"), parts)


def _build_error_hex(code: str, message: str) -> str:
    """Build an ErrorResponse message as hex."""
    payload = (
        b"SERROR\x00"
        + b"C" + code.encode("utf-8") + b"\x00"
        + b"M" + message.encode("utf-8") + b"\x00"
        + b"\x00"
    )
    return _build_server_msg_hex(ord("E"), payload)


def get_pgdriver_mutators() -> list:
    return [PgdriverMutator()]
