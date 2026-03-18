"""GuidanceProfile: per-library analysis result.

This is the output of a static analyzer and the input to the GuidanceEngine.
It describes what a specific library does and doesn't check, which paths
can be bypassed, and what inputs would trigger those bypasses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CheckpointStatus:
    """Status of a single security checkpoint in a library."""

    name: str
    present: bool
    conditional: bool = False  # guarded by options/flags
    condition: str = ""  # e.g. "options.get('verify_signature')"
    location: str = ""  # e.g. "jws.py:72"
    bypass_constraint: dict[str, Any] | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "name": self.name,
            "present": self.present,
        }
        if self.conditional:
            d["conditional"] = True
            d["condition"] = self.condition
        if self.location:
            d["location"] = self.location
        if self.bypass_constraint:
            d["bypass_constraint"] = self.bypass_constraint
        return d

    @classmethod
    def from_dict(cls, data: dict) -> CheckpointStatus:
        return cls(
            name=data["name"],
            present=data["present"],
            conditional=data.get("conditional", False),
            condition=data.get("condition", ""),
            location=data.get("location", ""),
            bypass_constraint=data.get("bypass_constraint"),
        )


@dataclass
class ErrorSwallow:
    """An error-swallowing pattern found in the library."""

    location: str  # file:line
    pattern: str  # e.g. "except Exception: pass"
    in_function: str  # containing function name
    reachable_from: list[str] = field(default_factory=list)
    swallows: str = ""  # what it swallows (e.g. "signature verification failure")

    def to_dict(self) -> dict:
        return {
            "location": self.location,
            "pattern": self.pattern,
            "in_function": self.in_function,
            "reachable_from": self.reachable_from,
            "swallows": self.swallows,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ErrorSwallow:
        return cls(**data)


@dataclass
class TaintPath:
    """A taint propagation path from attacker input to a branch decision."""

    source: str  # e.g. "header.alg"
    influences_branch: str  # e.g. "jws.py:38"
    determines: str  # what the branch decides
    reachable_checkpoints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "influences_branch": self.influences_branch,
            "determines": self.determines,
            "reachable_checkpoints": self.reachable_checkpoints,
        }

    @classmethod
    def from_dict(cls, data: dict) -> TaintPath:
        return cls(**data)


@dataclass
class BypassSeed:
    """A seed that exercises a specific gap."""

    gap: str  # checkpoint name that's missing/bypassable
    description: str
    seed_fields: dict[str, Any] = field(default_factory=dict)
    expected_behavior: str = "reject"
    actual_behavior: str = "accept"

    def to_dict(self) -> dict:
        return {
            "gap": self.gap,
            "description": self.description,
            "seed_fields": self.seed_fields,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
        }

    @classmethod
    def from_dict(cls, data: dict) -> BypassSeed:
        return cls(**data)


@dataclass
class GuidanceProfile:
    """Complete static analysis result for one library.

    This is the bridge between static analysis and fuzzing:
    - Analyzers produce it
    - GuidanceEngine consumes it
    - Serializable to/from JSON for caching
    """

    protocol: str  # "jwt", "saml"
    library: str  # "pyjwt", "python-jose"
    version: str
    language: str  # "python", "java", "node", "go"

    checkpoints: dict[str, CheckpointStatus] = field(default_factory=dict)
    error_swallowing: list[ErrorSwallow] = field(default_factory=list)
    taint_paths: list[TaintPath] = field(default_factory=list)
    bypass_seeds: list[BypassSeed] = field(default_factory=list)
    conditional_bypasses: int = 0

    # ── Derived properties ──

    @property
    def missing_checkpoints(self) -> list[str]:
        return [name for name, cp in self.checkpoints.items()
                if not cp.present]

    @property
    def conditional_checkpoints(self) -> list[str]:
        return [name for name, cp in self.checkpoints.items()
                if cp.present and cp.conditional]

    @property
    def checkpoint_score(self) -> tuple[int, int]:
        """(found, total) checkpoint counts."""
        total = len(self.checkpoints)
        found = sum(1 for cp in self.checkpoints.values() if cp.present)
        return found, total

    def has_gap(self, checkpoint_name: str) -> bool:
        """True if checkpoint is missing or conditional."""
        cp = self.checkpoints.get(checkpoint_name)
        if cp is None:
            return True  # unknown = assume missing
        return not cp.present or cp.conditional

    # ── Serialization ──

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol,
            "library": self.library,
            "version": self.version,
            "language": self.language,
            "checkpoints": {
                name: cp.to_dict()
                for name, cp in self.checkpoints.items()
            },
            "error_swallowing": [e.to_dict() for e in self.error_swallowing],
            "taint_paths": [t.to_dict() for t in self.taint_paths],
            "bypass_seeds": [b.to_dict() for b in self.bypass_seeds],
            "conditional_bypasses": self.conditional_bypasses,
        }

    @classmethod
    def from_dict(cls, data: dict) -> GuidanceProfile:
        checkpoints = {
            name: CheckpointStatus.from_dict({**cp_data, "name": name})
            for name, cp_data in data.get("checkpoints", {}).items()
        }
        return cls(
            protocol=data["protocol"],
            library=data["library"],
            version=data.get("version", ""),
            language=data.get("language", ""),
            checkpoints=checkpoints,
            error_swallowing=[
                ErrorSwallow.from_dict(e)
                for e in data.get("error_swallowing", [])
            ],
            taint_paths=[
                TaintPath.from_dict(t)
                for t in data.get("taint_paths", [])
            ],
            bypass_seeds=[
                BypassSeed.from_dict(b)
                for b in data.get("bypass_seeds", [])
            ],
            conditional_bypasses=data.get("conditional_bypasses", 0),
        )

    def save(self, path: str | Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str | Path) -> GuidanceProfile:
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))
