"""Protocol specification: defines what security checkpoints a protocol requires.

A ProtocolSpec is the "ground truth" — it says:
  "For JWT, these checkpoints MUST exist on every verification path."
  "For SAML, these checkpoints MUST exist on every assertion processing path."

Loaded from YAML files in webfuzzer/guidance/specs/.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AttackerField:
    """A field the attacker controls in the protocol input."""

    field: str  # e.g. "header.alg", "SignatureValue"
    type: str  # string, array, boolean, url, xml_element
    mutations: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Checkpoint:
    """A required security checkpoint in the protocol verification flow."""

    name: str  # e.g. "sig_verify", "crit_check"
    description: str
    rfc: str  # e.g. "RFC 7515 §4.1.11"
    severity: str  # critical, high, medium
    taint_sources: list[str] = field(default_factory=list)
    # regex patterns to detect this checkpoint in source code
    detection_patterns: list[str] = field(default_factory=list)


@dataclass
class ProtocolSpec:
    """Complete specification for a protocol's security requirements."""

    protocol: str  # "jwt", "saml", "oauth"
    version: str  # "RFC 7515/7519", "SAML 2.0"
    checkpoints: dict[str, Checkpoint] = field(default_factory=dict)
    attacker_controlled: list[AttackerField] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> ProtocolSpec:
        """Load a protocol spec from a YAML file."""
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)

        checkpoints = {}
        for name, cp_data in raw.get("checkpoints", {}).items():
            checkpoints[name] = Checkpoint(
                name=name,
                description=cp_data.get("description", ""),
                rfc=cp_data.get("rfc", ""),
                severity=cp_data.get("severity", "medium"),
                taint_sources=cp_data.get("taint_sources", []),
                detection_patterns=cp_data.get("detection_patterns", []),
            )

        attacker = []
        for af_data in raw.get("attacker_controlled", []):
            attacker.append(AttackerField(
                field=af_data["field"],
                type=af_data.get("type", "string"),
                mutations=af_data.get("mutations", []),
            ))

        return cls(
            protocol=raw["protocol"],
            version=raw.get("version", ""),
            checkpoints=checkpoints,
            attacker_controlled=attacker,
        )

    @classmethod
    def load_builtin(cls, protocol: str) -> ProtocolSpec:
        """Load a built-in spec by protocol name (e.g. 'jwt', 'saml')."""
        specs_dir = Path(__file__).parent / "specs"
        path = specs_dir / f"{protocol}.yaml"
        if not path.exists():
            raise FileNotFoundError(
                f"No built-in spec for protocol '{protocol}'. "
                f"Available: {[p.stem for p in specs_dir.glob('*.yaml')]}"
            )
        return cls.load(path)

    def critical_checkpoints(self) -> list[Checkpoint]:
        """Return checkpoints with severity=critical."""
        return [cp for cp in self.checkpoints.values()
                if cp.severity == "critical"]

    def taint_sources_for(self, checkpoint_name: str) -> list[str]:
        """Return attacker-controlled fields that influence a checkpoint."""
        cp = self.checkpoints.get(checkpoint_name)
        if cp is None:
            return []
        return cp.taint_sources
