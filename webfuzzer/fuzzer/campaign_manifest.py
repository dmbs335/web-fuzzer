"""Campaign manifest writer for formal-research validation runs.

The manifest is intentionally small and conservative.  It records enough
provenance for ``fuzzing-formal-research`` to join a fuzzer run with offline
artifacts, without trying to serialize the whole runtime object graph.
"""

from __future__ import annotations

import hashlib
import json
import platform
import shlex
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CAMPAIGN_MANIFEST_SCHEMA_VERSION = "1.0.0"

_EXPERIMENTAL_METHOD_FLAGS: tuple[tuple[str, str], ...] = (
    ("mcts", "mcts"),
    ("adaptive_coverage", "adaptive-coverage"),
    ("target_coverage", "target-coverage"),
    ("guidance", "guidance"),
    ("concolic", "concolic"),
)

_EXTERNAL_METHOD_PATHS: tuple[tuple[str, str], ...] = (
    ("lattice_atoms", "lattice-atoms"),
    ("automaton_witnesses", "automaton-witnesses"),
    ("stopping_signal", "stopping-signal"),
    ("dedup_atoms", "dedup-atoms"),
    ("implication_base", "implication-base"),
)


@dataclass(frozen=True)
class CampaignManifestInput:
    """Normalized CLI/runtime fields needed to build a manifest."""

    grammar: str
    target_cmd: str
    diff_cmds: tuple[str, ...] = ()
    output_dir: Path | None = None
    seed: int | None = None
    count: int = 0
    timeout: float = 0.0
    condition: str | None = None
    method: str | None = None
    cli: str = ""
    seeds_dir: Path | None = None
    artifacts: dict[str, str] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _hash_directory(path: Path) -> str:
    """Hash file names and contents in a directory deterministically."""
    h = hashlib.sha256()
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        rel = item.relative_to(path).as_posix()
        h.update(rel.encode("utf-8", errors="replace"))
        h.update(b"\0")
        h.update(_hash_file(item).encode("ascii"))
        h.update(b"\0")
    return "sha256:" + h.hexdigest()


def corpus_hash_for_manifest(
    *,
    seeds_dir: Path | None,
    grammar: str,
    seed: int | None,
    initial_seed_count: int | None = None,
) -> str:
    """Return a stable corpus/seed-source hash for manifest provenance."""
    if seeds_dir is not None and seeds_dir.exists():
        if seeds_dir.is_file():
            return _hash_file(seeds_dir)
        return _hash_directory(seeds_dir)
    seed_text = json.dumps(
        {
            "grammar": grammar,
            "seed": seed,
            "initial_seed_count": initial_seed_count,
            "seed_source": "generated",
        },
        sort_keys=True,
    )
    return _sha256_text(seed_text)


def target_hashes_for_manifest(target_cmd: str, diff_cmds: Iterable[str]) -> dict[str, str]:
    """Hash target command strings without exposing environment-specific objects."""
    hashes = {"primary": _sha256_text(target_cmd)}
    for idx, cmd in enumerate(diff_cmds):
        hashes[f"ref{idx}"] = _sha256_text(cmd)
    return hashes


def combined_target_hash(target_hashes: dict[str, str]) -> str:
    return _sha256_text(json.dumps(target_hashes, sort_keys=True))


def infer_method(options: dict[str, Any]) -> str:
    """Infer a compact method label from active experimental options."""
    if options.get("method"):
        return str(options["method"])

    methods: list[str] = []
    for key, label in _EXPERIMENTAL_METHOD_FLAGS:
        value = options.get(key)
        if value:
            methods.append(label if key != "guidance" else f"guidance:{value}")

    for key, label in _EXTERNAL_METHOD_PATHS:
        if options.get(key):
            methods.append(label)

    mutator_scheduler = str(options.get("mutator_scheduler") or "")
    if mutator_scheduler and mutator_scheduler != "random":
        methods.append(f"mutator-scheduler:{mutator_scheduler}")

    scheduler = str(options.get("scheduler") or "")
    if scheduler and scheduler not in {"", "entropic"}:
        methods.append(f"scheduler:{scheduler}")

    return "+".join(sorted(set(methods))) if methods else "baseline"


def infer_condition(options: dict[str, Any], method: str) -> str:
    if options.get("condition"):
        return str(options["condition"])
    if options.get("negative_control"):
        return "negative-control"
    if method == "baseline":
        return "baseline"
    if options.get("artifact_only"):
        return "artifact-only"
    if options.get("feedback_only"):
        return "feedback-only"
    return "candidate"


def build_campaign_manifest(inp: CampaignManifestInput) -> dict[str, Any]:
    """Build a schema-versioned campaign manifest."""
    target_hashes = target_hashes_for_manifest(inp.target_cmd, inp.diff_cmds)
    corpus_hash = corpus_hash_for_manifest(
        seeds_dir=inp.seeds_dir,
        grammar=inp.grammar,
        seed=inp.seed,
        initial_seed_count=inp.options.get("initial_seed_count"),
    )
    method = inp.method or infer_method(inp.options)
    condition = inp.condition or infer_condition(inp.options, method)
    run_id = _run_id(
        grammar=inp.grammar,
        condition=condition,
        method=method,
        seed=inp.seed,
    )
    artifacts = dict(inp.artifacts)
    if inp.output_dir is not None:
        artifacts.setdefault("report", str(inp.output_dir / "report.json"))
        artifacts.setdefault("findings_dir", str(inp.output_dir / "findings"))
        artifacts.setdefault("corpus_dir", str(inp.output_dir / "corpus"))

    return {
        "schema_version": CAMPAIGN_MANIFEST_SCHEMA_VERSION,
        "producer": "web-fuzzer",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source_run_id": run_id,
        "source_target_hash": combined_target_hash(target_hashes),
        "source_corpus_hash": corpus_hash,
        "method": method,
        "run_id": run_id,
        "domain": inp.grammar,
        "condition": condition,
        "seed": inp.seed if inp.seed is not None else 0,
        "budget_seconds": float(inp.timeout or 0.0),
        "budget_iterations": int(inp.count or 0),
        "target_hashes": target_hashes,
        "corpus_hash": corpus_hash,
        "cli": inp.cli,
        "artifacts": artifacts,
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "options": inp.options,
    }


def write_campaign_manifest(path: Path, manifest: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")


def argv_to_cli(argv: list[str] | None = None) -> str:
    args = sys.argv[1:] if argv is None else argv
    return "webfuzzer " + " ".join(shlex.quote(str(part)) for part in args)


def _run_id(*, grammar: str, condition: str, method: str, seed: int | None) -> str:
    safe_method = "".join(ch if ch.isalnum() else "_" for ch in method).strip("_")
    safe_method = safe_method[:48] or "baseline"
    seed_part = f"seed{seed}" if seed is not None else "seed0"
    date_part = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"{grammar}_{condition}_{safe_method}_{seed_part}_{date_part}"
