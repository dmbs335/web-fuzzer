"""Assembly helpers for optional external research hooks.

These helpers keep artifact loading and startup-time hook application out of
the CLI. All hooks are optional and must degrade to the normal fuzzer path on
bad or missing input.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def load_stopping_signal(path: Path):
    """Parse an external stopping-signal payload from ``path``."""
    from ..fuzzer.protocols import StoppingSignal

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"Warning: failed to read --stopping-signal {path}: {exc}",
            file=sys.stderr,
        )
        return None

    observed: dict | None = None
    phase: str | None = None
    source_run_id: str | None = None
    pareto_alpha: float | None = None

    if isinstance(payload, dict) and "phase" in payload:
        observed = payload
        phase = str(payload.get("phase") or "").strip().lower() or None
        source_run_id = payload.get("source_run_id")
        if payload.get("pareto_alpha") is not None:
            try:
                pareto_alpha = float(payload["pareto_alpha"])
            except (TypeError, ValueError):
                pass
    elif isinstance(payload, dict) and isinstance(payload.get("checks"), list):
        source_run_id = payload.get("run_id")
        for ck in payload["checks"]:
            if not isinstance(ck, dict):
                continue
            if ck.get("id") == "DG018":
                observed = ck.get("observed") or {}
                status = str(ck.get("status") or "").upper()
                phase = "exploitation" if status == "PASS" else "discovery"
                break
        # DG006 carries the Hill/Pareto tail-index used by learned-weight
        # normalization. It is optional and older payloads will not have it.
        for ck in payload.get("checks", []):
            if not isinstance(ck, dict) or ck.get("id") != "DG006":
                continue
            obs = ck.get("observed") or {}
            alpha_value = obs.get("pareto_alpha", obs.get("alpha"))
            if alpha_value is not None:
                try:
                    pareto_alpha = float(alpha_value)
                except (TypeError, ValueError):
                    pass

    if not isinstance(observed, dict) or phase not in {"discovery", "exploitation"}:
        print(
            f"Warning: --stopping-signal {path} did not contain a usable "
            "phase/check; ignoring.",
            file=sys.stderr,
        )
        return None

    try:
        return StoppingSignal(
            phase=phase,
            missing_mass_upper=float(observed.get("missing_mass_upper", 0.0)),
            n_samples=int(observed.get("n_samples", 0)),
            tau_mix=(
                None
                if observed.get("tau_mix") is None
                else float(observed.get("tau_mix"))
            ),
            source_run_id=source_run_id,
            pareto_alpha=pareto_alpha,
        )
    except (TypeError, ValueError) as exc:
        print(
            f"Warning: --stopping-signal {path} could not be parsed: {exc}",
            file=sys.stderr,
        )
        return None


def apply_mutator_research_hooks(
    *,
    mutators: list,
    lattice_atoms_path: Path | None,
    automaton_witnesses_path: Path | None,
) -> None:
    """Apply startup-time strategy boosts from external research artifacts."""
    _apply_weight_hook(
        mutators=mutators,
        path=lattice_atoms_path,
        option_name="lattice-atoms",
        protocol_name="LatticeAtomMutator",
        method_name="apply_lattice_atoms",
    )
    _apply_weight_hook(
        mutators=mutators,
        path=automaton_witnesses_path,
        option_name="automaton-witnesses",
        protocol_name="AutomatonWitnessMutator",
        method_name="apply_automaton_witnesses",
    )


def apply_stopping_signal_hook(*, scheduler, stopping_signal_path: Path | None) -> None:
    """Apply an optional stopping signal to compatible schedulers."""
    if stopping_signal_path is None:
        return

    signal = load_stopping_signal(stopping_signal_path)
    if signal is None:
        return

    applied = False
    for cand in (
        scheduler,
        getattr(scheduler, "primary", None),
        getattr(scheduler, "secondary", None),
    ):
        if cand is not None and hasattr(cand, "set_stopping_signal"):
            cand.set_stopping_signal(signal)
            applied = True

    if applied:
        print(
            f"[stopping-signal] phase={signal.phase} "
            f"M0_upper={signal.missing_mass_upper:.4g} "
            f"n={signal.n_samples} from {stopping_signal_path}",
        )
    else:
        print(
            f"Warning: --stopping-signal supplied but scheduler "
            f"{type(scheduler).__name__} has no set_stopping_signal method; "
            "ignoring.",
            file=sys.stderr,
        )


def build_research_deduplicator(dedup_atoms_path: Path | None):
    """Build an optional atom-based deduplicator from an external artifact."""
    if dedup_atoms_path is None:
        return None
    try:
        payload = _read_json(dedup_atoms_path, option_name="dedup-atoms")
        atoms = payload.get("atoms", []) if isinstance(payload, dict) else []
        if atoms:
            from ..fuzzer.dedup.structural_dedup import StructuralDeduplicator

            deduplicator = StructuralDeduplicator()
            deduplicator.set_atoms(atoms)
            print(
                f"  Dedup: experimental atom mode - {len(atoms)} atoms "
                f"from {dedup_atoms_path}",
                file=sys.stderr,
            )
            return deduplicator
        print(
            f"Warning: --dedup-atoms {dedup_atoms_path} has no 'atoms' list; "
            "falling back to default dedup.",
            file=sys.stderr,
        )
    except Exception as exc:
        print(
            f"Warning: failed to load --dedup-atoms {dedup_atoms_path}: {exc}; "
            "falling back to default dedup.",
            file=sys.stderr,
        )
    return None


def wrap_implication_oracles(oracles: list, implication_base_path: Path | None) -> list:
    """Wrap oracles with optional implication diagnostics."""
    if implication_base_path is None:
        return oracles
    try:
        implications = _read_json(implication_base_path, option_name="implication-base")
        if isinstance(implications, list) and implications:
            from ..fuzzer.oracles.implication_oracle import ImplicationSoftOracle

            wrapped = [ImplicationSoftOracle(o, implications) for o in oracles]
            print(
                f"  Implication oracle: {len(implications)} conf=1.0 rules "
                f"from {implication_base_path}",
                file=sys.stderr,
            )
            return wrapped
        print(
            f"Warning: --implication-base {implication_base_path} is empty "
            "or not a list; implication oracle disabled.",
            file=sys.stderr,
        )
    except Exception as exc:
        print(
            f"Warning: failed to load --implication-base {implication_base_path}: "
            f"{exc}; implication oracle disabled.",
            file=sys.stderr,
        )
    return oracles


def _apply_weight_hook(
    *,
    mutators: list,
    path: Path | None,
    option_name: str,
    protocol_name: str,
    method_name: str,
) -> None:
    if path is None:
        return
    try:
        payload = _read_json(path, option_name=option_name)
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"Warning: failed to read --{option_name} {path}: {exc}",
            file=sys.stderr,
        )
        return

    weights = payload.get("weights") if isinstance(payload, dict) else None
    if not isinstance(weights, dict) or not weights:
        return

    from ..fuzzer import protocols

    protocol = getattr(protocols, protocol_name)
    boosted = 0
    for mutator in mutators:
        if isinstance(mutator, protocol):
            getattr(mutator, method_name)(weights)
            boosted += 1
    print(
        f"[{option_name}] applied {len(weights)} strategy weights to "
        f"{boosted} mutator(s) from {path}",
    )


def _read_json(path: Path, *, option_name: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise json.JSONDecodeError(
            f"--{option_name} payload is not valid JSON: {exc.msg}",
            exc.doc,
            exc.pos,
        ) from exc
