"""CLI interface for the web fuzzer framework.

Usage:
    python -m webfuzzer generate --grammar html --count 5
    python -m webfuzzer generate --grammar csp --count 10 --seed 42
    python -m webfuzzer list
    python -m webfuzzer validate --grammar html
    python -m webfuzzer fuzz --grammar json --target-cmd "./parser {input}" --count 1000
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .app.campaigns import apply_campaign_preset
from .app.factories import (
    build_coverage,
    build_mutator_scheduler,
    build_mutators,
    build_oracles,
    build_seed_scheduler,
    build_targets,
    configure_differential_oracles,
)
from .core.generator import Generator, GenerationError
from .core.registry import GrammarRegistry
from .app.persistent_targets import persistent_timeout_for_cmd, to_persistent_cmd


def _load_stopping_signal(path: Path):
    """Parse a DG018 stopping-signal payload from ``path``.

    Accepts two shapes:

    * Minimal: ``{"phase": "exploitation", "missing_mass_upper": 0.005,
      "n_samples": 9802, "tau_mix": 8.91}``
    * Full lint output from the external diffspace research workspace: the loader
      walks ``checks`` for ``id == "DG018"`` and lifts ``observed`` plus
      derives ``phase`` from ``status`` (``PASS`` → ``exploitation``,
      anything else → ``discovery``).

    Returns a :class:`StoppingSignal` or ``None`` if parsing failed
    (which is logged to stderr but does not abort the run).
    """
    from .fuzzer.protocols import StoppingSignal

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
                phase = (
                    "exploitation"
                    if str(ck.get("status", "")).upper() == "PASS"
                    else "discovery"
                )
            elif ck.get("id") == "DG006":
                # Extract Pareto α for heavy-tail-aware apply_learned_weights.
                _dg006_obs = ck.get("observed") or {}
                if _dg006_obs.get("alpha") is not None:
                    try:
                        pareto_alpha = float(_dg006_obs["alpha"])
                    except (TypeError, ValueError):
                        pass

    if observed is None or phase not in {"discovery", "exploitation"}:
        print(
            f"Warning: --stopping-signal {path} did not contain a usable "
            f"DG018 payload; ignoring.",
            file=sys.stderr,
        )
        return None

    try:
        return StoppingSignal(
            phase=phase,  # type: ignore[arg-type]
            missing_mass_upper=float(observed.get("missing_mass_upper", 0.0)),
            n_samples=int(observed.get("n_samples", 0)),
            tau_mix=(
                float(observed["tau_mix"])
                if observed.get("tau_mix") is not None
                else None
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


def _build_oracles(names: str) -> list:
    """Backward-compatible wrapper for legacy tests and callers."""
    return build_oracles(names)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webfuzzer",
        description="Grammar-based web fuzzing framework",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- generate ---
    gen = sub.add_parser("generate", help="Generate output from a grammar")
    gen.add_argument(
        "-g", "--grammar", required=True, help="Grammar name to use"
    )
    gen.add_argument(
        "-r", "--rule", default=None, help="Starting rule (default: grammar root)"
    )
    gen.add_argument(
        "-n", "--count", type=int, default=1, help="Number of outputs to generate"
    )
    gen.add_argument(
        "-s", "--seed", type=int, default=None, help="Random seed for reproducibility"
    )
    gen.add_argument(
        "-d", "--max-depth", type=int, default=None, help="Max recursion depth"
    )
    gen.add_argument(
        "--grammar-dir",
        type=Path,
        default=None,
        help="Additional directory to load grammars from",
    )
    gen.add_argument(
        "--no-builtins",
        action="store_true",
        help="Don't load built-in grammar files",
    )
    gen.add_argument(
        "-o", "--output", type=Path, default=None, help="Output file (default: stdout)"
    )
    gen.add_argument(
        "--separator",
        default="\n---\n",
        help="Separator between generated outputs (default: ---)",
    )

    # --- list ---
    sub.add_parser("list", help="List loaded grammars and their rules")

    # --- validate ---
    val = sub.add_parser("validate", help="Validate grammar files")
    val.add_argument(
        "-g", "--grammar", default=None, help="Specific grammar to validate (or all)"
    )
    val.add_argument(
        "--grammar-dir",
        type=Path,
        default=None,
        help="Additional directory to load grammars from",
    )

    # --- fuzz ---
    fuz = sub.add_parser("fuzz", help="Fuzz a target using grammar-based generation")
    fuz.add_argument(
        "-g", "--grammar", required=True, help="Grammar name for input generation"
    )
    fuz.add_argument(
        "-r", "--rule", default=None, help="Starting rule (default: grammar root)"
    )
    fuz.add_argument(
        "--target-cmd", required=True,
        help="Command to execute. Use {input} as placeholder for input file path",
    )
    fuz.add_argument(
        "-n", "--count", type=int, default=0,
        help="Max iterations (0 = unlimited, default: 0)",
    )
    fuz.add_argument(
        "-t", "--timeout", type=float, default=0,
        help="Max time in seconds (0 = unlimited)",
    )
    fuz.add_argument(
        "-s", "--seed", type=int, default=None, help="Random seed"
    )
    fuz.add_argument(
        "--mutators", default="grammar,havoc",
        help="Comma-separated mutator list (grammar,havoc,token,splice,dictionary,mxss,structural,saml,cookie,jwt,oauth,pgwire,request_smuggling,domclobber)",
    )
    fuz.add_argument(
        "--scheduler", default="entropic",
        help="Seed scheduler (random,entropic,ecofuzz,rare-branch,map-elites)",
    )
    fuz.add_argument(
        "--oracle", default="crash,sanitizer",
        help="Comma-separated oracle list (crash,response,sanitizer,xss,mxss,ssrf,saml,saml_sigtrue,saml_validator,cookie,jwt,oauth,pgwire,request_smuggling,graphql,graphql_exec,sanitizer_diff,deser,jndi,jdbc,domclobber,domclobber_diff)",
    )
    fuz.add_argument(
        "--initial-seeds", type=int, default=100,
        help="Number of initial seeds to generate (default: 100)",
    )
    fuz.add_argument(
        "-o", "--output-dir", type=Path, default=None,
        help="Directory for findings and corpus",
    )
    fuz.add_argument(
        "--grammar-dir", type=Path, default=None,
        help="Additional directory to load grammars from",
    )
    fuz.add_argument(
        "--no-builtins", action="store_true",
        help="Don't load built-in grammar files",
    )
    fuz.add_argument(
        "--diff-cmd", action="append", default=[],
        help="Reference target for differential fuzzing (repeatable)",
    )
    fuz.add_argument(
        "--diff-trace", type=Path, default=None,
        help="Append one JSONL row per differential oracle invocation to this "
             "path (pre-dedup raw stream for E1 census / Good-Turing).",
    )
    fuz.add_argument(
        "--feature-dump", type=Path, default=None,
        help="Append one JSONL row per differential execution with input-side "
             "features (sha1, length, applied mutator strategies, divergence, "
             "diff_fields). Consumed by E2 preservation and E3 manifold "
             "offline analyses.",
    )
    fuz.add_argument(
        "--lattice-atoms", type=Path, default=None,
        help="Path to strategy_atom_weights.json produced by E4 FCA. "
             "On startup, strategies listed in this file get their base "
             "weights boosted by their Birkhoff-atom coverage score "
             "(SamlMutator.apply_lattice_atoms).",
    )
    fuz.add_argument(
        "--automaton-witnesses", type=Path, default=None,
        help="Path to strategy_witness_weights.json produced by the external "
             "diffspace research workspace. "
             "On startup, strategies listed in this file get their base "
             "weights boosted by their E7 disagreement-witness contribution "
             "(SamlMutator.apply_automaton_witnesses).",
    )
    fuz.add_argument(
        "--stopping-signal", type=Path, default=None,
        help="Path to a stopping-signal JSON file produced by the external "
             "diffspace research workspace. "
             "When the embedded DG018 check reports phase=exploitation, "
             "EntropicScheduler dampens the entropy/novelty component "
             "and amplifies the class-saturation penalty so energy "
             "flows to under-visited diff-pattern classes. Accepts "
             "either the full lint JSON or a minimal "
             "{phase, missing_mass_upper, n_samples} payload.",
    )
    fuz.add_argument(
        "--dedup-atoms", type=Path, default=None,
        help="Path to an E4 FCA summary.json (or any JSON with a top-level "
             "\"atoms\" list).  When supplied, the deduplicator switches from "
             "oracle-level diff_pattern_hash fingerprinting to a Birkhoff "
             "bitvector key: two findings that touch the same subset of "
             "meet-irreducible lattice atoms are collapsed into one report "
             "regardless of which mutator strategy produced them.  Findings "
             "whose diff_fields have no overlap with the atom set fall back "
             "to the original hash path so no coverage is lost.",
    )
    fuz.add_argument(
        "--implication-base", type=Path, default=None,
        help="Path to an E4 FCA implication_base.json.  When supplied, an "
             "ImplicationSoftOracle is layered on top of the primary oracle: "
             "any finding whose diff_fields satisfy a conf=1.0 implication "
             "premise but NOT its conclusion is flagged as a novel "
             "implication-violation finding and written to violations.jsonl "
             "in the output directory.",
    )
    fuz.add_argument(
        "--dict-file", type=Path, default=None,
        help="Dictionary file for dictionary mutator (one token per line)",
    )
    fuz.add_argument(
        "--seeds-dir", type=Path, default=None,
        help="Directory of seed files to load into initial corpus",
    )
    fuz.add_argument(
        "--max-corpus-size", type=int, default=5000,
        help="Maximum corpus size (default: 5000, dynamically scales up to 2x when discovering new coverage)",
    )
    fuz.add_argument(
        "--max-assertions", type=int, default=0,
        help="Limit max assertion count per SAML payload (0=no limit, 1=single assertion mode for FP reduction)",
    )
    fuz.add_argument(
        "--import-findings", type=Path, nargs="+", default=None,
        help="Import finding inputs from previous session directories as seeds "
             "(e.g. --import-findings /path/to/session/53 /path/to/session/58)",
    )
    fuz.add_argument(
        "--persistent", action="store_true",
        help="Use persistent target mode (keep subprocess alive, ~50x faster)",
    )
    fuz.add_argument(
        "--resume", action="store_true",
        help="Resume from last checkpoint (requires --output-dir with existing checkpoint)",
    )
    fuz.add_argument(
        "--checkpoint-interval", type=float, default=60.0,
        help="Checkpoint save interval in seconds (default: 60)",
    )

    fuz.add_argument(
        "--campaign", default=None,
        help="Campaign preset (cve_detect, patch_bypass, novel, hrs_stable, hrs_research, hrs_hybrid, pgwire_stable, pgwire_research, pgwire_hybrid). "
             "Pre-configures oracle/mutators/seeds for the campaign goal.",
    )

    # ── Exploration strategy flags ─────────────────────────────
    fuz.add_argument(
        "--mcts", action="store_true",
        help="Use MCTS-guided grammar derivation (UCB1 production selection)",
    )
    fuz.add_argument(
        "--mcts-exploration", type=float, default=1.41,
        help="MCTS exploration weight (UCB1 c parameter, default: 1.41)",
    )
    fuz.add_argument(
        "--mutator-scheduler", default="random",
        help="Mutator scheduler (random,mopt,darwin,linucb)",
    )
    fuz.add_argument(
        "--mutator-weights",
        default=None,
        help="Comma-separated weights for mutators (e.g. '1,1,3' for grammar,havoc,saml → 20%%/20%%/60%%)",
    )
    fuz.add_argument(
        "--linucb-alpha", type=float, default=1.0,
        help="LinUCB exploration parameter (default: 1.0)",
    )
    fuz.add_argument(
        "--danger-boost", action="store_true", default=True,
        help="Enable danger-weighted seed scheduling (default: on)",
    )
    fuz.add_argument(
        "--no-danger-boost", dest="danger_boost", action="store_false",
        help="Disable danger-weighted seed scheduling",
    )
    fuz.add_argument(
        "--adaptive-coverage", action="store_true",
        help="Enable CEGAR-inspired adaptive coverage abstraction",
    )
    fuz.add_argument(
        "--adaptive-level", type=int, default=1, choices=range(5),
        help="Initial refinement level 0-4 (default: 1=coarse)",
    )
    fuz.add_argument(
        "--adaptive-upper-pct", type=float, default=5.0,
        help="Coarsen when corpus%% exceeds this threshold (default: 5.0)",
    )
    fuz.add_argument(
        "--adaptive-check-interval", type=int, default=5000,
        help="Check abstraction every N iterations (default: 5000)",
    )
    fuz.add_argument(
        "--target-coverage", action="store_true",
        help="Enable per-target code coverage collection (augments diff coverage with structural code paths)",
    )
    fuz.add_argument(
        "--verify-browser", action="store_true",
        help="Publish interesting inputs to a file queue for async browser verification",
    )
    fuz.add_argument(
        "--guidance", default=None, choices=["jwt", "saml"],
        help="Enable static-analysis guidance for mutation bias and finding attribution",
    )
    fuz.add_argument(
        "--guidance-profiles", type=Path, default=None,
        help="Directory with cached guidance profile JSONs (skip live analysis)",
    )
    fuz.add_argument(
        "--concolic", action="store_true", default=False,
        help="Enable concolic constraint extraction and solving (SAML only)",
    )
    fuz.add_argument(
        "--concolic-budget", type=float, default=0.10,
        help="Max fraction of iterations for concolic phase (default: 0.10)",
    )
    fuz.add_argument(
        "--concolic-mode", choices=["expert", "learned", "hybrid", "whitebox"],
        default="hybrid",
        help="Concolic mode: 'hybrid' (default), 'whitebox' (coverage-guided, no expert), 'expert' (v1), 'learned' (v2)",
    )

    # ── verify-browser subcommand ──────────────────────────────
    vb = sub.add_parser(
        "verify-browser",
        help="Browser verification: consume queue, re-parse in Chromium",
    )
    vb.add_argument(
        "-o", "--output-dir", type=Path, required=True,
        help="Session output directory (same as the fuzzer session)",
    )
    vb.add_argument(
        "--sanitizer", default="dompurify",
        choices=["dompurify", "jsxss", "sanitize-html"],
        help="Which sanitizer's browser module to use (default: dompurify)",
    )

    return parser



def make_registry(
    grammar_dir: Path | None = None, no_builtins: bool = False
) -> GrammarRegistry:
    """Create and populate a grammar registry."""
    registry = GrammarRegistry()

    if not no_builtins:
        registry.load_builtins()

    if grammar_dir:
        registry.load_directory(grammar_dir)

    return registry


def cmd_generate(args: argparse.Namespace) -> int:
    """Handle the 'generate' command."""
    registry = make_registry(args.grammar_dir, args.no_builtins)

    if args.grammar not in registry:
        print(f"Error: Grammar {args.grammar!r} not found.", file=sys.stderr)
        print(f"Available: {', '.join(registry.grammar_names)}", file=sys.stderr)
        return 1

    generator = Generator(
        registry, seed=args.seed, max_depth_override=args.max_depth
    )

    outputs: list[str] = []
    for i in range(args.count):
        try:
            result = generator.generate(args.grammar, args.rule)
            outputs.append(result)
        except GenerationError as e:
            print(f"Error generating #{i + 1}: {e}", file=sys.stderr)
            return 1

    text = args.separator.join(outputs)

    if args.output:
        # Preserve exact line endings for raw-wire grammars such as HRS streams.
        args.output.write_bytes(text.encode("utf-8"))
        print(f"Wrote {args.count} output(s) to {args.output}", file=sys.stderr)
    else:
        print(text)

    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """Handle the 'list' command."""
    registry = make_registry()

    if not registry.grammar_names:
        print("No grammars loaded.")
        return 0

    for name in registry.grammar_names:
        grammar = registry.get(name)
        if grammar is None:
            continue
        rule_count = len(grammar.rules)
        root = grammar.root or "(none)"
        print(f"  {name}")
        print(f"    Root: <{root}>")
        print(f"    Rules: {rule_count}")
        print(f"    Max depth: {grammar.max_depth}")
        if grammar.imports:
            print(f"    Imports: {', '.join(grammar.imports)}")
        print()

    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Handle the 'validate' command."""
    registry = make_registry(args.grammar_dir)

    errors = registry.validate_all()

    if errors:
        print(f"Found {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("All grammars valid.")
    return 0


def cmd_fuzz(args: argparse.Namespace) -> int:
    """Handle the 'fuzz' command."""
    from .fuzzer.engine import FuzzEngine
    from .fuzzer.grammar_source import GrammarInputSource

    # Apply campaign preset (overrides defaults, explicit flags still win)
    _campaign_mode = apply_campaign_preset(args)

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Build grammar registry
    registry = make_registry(
        getattr(args, "grammar_dir", None),
        getattr(args, "no_builtins", False),
    )

    if args.grammar not in registry:
        print(f"Error: Grammar {args.grammar!r} not found.", file=sys.stderr)
        print(f"Available: {', '.join(registry.grammar_names)}", file=sys.stderr)
        return 1

    requested_oracle_names = {n.strip() for n in args.oracle.split(",") if n.strip()}
    diff_cmds: list[str] = getattr(args, "diff_cmd", [])
    target_assembly = build_targets(
        args,
        requested_oracle_names=requested_oracle_names,
        to_persistent_cmd=to_persistent_cmd,
        persistent_timeout_for_cmd=persistent_timeout_for_cmd,
    )
    target = target_assembly.target
    reference_targets = target_assembly.reference_targets
    is_diff_mode = len(reference_targets) > 0
    if target_assembly.use_persistent and not getattr(args, "persistent", False):
        print("Auto-enabled persistent mode (mapping found)", file=sys.stderr)

    # Warn about synthetic/test targets in differential comparison.
    # These are NOT real libraries and will generate false positives.
    _SYNTHETIC_PATTERNS = ("_strict.", "_permissive.", "_pac4j_like.", "_manual.")
    all_cmds = [args.target_cmd] + diff_cmds
    synthetic_found = [
        cmd for cmd in all_cmds
        if any(pat in cmd for pat in _SYNTHETIC_PATTERNS)
    ]
    if synthetic_found and is_diff_mode:
        print(
            f"\n  ⚠ WARNING: {len(synthetic_found)} synthetic target(s) detected "
            f"in differential comparison.\n"
            f"  Findings involving these targets are likely FALSE POSITIVES:\n"
            + "".join(f"    → {cmd}\n" for cmd in synthetic_found)
            + "  Consider removing them from --diff-cmd for production runs.\n",
            file=sys.stderr,
        )

    # MCTS UCB table (shared between input source and grammar mutator)
    ucb_table = None
    if getattr(args, "mcts", False):
        from .fuzzer.mcts import UCBTable
        ucb_table = UCBTable(
            exploration_weight=getattr(args, "mcts_exploration", 1.41),
            seed=args.seed,
        )

    # Input source
    input_source = GrammarInputSource(
        registry, args.grammar, args.rule, seed=args.seed,
        ucb_table=ucb_table,
    )

    # Mutators
    mutators = build_mutators(
        args.mutators, registry, args.grammar, args.rule, args.seed,
        dict_file=getattr(args, "dict_file", None),
        ucb_table=ucb_table,
        max_assertions=getattr(args, "max_assertions", 0),
        campaign_mode=_campaign_mode,
    )

    # E4 FCA — startup-time strategy boost from Birkhoff atom coverage.
    lattice_atoms_path = getattr(args, "lattice_atoms", None)
    if lattice_atoms_path is not None:
        try:
            _atoms_payload = json.loads(
                Path(lattice_atoms_path).read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"Warning: failed to read --lattice-atoms {lattice_atoms_path}: "
                f"{exc}",
                file=sys.stderr,
            )
            _atoms_payload = None
        if _atoms_payload is not None:
            _atom_weights = _atoms_payload.get("weights") or {}
            if isinstance(_atom_weights, dict) and _atom_weights:
                from .fuzzer.protocols import LatticeAtomMutator
                _boosted = 0
                for m in mutators:
                    if isinstance(m, LatticeAtomMutator):
                        m.apply_lattice_atoms(_atom_weights)
                        _boosted += 1
                print(
                    f"[lattice-atoms] applied {len(_atom_weights)} strategy "
                    f"weights to {_boosted} mutator(s) from "
                    f"{lattice_atoms_path}",
                )

    # E7 differential-SFA — startup-time strategy boost from witness scores.
    automaton_witnesses_path = getattr(args, "automaton_witnesses", None)
    if automaton_witnesses_path is not None:
        try:
            _aw_payload = json.loads(
                Path(automaton_witnesses_path).read_text(encoding="utf-8"),
            )
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"Warning: failed to read --automaton-witnesses "
                f"{automaton_witnesses_path}: {exc}",
                file=sys.stderr,
            )
            _aw_payload = None
        if _aw_payload is not None:
            _aw_weights = _aw_payload.get("weights") or {}
            if isinstance(_aw_weights, dict) and _aw_weights:
                from .fuzzer.protocols import AutomatonWitnessMutator
                _aw_boosted = 0
                for m in mutators:
                    if isinstance(m, AutomatonWitnessMutator):
                        m.apply_automaton_witnesses(_aw_weights)
                        _aw_boosted += 1
                print(
                    f"[automaton-witnesses] applied {len(_aw_weights)} "
                    f"strategy weights to {_aw_boosted} mutator(s) from "
                    f"{automaton_witnesses_path}",
                )

    # Scheduler
    scheduler = build_seed_scheduler(args.scheduler, args.seed)

    # DG018 stopping signal — optional offline PAC phase signal that
    # tells the scheduler whether to operate in discovery or
    # exploitation mode (see EntropicScheduler.set_stopping_signal and
    # the external diffspace-research lint DG018 check).
    stopping_signal_path = getattr(args, "stopping_signal", None)
    if stopping_signal_path is not None:
        signal = _load_stopping_signal(stopping_signal_path)
        if signal is not None:
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
                    f"{type(scheduler).__name__} has no set_stopping_signal "
                    f"method; ignoring.",
                    file=sys.stderr,
                )

    # Mutator scheduler
    mutator_scheduler = build_mutator_scheduler(
        getattr(args, "mutator_scheduler", "random"),
        args.seed,
        alpha=getattr(args, "linucb_alpha", 1.0),
        weights=getattr(args, "mutator_weights", None),
    )

    # Oracles — auto-add DiffOracle in differential mode
    _DIFF_ONLY_ORACLES = {"sanitizer_diff", "markdown", "domclobber_diff", "sandbox", "request_smuggling", "waf_bypass", "pgwire"}
    diff_only_requested = requested_oracle_names & _DIFF_ONLY_ORACLES
    if diff_only_requested and not is_diff_mode:
        names = ", ".join(sorted(diff_only_requested))
        print(
            f"Error: --oracle {names} requires differential mode (--diff-cmd). "
            f"These oracles are placeholders that only work via DiffOracle with reference targets.",
            file=sys.stderr,
        )
        return 1

    oracles = build_oracles(args.oracle)
    has_sanitizer_diff = False
    diff_trace_sink: object | None = None
    feature_dump_sink: object | None = None
    if is_diff_mode:
        diff_setup = configure_differential_oracles(
            oracles=oracles,
            oracle_csv=args.oracle,
            reference_targets=reference_targets,
            trace_path=getattr(args, "diff_trace", None),
            feature_dump_path=getattr(args, "feature_dump", None),
        )
        oracles = diff_setup.oracles
        has_sanitizer_diff = diff_setup.has_sanitizer_diff
        diff_trace_sink = diff_setup.trace_sink
        feature_dump_sink = diff_setup.feature_sink
        if diff_trace_sink is not None:
            print(
                f"  Diff trace: appending pre-dedup JSONL to "
                f"{getattr(diff_trace_sink, 'path', '(unknown)')}",
                file=sys.stderr,
            )
        if feature_dump_sink is not None:
            print(
                f"  Feature dump: appending per-input JSONL to "
                f"{getattr(feature_dump_sink, 'path', '(unknown)')}",
                file=sys.stderr,
            )

    coverage = build_coverage(
        args,
        is_diff_mode=is_diff_mode,
        reference_targets=reference_targets,
        has_sanitizer_diff=has_sanitizer_diff,
    )

    # Danger-weighted seed scheduling
    from .fuzzer.schedulers.danger_booster import DangerBooster
    danger_booster = DangerBooster() if getattr(args, "danger_boost", True) else None

    # Static-analysis guidance (optional)
    guidance_hooks = None
    if getattr(args, "guidance", None):
        from .guidance.integration import build_guidance_engine, GuidanceFuzzHooks
        guidance_engine = build_guidance_engine(
            protocol=args.guidance,
            profile_dir=getattr(args, "guidance_profiles", None),
        )
        if guidance_engine:
            guidance_hooks = GuidanceFuzzHooks(guidance_engine)
            print(f"  Guidance: {args.guidance} — "
                  f"{guidance_engine.metrics.gaps_identified} gaps, "
                  f"{guidance_engine.metrics.targeted_seeds_generated} seeds",
                  file=sys.stderr)
        else:
            print(f"  Guidance: {args.guidance} — no libraries found, disabled",
                  file=sys.stderr)

    # Concolic constraint extraction + solving (optional, domain-agnostic)
    concolic_coordinator = None
    if getattr(args, "concolic", False):
        concolic_mode = getattr(args, "concolic_mode", "hybrid")
        budget = getattr(args, "concolic_budget", 0.10)

        # Auto-detect domain plugin from oracle/grammar
        domain_plugin = None
        from .fuzzer.concolic.plugins.registry import get_plugin
        oracle_name = getattr(args, "oracle", None)
        grammar_name = getattr(args, "grammar", None)
        domain_plugin = get_plugin(oracle=oracle_name, grammar=grammar_name)
        plugin_name = type(domain_plugin).__name__ if domain_plugin else "default(SAML)"

        if concolic_mode == "expert":
            from .fuzzer.concolic.coordinator import ConcolicCoordinator
            from .fuzzer.concolic.constraint_extractor import ConstraintExtractor
            from .fuzzer.concolic.solver import ConstraintSolver
            concolic_coordinator = ConcolicCoordinator(
                extractor=ConstraintExtractor(),
                solver=ConstraintSolver(seed=args.seed),
                budget_pct=budget,
            )
        elif concolic_mode == "learned":
            from .fuzzer.concolic.property_guided import PropertyGuidedCoordinator
            concolic_coordinator = PropertyGuidedCoordinator(
                budget_pct=budget,
                seed=args.seed,
            )
        elif concolic_mode == "whitebox":
            from .fuzzer.concolic.hybrid_coordinator import HybridCoordinator
            concolic_coordinator = HybridCoordinator(
                budget_pct=budget,
                seed=args.seed,
                use_expert=False,
                use_coverage=True,
                domain_plugin=domain_plugin,
            )
        else:  # hybrid (default)
            from .fuzzer.concolic.hybrid_coordinator import HybridCoordinator
            concolic_coordinator = HybridCoordinator(
                budget_pct=budget,
                seed=args.seed,
                domain_plugin=domain_plugin,
            )
        print(f"  Concolic: enabled (mode={concolic_mode}, plugin={plugin_name}, budget={budget:.0%})",
              file=sys.stderr)

    # Phase 2A: Birkhoff bitvector deduplicator (optional, off by default)
    dedup_atoms_path = getattr(args, "dedup_atoms", None)
    deduplicator = None
    if dedup_atoms_path is not None:
        try:
            import json as _json
            _dedup_raw = _json.loads(
                Path(dedup_atoms_path).read_text(encoding="utf-8"),
            )
            _atoms_list = _dedup_raw.get("atoms", [])
            if _atoms_list:
                from .fuzzer.dedup.structural_dedup import StructuralDeduplicator
                _sdedup = StructuralDeduplicator()
                _sdedup.set_atoms(_atoms_list)
                deduplicator = _sdedup
                print(
                    f"  Dedup: bitvector mode — {len(_atoms_list)} Birkhoff atoms "
                    f"from {dedup_atoms_path}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"Warning: --dedup-atoms {dedup_atoms_path} has no 'atoms' list; "
                    f"falling back to default dedup.",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(
                f"Warning: failed to load --dedup-atoms {dedup_atoms_path}: {exc}; "
                f"falling back to default dedup.",
                file=sys.stderr,
            )

    # Phase 2C: FCA implication soft oracle (optional, off by default)
    implication_base_path = getattr(args, "implication_base", None)
    if implication_base_path is not None:
        try:
            import json as _json
            _implications = _json.loads(
                Path(implication_base_path).read_text(encoding="utf-8"),
            )
            if isinstance(_implications, list) and _implications:
                from .fuzzer.oracles.implication_oracle import ImplicationSoftOracle
                # Wrap each oracle in the soft oracle; drain_violations is
                # called by the engine's post-check hook if present, otherwise
                # violations are silently buffered (no crash).
                oracles = [
                    ImplicationSoftOracle(o, _implications)
                    for o in oracles
                ]
                print(
                    f"  Implication oracle: {len(_implications)} conf=1.0 rules "
                    f"from {implication_base_path}",
                    file=sys.stderr,
                )
            else:
                print(
                    f"Warning: --implication-base {implication_base_path} is empty "
                    f"or not a list; implication oracle disabled.",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(
                f"Warning: failed to load --implication-base {implication_base_path}: "
                f"{exc}; implication oracle disabled.",
                file=sys.stderr,
            )

    # Build and run engine
    engine = FuzzEngine(
        target=target,
        input_source=input_source,
        mutators=mutators,
        oracles=oracles,
        coverage=coverage,
        seed_scheduler=scheduler,
        mutator_scheduler=mutator_scheduler,
        max_iterations=args.count,
        max_time_seconds=args.timeout,
        initial_seed_count=args.initial_seeds,
        seed=args.seed,
        output_dir=args.output_dir,
        reference_targets=reference_targets,
        seeds_dir=getattr(args, "seeds_dir", None),
        import_findings=getattr(args, "import_findings", None),
        resume=getattr(args, "resume", False),
        checkpoint_interval=getattr(args, "checkpoint_interval", 60.0),
        danger_booster=danger_booster,
        verify_browser=getattr(args, "verify_browser", False),
        max_corpus_size=getattr(args, "max_corpus_size", 5000),
        target_coverage=getattr(args, "target_coverage", False),
        guidance_hooks=guidance_hooks,
        concolic=concolic_coordinator,
        fixed_primary=_campaign_mode.startswith("waf_"),
        deduplicator=deduplicator,
    )

    print(f"Starting fuzzer: grammar={args.grammar}, target={args.target_cmd}",
          file=sys.stderr)
    if is_diff_mode:
        print(f"  Mode: DIFFERENTIAL ({len(reference_targets)} reference target(s))",
              file=sys.stderr)
        for i, cmd in enumerate(diff_cmds):
            print(f"    ref[{i}]: {cmd}", file=sys.stderr)
    print(f"  Mutators: {', '.join(m.name for m in mutators)}", file=sys.stderr)
    print(f"  Scheduler: {args.scheduler}", file=sys.stderr)
    print(f"  Mutator scheduler: {getattr(args, 'mutator_scheduler', 'random')}", file=sys.stderr)
    print(f"  Oracles: {', '.join(o.name for o in oracles)}", file=sys.stderr)
    if danger_booster:
        print(f"  Danger boost: enabled", file=sys.stderr)
    if getattr(args, "mcts", False):
        expl = getattr(args, "mcts_exploration", 1.41)
        print(f"  MCTS: enabled (c={expl})", file=sys.stderr)
    if getattr(args, "target_coverage", False):
        print(f"  Target coverage: enabled (V8/settrace)", file=sys.stderr)
    if getattr(args, "adaptive_coverage", False):
        lvl = getattr(args, "adaptive_level", 1)
        print(f"  Adaptive coverage: L{lvl} (CEGAR)", file=sys.stderr)
    print(f"  Initial seeds: {args.initial_seeds}", file=sys.stderr)
    if guidance_hooks and guidance_hooks.active:
        print(f"  Guidance: {args.guidance} (static analysis → mutation bias)", file=sys.stderr)
    if getattr(args, "seeds_dir", None):
        print(f"  Seeds dir: {args.seeds_dir}", file=sys.stderr)
    if getattr(args, "import_findings", None):
        print(f"  Import findings: {len(args.import_findings)} session dir(s)", file=sys.stderr)
    if getattr(args, "resume", False):
        print(f"  Resume: enabled (checkpoint interval: {getattr(args, 'checkpoint_interval', 60)}s)", file=sys.stderr)
    if args.count:
        print(f"  Max iterations: {args.count}", file=sys.stderr)
    if args.timeout:
        print(f"  Max time: {args.timeout}s", file=sys.stderr)
    print(file=sys.stderr)

    stats = engine.run()

    # Print deser compile/deserialize rates if available
    if hasattr(engine, '_deser_total') and engine._deser_total > 0:
        t = engine._deser_total
        c = engine._deser_compiled
        d = engine._deser_deserialized
        print(
            f"\n  Deser pipeline: {c}/{t} compiled ({c*100//t}%), "
            f"{d}/{t} deserialized ({d*100//t}%)",
            file=sys.stderr,
        )

    # Print guidance summary if active
    if guidance_hooks and guidance_hooks.active:
        report_section = guidance_hooks.get_report_section()
        if report_section:
            print(f"\n  Guidance summary:", file=sys.stderr)
            print(f"    Gaps: {report_section.get('total_gaps', 0)} "
                  f"(active: {report_section.get('active_gaps', 0)})",
                  file=sys.stderr)
            metrics = report_section.get("metrics", {})
            rt = metrics.get("runtime", {})
            print(f"    Findings attributed: {rt.get('findings_attributed', 0)}"
                  f"/{rt.get('findings_total', 0)}",
                  file=sys.stderr)
            if rt.get("focus_rotations", 0):
                print(f"    Focus rotations: {rt['focus_rotations']}", file=sys.stderr)

    # Print final report
    print(stats.report(), file=sys.stderr)

    # Close the diff trace sink, if any, so the JSONL file is fully flushed.
    if diff_trace_sink is not None:
        try:
            diff_trace_sink.close()
        except Exception:
            pass
    if feature_dump_sink is not None:
        try:
            feature_dump_sink.close()
        except Exception:
            pass

    return 0


def cmd_verify_browser(args: argparse.Namespace) -> int:
    """Run the async browser verifier."""
    from .fuzzer.browser_verifier import BrowserVerifier
    from .fuzzer.verification_queue import create_verification_queue

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_dir: Path = args.output_dir
    if not output_dir.exists():
        print(f"Output directory does not exist: {output_dir}", file=sys.stderr)
        return 1

    queue = create_verification_queue(output_dir)
    verifier = BrowserVerifier(
        queue=queue,
        output_dir=output_dir,
        sanitizer=args.sanitizer,
    )

    print(f"Starting browser verifier: sanitizer={args.sanitizer}, output={output_dir}",
          file=sys.stderr)
    print(f"  Queue dir: {output_dir / 'verify_queue'}", file=sys.stderr)
    print(f"  Watching for interesting inputs from JSDOM fuzzer...", file=sys.stderr)
    print(file=sys.stderr)

    verifier.run()
    return 0


def main() -> None:
    import atexit

    def _exit_diagnostics():
        """Log when the process exits — helps diagnose silent crashes."""
        try:
            import time as _time
            msg = f"[EXIT] Process exiting at {_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            sys.stderr.write(msg)
            sys.stderr.flush()
        except Exception:
            pass

    atexit.register(_exit_diagnostics)

    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "generate": cmd_generate,
        "list": cmd_list,
        "validate": cmd_validate,
        "fuzz": cmd_fuzz,
        "verify-browser": cmd_verify_browser,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    # Enable faulthandler so native crashes (e.g., Rust extension segfault)
    # dump a traceback to stderr instead of dying silently.
    import faulthandler
    faulthandler.enable()
    main()
