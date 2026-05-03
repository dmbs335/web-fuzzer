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
import logging
import sys
from pathlib import Path

from .app.campaigns import apply_campaign_preset
from .app.experimental_features import (
    build_guidance_hooks,
    build_targeted_mutation_coordinator,
)
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
from .app.research_hooks import (
    apply_mutator_research_hooks,
    apply_stopping_signal_hook,
    build_research_deduplicator,
    load_stopping_signal as _load_stopping_signal,
    wrap_implication_oracles,
)


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
        "--manifest-method",
        default=None,
        help="Override campaign_manifest.json method label for validation runs",
    )
    fuz.add_argument(
        "--manifest-condition",
        default=None,
        choices=["baseline", "candidate", "artifact-only", "feedback-only", "negative-control"],
        help="Override campaign_manifest.json validation condition",
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
        help="Append one JSONL row per differential oracle invocation. "
             "This is an experimental pre-dedup stream for offline analysis.",
    )
    fuz.add_argument(
        "--feature-dump", type=Path, default=None,
        help="Append one JSONL row per differential execution with input-side "
             "features (sha1, length, applied mutator strategies, divergence, "
             "diff_fields). This is an experimental offline-analysis feed.",
    )
    fuz.add_argument(
        "--lattice-atoms", type=Path, default=None,
        help="Experimental external-research hook: path to strategy atom "
             "weights. Matching mutator strategies get startup weight boosts.",
    )
    fuz.add_argument(
        "--automaton-witnesses", type=Path, default=None,
        help="Experimental external-research hook: path to disagreement "
             "witness weights. Matching mutator strategies get startup boosts.",
    )
    fuz.add_argument(
        "--stopping-signal", type=Path, default=None,
        help="Experimental external-research hook: path to a stopping-signal "
             "JSON file. Accepted payloads include either the full external "
             "analysis JSON or {phase, missing_mass_upper, n_samples}.",
    )
    fuz.add_argument(
        "--dedup-atoms", type=Path, default=None,
        help="Experimental external-research hook: path to a JSON file with "
             "an atoms list. Differential findings that hit the same atom "
             "subset share a coarse dedup key; non-overlapping findings fall "
             "back to the normal dedup path.",
    )
    fuz.add_argument(
        "--implication-base", type=Path, default=None,
        help="Experimental external-research hook: path to an implication "
             "base. Matching implication violations are written as INFO "
             "diagnostics to violations.jsonl.",
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
        help="Use persistent target mode when the target wrapper supports it",
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

    # Exploration strategy flags. Several are research-oriented heuristics;
    # see docs/methodology-status.md before making methodology claims.
    fuz.add_argument(
        "--mcts", action="store_true",
        help="Use experimental UCB1-guided grammar production selection",
    )
    fuz.add_argument(
        "--mcts-exploration", type=float, default=1.41,
        help="UCB1 exploration weight for --mcts (default: 1.41)",
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
        help="LinUCB exploration parameter for the experimental mutator scheduler (default: 1.0)",
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
        help="Enable experimental adaptive differential feature granularity",
    )
    fuz.add_argument(
        "--adaptive-level", type=int, default=1, choices=range(5),
        help="Initial refinement level 0-4 (default: 1=coarse)",
    )
    fuz.add_argument(
        "--adaptive-upper-pct", type=float, default=5.0,
        help="Refine when corpus%% exceeds this threshold (default: 5.0)",
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
        help="Enable experimental regex/AST guidance for mutation bias and finding attribution",
    )
    fuz.add_argument(
        "--guidance-profiles", type=Path, default=None,
        help="Directory with cached guidance profile JSONs (skip live analysis)",
    )
    fuz.add_argument(
        "--concolic", action="store_true", default=False,
        help="Enable experimental targeted mutation from constraints/properties/source hints",
    )
    fuz.add_argument(
        "--concolic-budget", type=float, default=0.10,
        help="Max fraction of iterations for concolic phase (default: 0.10)",
    )
    fuz.add_argument(
        "--concolic-mode", choices=["expert", "learned", "hybrid", "whitebox"],
        default="hybrid",
        help="Targeted-mutation mode: hybrid (default), whitebox, expert, or learned",
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
    from .fuzzer.campaign_manifest import (
        CampaignManifestInput,
        argv_to_cli,
        build_campaign_manifest,
    )
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

    # UCB table for experimental grammar production selection.
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

    apply_mutator_research_hooks(
        mutators=mutators,
        lattice_atoms_path=getattr(args, "lattice_atoms", None),
        automaton_witnesses_path=getattr(args, "automaton_witnesses", None),
    )

    # Scheduler
    scheduler = build_seed_scheduler(args.scheduler, args.seed)

    apply_stopping_signal_hook(
        scheduler=scheduler,
        stopping_signal_path=getattr(args, "stopping_signal", None),
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

    manifest_artifacts: dict[str, str] = {}
    if getattr(args, "diff_trace", None):
        manifest_artifacts["diff_trace"] = str(args.diff_trace)
    if getattr(args, "feature_dump", None):
        manifest_artifacts["feature_dump"] = str(args.feature_dump)
    manifest_options = {
        "scheduler": getattr(args, "scheduler", ""),
        "mutator_scheduler": getattr(args, "mutator_scheduler", "random"),
        "mcts": getattr(args, "mcts", False),
        "adaptive_coverage": getattr(args, "adaptive_coverage", False),
        "target_coverage": getattr(args, "target_coverage", False),
        "guidance": getattr(args, "guidance", None),
        "concolic": getattr(args, "concolic", False),
        "danger_boost": getattr(args, "danger_boost", True),
        "lattice_atoms": str(getattr(args, "lattice_atoms", "") or ""),
        "automaton_witnesses": str(getattr(args, "automaton_witnesses", "") or ""),
        "stopping_signal": str(getattr(args, "stopping_signal", "") or ""),
        "dedup_atoms": str(getattr(args, "dedup_atoms", "") or ""),
        "implication_base": str(getattr(args, "implication_base", "") or ""),
        "initial_seed_count": getattr(args, "initial_seeds", 0),
        "campaign": getattr(args, "campaign", None),
        "method": getattr(args, "manifest_method", None),
        "condition": getattr(args, "manifest_condition", None),
    }
    campaign_manifest = build_campaign_manifest(
        CampaignManifestInput(
            grammar=args.grammar,
            target_cmd=args.target_cmd,
            diff_cmds=tuple(diff_cmds),
            output_dir=args.output_dir,
            seed=args.seed,
            count=args.count,
            timeout=args.timeout,
            cli=argv_to_cli(),
            seeds_dir=getattr(args, "seeds_dir", None),
            artifacts=manifest_artifacts,
            options=manifest_options,
        )
    )

    # Danger-weighted seed scheduling
    from .fuzzer.schedulers.danger_booster import DangerBooster
    danger_booster = DangerBooster() if getattr(args, "danger_boost", True) else None

    guidance_hooks = build_guidance_hooks(
        protocol=getattr(args, "guidance", None),
        profile_dir=getattr(args, "guidance_profiles", None),
    )
    concolic_coordinator = build_targeted_mutation_coordinator(
        enabled=getattr(args, "concolic", False),
        mode=getattr(args, "concolic_mode", "hybrid"),
        budget=getattr(args, "concolic_budget", 0.10),
        seed=args.seed,
        oracle=getattr(args, "oracle", None),
        grammar=getattr(args, "grammar", None),
    )
    deduplicator = build_research_deduplicator(
        getattr(args, "dedup_atoms", None),
    )
    oracles = wrap_implication_oracles(
        oracles,
        getattr(args, "implication_base", None),
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
        campaign_manifest=campaign_manifest,
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
        print(f"  UCB grammar selection: enabled (c={expl})", file=sys.stderr)
    if getattr(args, "target_coverage", False):
        print(f"  Target coverage: enabled (V8/settrace)", file=sys.stderr)
    if getattr(args, "adaptive_coverage", False):
        lvl = getattr(args, "adaptive_level", 1)
        print(f"  Adaptive coverage: L{lvl} (experimental)", file=sys.stderr)
    print(f"  Initial seeds: {args.initial_seeds}", file=sys.stderr)
    if guidance_hooks and guidance_hooks.active:
        print(f"  Guidance: {args.guidance} (experimental mutation bias)", file=sys.stderr)
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
