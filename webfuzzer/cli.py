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

from .core.generator import Generator, GenerationError
from .core.registry import GrammarRegistry, RegistryError


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
        help="Comma-separated mutator list (grammar,havoc,token,splice,dictionary,mxss,structural,saml,cookie)",
    )
    fuz.add_argument(
        "--scheduler", default="entropic",
        help="Seed scheduler (random,entropic,ecofuzz,rare-branch,map-elites)",
    )
    fuz.add_argument(
        "--oracle", default="crash,sanitizer",
        help="Comma-separated oracle list (crash,response,sanitizer,xss,mxss,ssrf,saml,cookie,sanitizer_diff)",
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
        "--dict-file", type=Path, default=None,
        help="Dictionary file for dictionary mutator (one token per line)",
    )
    fuz.add_argument(
        "--seeds-dir", type=Path, default=None,
        help="Directory of seed files to load into initial corpus",
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
        "--linucb-alpha", type=float, default=1.0,
        help="LinUCB exploration parameter (default: 1.0)",
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

    return parser


# ── Persistent target helpers ────────────────────────────────────

# Maps subprocess target scripts to their persistent module equivalents
# Value format: (wrapper_cmd, module_path)
_PERSISTENT_MODULE_MAP = {
    "targets/sanitizer_dompurify.js": ("node targets/persistent_wrapper.js", "targets/sanitizer_dompurify_module.js"),
    "targets/sanitizer_sanitize_html.js": ("node targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_module.js"),
    "targets/sanitizer_jsxss.js": ("node targets/persistent_wrapper.js", "targets/sanitizer_jsxss_module.js"),
    "targets/sanitizer_dompurify_mxss.js": ("node targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_module.js"),
    # Sanitizer differential targets
    "targets/sanitizer_dompurify_diff.js": ("node targets/persistent_wrapper.js", "targets/sanitizer_dompurify_diff_module.js"),
    "targets/sanitizer_sanitize_html_diff.js": ("node targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_diff_module.js"),
    "targets/sanitizer_jsxss_diff.js": ("node targets/persistent_wrapper.js", "targets/sanitizer_jsxss_diff_module.js"),
    "targets/url_node_whatwg.js": ("node targets/persistent_wrapper.js", "targets/url_node_whatwg_module.js"),
    "targets/url_node_legacy.js": ("node targets/persistent_wrapper.js", "targets/url_node_legacy_module.js"),
    "targets/url_python_urllib.py": ("python targets/persistent_wrapper.py", "targets/url_python_urllib_module.py"),
    "targets/url_python_rfc3986.py": ("python targets/persistent_wrapper.py", "targets/url_python_rfc3986_module.py"),
    # New URL parser targets
    "targets/url_curl.py": ("python targets/persistent_wrapper.py", "targets/url_curl_module.py"),
    "targets/url_php_parse_url.php": ("python targets/persistent_wrapper.py", "targets/url_php_parse_url_module.py"),
    "targets/url_wget.py": ("python targets/persistent_wrapper.py", "targets/url_wget_module.py"),
    # SAML targets
    "targets/saml_xmlcrypto.js": ("node targets/persistent_wrapper.js", "targets/saml_xmlcrypto_module.js"),
    "targets/saml_samlify.js": ("node targets/persistent_wrapper.js", "targets/saml_samlify_module.js"),
    "targets/saml_nodesaml.js": ("node targets/persistent_wrapper.js", "targets/saml_nodesaml_module.js"),
    "targets/saml_signxml.py": ("python targets/persistent_wrapper.py", "targets/saml_signxml_module.py"),
    "targets/saml_python3saml.py": ("python targets/persistent_wrapper.py", "targets/saml_python3saml_module.py"),
    "targets/saml_rubysaml.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/saml_rubysaml_module.rb"),
    "targets/saml_phpsaml.php": ("C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe targets/persistent_wrapper.php", "targets/saml_phpsaml_module.php"),
    # Multi-language sanitizer differential targets
    "targets/sanitizer_bleach_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_bleach_diff_module.py"),
    "targets/sanitizer_nh3_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_nh3_diff_module.py"),
    "targets/sanitizer_lxml_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_lxml_diff_module.py"),
    "targets/sanitizer_sanitize_diff.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/sanitizer_sanitize_diff_module.rb"),
    "targets/sanitizer_loofah_diff.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/sanitizer_loofah_diff_module.rb"),
    "targets/sanitizer_htmlpurifier_diff.php": ("C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe targets/persistent_wrapper.php", "targets/sanitizer_htmlpurifier_diff_module.php"),
    # Cookie targets
    "targets/cookie_python_stdlib.py": ("python targets/persistent_wrapper.py", "targets/cookie_python_stdlib_module.py"),
    "targets/cookie_node_setcookieparser.js": ("node targets/persistent_wrapper.js", "targets/cookie_node_setcookieparser_module.js"),
    "targets/cookie_node_toughcookie.js": ("node targets/persistent_wrapper.js", "targets/cookie_node_toughcookie_module.js"),
    "targets/cookie_node_cookie.js": ("node targets/persistent_wrapper.js", "targets/cookie_node_cookie_module.js"),
    "targets/cookie_ruby_webrick.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/cookie_ruby_webrick_module.rb"),
}

# Targets with native persistent mode (binary protocol, no wrapper needed).
# Command format for PersistentTarget: the command itself runs the binary protocol loop.
_NATIVE_PERSISTENT_MAP = {
    "java -cp targets/url_java_uri UrlJavaUri": "java -cp targets/url_java_uri UrlJavaUri --persistent",
    "java -cp targets/url_java_url UrlJavaUrl": "java -cp targets/url_java_url UrlJavaUrl --persistent",
    "targets/url_go_neturl/url_go_neturl.exe": "targets/url_go_neturl/url_go_neturl.exe --persistent",
    "targets/url_go_neturl/url_go_neturl": "targets/url_go_neturl/url_go_neturl --persistent",
    "targets/url_go_net_url/url_go_net_url.exe": "targets/url_go_net_url/url_go_net_url.exe --persistent",
    "targets/url_go_net_url/url_go_net_url": "targets/url_go_net_url/url_go_net_url --persistent",
    "targets/url_rust_url/target/release/url_rust_url.exe": "targets/url_rust_url/target/release/url_rust_url.exe --persistent",
    "targets/url_rust_url/target/release/url_rust_url": "targets/url_rust_url/target/release/url_rust_url --persistent",
    # Python wrapper maps to Go binary persistent mode
    "python targets/url_go_neturl.py": "targets/url_go_neturl/url_go_neturl.exe --persistent",
    # SAML Go target (crewjam/saml)
    "targets/saml_crewjam/saml_crewjam.exe": "targets/saml_crewjam/saml_crewjam.exe --persistent",
    "targets/saml_crewjam/saml_crewjam": "targets/saml_crewjam/saml_crewjam --persistent",
    # SAML Java target (JDK javax.xml.crypto / Xerces)
    "java -cp targets/saml_java_xmldsig SamlJavaXmldsig": "java -cp targets/saml_java_xmldsig SamlJavaXmldsig --persistent",
    # SAML Rust target (quick-xml parser)
    "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser.exe": "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser.exe --persistent",
    "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser": "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser --persistent",
    # Multi-language sanitizer (native binary protocol, no args = persistent)
    "targets/sanitizer_bluemonday.exe": "targets/sanitizer_bluemonday.exe",
    "targets/sanitizer_ammonia.exe": "targets/sanitizer_ammonia.exe",
    "targets/rust-sanitizer/target/release/sanitizer_ammonia.exe": "targets/rust-sanitizer/target/release/sanitizer_ammonia.exe",
}


def _to_persistent_cmd(cmd: str) -> str | None:
    """Convert a subprocess target command to a persistent wrapper command.

    Returns None if no persistent mapping exists (caller should fall back
    to ProcessTarget).

    Example:
        "node targets/sanitizer_dompurify.js {input}"
        -> "node targets/persistent_wrapper.js targets/sanitizer_dompurify_module.js"
        "python targets/url_python_urllib.py {input}"
        -> "python targets/persistent_wrapper.py targets/url_python_urllib_module.py"
        "java -cp targets/url_java_uri UrlJavaUri {input}"
        -> "java -cp targets/url_java_uri UrlJavaUri --persistent"
    """
    # Check native persistent mode first (e.g., Java targets with --persistent flag)
    base_cmd = cmd.replace(" {input}", "").strip()
    if base_cmd in _NATIVE_PERSISTENT_MAP:
        result = _NATIVE_PERSISTENT_MAP[base_cmd]
        # Windows cmd.exe needs backslashes for relative executable paths
        if sys.platform == "win32":
            result = result.replace("/", "\\")
        return result

    for script, (wrapper, module) in _PERSISTENT_MODULE_MAP.items():
        if script in cmd:
            return f"{wrapper} {module}"
    # No mapping found — caller should fall back to ProcessTarget
    print(f"Warning: no persistent module mapping for: {cmd}", file=sys.stderr)
    return None


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
        args.output.write_text(text, encoding="utf-8")
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


def _build_mutators(names: str, registry: GrammarRegistry,
                     grammar_name: str, rule: str | None,
                     seed: int | None,
                     dict_file: Path | None = None,
                     ucb_table=None) -> list:
    """Instantiate mutators from comma-separated names."""
    from .fuzzer.mutators.grammar_mutator import GrammarMutator
    from .fuzzer.mutators.havoc_mutator import HavocMutator
    from .fuzzer.mutators.token_mutator import TokenMutator
    from .fuzzer.mutators.splice_mutator import SpliceMutator
    from .fuzzer.mutators.dictionary_mutator import DictionaryMutator
    from .fuzzer.mutators.mxss_mutator import MxssMutator
    from .fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator
    from .fuzzer.mutators.saml_mutator import SamlMutator
    from .fuzzer.mutators.cookie_mutator import CookieMutator

    MUTATOR_MAP = {
        "grammar": lambda: GrammarMutator(registry, grammar_name, rule, seed=seed, ucb_table=ucb_table),
        "havoc": lambda: HavocMutator(seed=seed),
        "token": lambda: TokenMutator(seed=seed),
        "splice": lambda: SpliceMutator(seed=seed),
        "dictionary": lambda: DictionaryMutator(seed=seed, dict_file=dict_file),
        "mxss": lambda: MxssMutator(seed=seed),
        "structural": lambda: StructuralHavocMutator(seed=seed),
        "saml": lambda: SamlMutator(seed=seed),
        "cookie": lambda: CookieMutator(seed=seed),
    }

    mutators = []
    for name in names.split(","):
        name = name.strip()
        if name in MUTATOR_MAP:
            mutators.append(MUTATOR_MAP[name]())
        else:
            print(f"Warning: Unknown mutator {name!r}, skipping.", file=sys.stderr)

    if not mutators:
        mutators.append(HavocMutator(seed=seed))

    return mutators


def _build_scheduler(name: str, seed: int | None):
    """Instantiate a seed scheduler by name."""
    from .fuzzer.schedulers.random_scheduler import RandomSeedScheduler
    from .fuzzer.schedulers.entropic import EntropicScheduler
    from .fuzzer.schedulers.ecofuzz import EcoFuzzScheduler
    from .fuzzer.schedulers.rare_branch import RareBranchScheduler

    SCHEDULER_MAP = {
        "random": lambda: RandomSeedScheduler(seed=seed),
        "entropic": lambda: EntropicScheduler(seed=seed),
        "ecofuzz": lambda: EcoFuzzScheduler(seed=seed),
        "rare-branch": lambda: RareBranchScheduler(seed=seed),
    }

    # MAP-Elites: compose with Entropic as primary.
    if name == "map-elites":
        from .fuzzer.schedulers.map_elites import MapElitesScheduler
        from .fuzzer.schedulers.composite import CompositeScheduler
        return CompositeScheduler(
            primary=EntropicScheduler(seed=seed),
            secondary=MapElitesScheduler(seed=seed),
            p_secondary=0.3,
            seed=seed,
        )

    factory = SCHEDULER_MAP.get(name)
    if factory is None:
        print(f"Warning: Unknown scheduler {name!r}, using entropic.", file=sys.stderr)
        return EntropicScheduler(seed=seed)
    return factory()


def _build_mutator_scheduler(name: str, seed: int | None, **kwargs):
    """Instantiate a mutator scheduler by name."""
    if name == "random":
        return None  # engine uses _DefaultMutatorScheduler

    from .fuzzer.schedulers.mutation_scheduler import MOPTScheduler, DARWINScheduler
    from .fuzzer.schedulers.linucb_scheduler import LinUCBScheduler

    MUTATOR_SCHEDULER_MAP = {
        "mopt": lambda: MOPTScheduler(seed=seed),
        "darwin": lambda: DARWINScheduler(seed=seed),
        "linucb": lambda: LinUCBScheduler(
            alpha=kwargs.get("alpha", 1.0), seed=seed,
        ),
    }

    factory = MUTATOR_SCHEDULER_MAP.get(name)
    if factory is None:
        print(f"Warning: Unknown mutator scheduler {name!r}, using random.", file=sys.stderr)
        return None
    return factory()


def _build_oracles(names: str) -> list:
    """Instantiate oracles from comma-separated names."""
    from .fuzzer.oracles.crash_oracle import CrashOracle
    from .fuzzer.oracles.response_oracle import ResponseOracle
    from .fuzzer.oracles.sanitizer_oracle import SanitizerOracle
    from .fuzzer.oracles.xss_oracle import XssOracle
    from .fuzzer.oracles.mxss_oracle import MxssOracle
    from .fuzzer.oracles.ssrf_oracle import SsrfOracle
    from .fuzzer.oracles.saml_oracle import SamlOracle
    from .fuzzer.oracles.cookie_oracle import CookieOracle

    ORACLE_MAP = {
        "crash": lambda: CrashOracle(),
        "response": lambda: ResponseOracle(),
        "sanitizer": lambda: SanitizerOracle(),
        "xss": lambda: XssOracle(),
        "mxss": lambda: MxssOracle(),
        "ssrf": lambda: SsrfOracle(),
        "saml": lambda: SamlOracle(),
        "cookie": lambda: CookieOracle(),
        "sanitizer_diff": lambda: None,  # placeholder — strategies injected via DiffOracle
    }

    oracles = []
    for name in names.split(","):
        name = name.strip()
        if name in ORACLE_MAP:
            oracles.append(ORACLE_MAP[name]())
        else:
            print(f"Warning: Unknown oracle {name!r}, skipping.", file=sys.stderr)

    if not oracles:
        oracles.append(CrashOracle())

    return oracles


def cmd_fuzz(args: argparse.Namespace) -> int:
    """Handle the 'fuzz' command."""
    from .fuzzer.engine import FuzzEngine
    from .fuzzer.grammar_source import GrammarInputSource
    from .fuzzer.targets.process_target import ProcessTarget
    from .fuzzer.coverage.response_coverage import ResponseCoverageCollector
    from .fuzzer.coverage.diff_coverage import DiffCoverageCollector
    from .fuzzer.oracles.diff_oracle import DiffOracle

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

    # Target — supports mixed mode: PersistentTarget for mapped targets,
    # ProcessTarget fallback for unmapped ones.
    use_persistent = getattr(args, "persistent", False)
    if use_persistent:
        from .fuzzer.targets.persistent_target import PersistentTarget
        pcmd = _to_persistent_cmd(args.target_cmd)
        if pcmd is not None:
            target = PersistentTarget(pcmd, timeout_seconds=0.5)
        else:
            target = ProcessTarget(args.target_cmd)
    else:
        target = ProcessTarget(args.target_cmd)

    # Reference targets for differential fuzzing
    diff_cmds: list[str] = getattr(args, "diff_cmd", [])
    if use_persistent:
        from .fuzzer.targets.persistent_target import PersistentTarget
        reference_targets = []
        for cmd in diff_cmds:
            pcmd = _to_persistent_cmd(cmd)
            if pcmd is not None:
                reference_targets.append(PersistentTarget(pcmd, timeout_seconds=0.5))
            else:
                reference_targets.append(ProcessTarget(cmd))
    else:
        reference_targets = [ProcessTarget(cmd) for cmd in diff_cmds]
    is_diff_mode = len(reference_targets) > 0

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
    mutators = _build_mutators(
        args.mutators, registry, args.grammar, args.rule, args.seed,
        dict_file=getattr(args, "dict_file", None),
        ucb_table=ucb_table,
    )

    # Scheduler
    scheduler = _build_scheduler(args.scheduler, args.seed)

    # Mutator scheduler
    mutator_scheduler = _build_mutator_scheduler(
        getattr(args, "mutator_scheduler", "random"),
        args.seed,
        alpha=getattr(args, "linucb_alpha", 1.0),
    )

    # Oracles — auto-add DiffOracle in differential mode
    oracles = _build_oracles(args.oracle)
    if is_diff_mode:
        # Use domain-specific strategies when specialized oracles are active
        has_xss = any(getattr(o, "name", "") == "xss" for o in oracles)
        has_ssrf = any(getattr(o, "name", "") == "ssrf" for o in oracles)
        has_saml = any(getattr(o, "name", "") == "saml" for o in oracles)
        has_cookie = any(getattr(o, "name", "") == "cookie" for o in oracles)
        has_sanitizer_diff = any(o is None for o in oracles)  # sanitizer_diff placeholder
        # Remove None placeholders from oracle list
        oracles = [o for o in oracles if o is not None]
        if has_sanitizer_diff:
            from .fuzzer.oracles.sanitizer_diff_strategy import get_sanitizer_strategies
            strategies = get_sanitizer_strategies()
        elif has_saml:
            from .fuzzer.oracles.saml_diff_strategy import get_saml_strategies
            strategies = get_saml_strategies()
        elif has_cookie:
            from .fuzzer.oracles.cookie_diff_strategy import get_cookie_strategies
            strategies = get_cookie_strategies()
        elif has_ssrf:
            from .fuzzer.oracles.ssrf_oracle import get_ssrf_strategies
            strategies = get_ssrf_strategies()
        elif has_xss:
            from .fuzzer.oracles.diff_oracle import get_xss_strategies
            strategies = get_xss_strategies()
        else:
            strategies = None  # use defaults
        oracles.append(DiffOracle(
            reference_targets=reference_targets,
            strategies=strategies,
        ))

    # Coverage — use DiffCoverageCollector in differential mode
    if is_diff_mode:
        if getattr(args, "adaptive_coverage", False):
            from .fuzzer.coverage.adaptive_coverage import (
                AdaptiveDiffCoverage, AdaptiveConfig, RefinementLevel,
            )
            # Sanitizer domain: start at L2 with faster refinement
            # (boolean comparison_keys saturate L1 quickly)
            if has_sanitizer_diff:
                adaptive_config = AdaptiveConfig(
                    initial_level=RefinementLevel.L2_COMPONENT,
                    stagnation_window=5000,
                    check_interval=getattr(args, "adaptive_check_interval", 5000),
                    upper_corpus_pct=getattr(args, "adaptive_upper_pct", 5.0),
                )
            else:
                adaptive_config = AdaptiveConfig(
                    initial_level=RefinementLevel(getattr(args, "adaptive_level", 1)),
                    check_interval=getattr(args, "adaptive_check_interval", 5000),
                    upper_corpus_pct=getattr(args, "adaptive_upper_pct", 5.0),
                )
            coverage = AdaptiveDiffCoverage(
                reference_targets=reference_targets,
                config=adaptive_config,
            )
        else:
            coverage = DiffCoverageCollector(reference_targets=reference_targets)
    else:
        coverage = ResponseCoverageCollector()

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
    if getattr(args, "mcts", False):
        expl = getattr(args, "mcts_exploration", 1.41)
        print(f"  MCTS: enabled (c={expl})", file=sys.stderr)
    if getattr(args, "adaptive_coverage", False):
        lvl = getattr(args, "adaptive_level", 1)
        print(f"  Adaptive coverage: L{lvl} (CEGAR)", file=sys.stderr)
    print(f"  Initial seeds: {args.initial_seeds}", file=sys.stderr)
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

    # Print final report
    print(stats.report(), file=sys.stderr)
    return 0


def main() -> None:
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
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
