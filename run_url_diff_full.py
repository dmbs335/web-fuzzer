"""URL Differential Fuzzing — Full 9-target session.

Launches differential fuzzing across all available URL parsers:
  Primary:    Python urllib.parse (baseline, lenient RFC 3986)
  Reference:  8 other parsers from different ecosystems

Targets:
  1. Python urllib.parse       — baseline (primary target)
  2. Python rfc3986            — strict RFC 3986
  3. Node new URL() (WHATWG)   — browser standard
  4. Node url.parse() (legacy) — legacy Node.js
  5. curl (libcurl)            — PHP SSRF request side
  6. Go net/url.Parse()        — Go ecosystem
  7. Java java.net.URI         — strict, Log4Shell relevant
  8. Java java.net.URL         — lenient, SSRF relevant
  9. Rust url crate            — another WHATWG implementation

Optional (if runtime installed):
  - PHP parse_url()            — SSRF core target
  - C# System.Uri             — .NET ecosystem
  - wget                      — CLI comparison

Usage:
  python run_url_diff_full.py [--time SECONDS] [--count N] [--output-dir DIR]
"""

import argparse
import shutil
import sys
from pathlib import Path

from webfuzzer.core.registry import GrammarRegistry
from webfuzzer.fuzzer.coverage.diff_coverage import DiffCoverageCollector
from webfuzzer.fuzzer.engine import FuzzEngine
from webfuzzer.fuzzer.grammar_source import GrammarInputSource
from webfuzzer.fuzzer.mutators.grammar_mutator import GrammarMutator
from webfuzzer.fuzzer.mutators.havoc_mutator import HavocMutator
from webfuzzer.fuzzer.oracles.diff_oracle import DiffOracle
from webfuzzer.fuzzer.oracles.ssrf_oracle import get_ssrf_strategies
from webfuzzer.fuzzer.schedulers.entropic import EntropicScheduler
from webfuzzer.fuzzer.targets.persistent_target import PersistentTarget
from webfuzzer.fuzzer.targets.process_target import ProcessTarget

TARGETS_DIR = Path("targets")

# ── Target definitions ──────────────────────────────────────────
# Each entry: (name, cmd_type, command)
#   cmd_type: "persistent" | "process"
#   For persistent: command is passed directly to PersistentTarget
#   For process:    command uses {input} placeholder for ProcessTarget

CORE_TARGETS = [
    # Primary target (index 0)
    ("python-urllib", "persistent",
     "python targets/persistent_wrapper.py targets/url_python_urllib_module.py"),

    # Reference targets
    ("python-rfc3986", "persistent",
     "python targets/persistent_wrapper.py targets/url_python_rfc3986_module.py"),
    ("node-whatwg", "persistent",
     "node targets/persistent_wrapper.js targets/url_node_whatwg_module.js"),
    ("node-legacy", "persistent",
     "node targets/persistent_wrapper.js targets/url_node_legacy_module.js"),
    ("curl", "persistent",
     "python targets/persistent_wrapper.py targets/url_curl_module.py"),
    ("go-net-url", "process",
     "targets/url_go_net_url/url_go_net_url.exe {input}"),
    ("java-uri", "persistent",
     "java -cp targets/url_java_uri UrlJavaUri --persistent"),
    ("java-url", "persistent",
     "java -cp targets/url_java_url UrlJavaUrl --persistent"),
    ("rust-url", "process",
     "targets/url_rust_url/target/release/url_rust_url.exe {input}"),
]

# Optional targets — only added if runtime is available
OPTIONAL_TARGETS = [
    ("php-parse-url", "process", "php targets/url_php_parse_url.php {input}",
     "php"),
    ("dotnet-uri", "process", "targets/url_dotnet_uri/bin/url_dotnet_uri.exe {input}",
     "dotnet"),
    ("wget", "persistent", "python targets/persistent_wrapper.py targets/url_wget_module.py",
     "wget"),
]


def _check_runtime(name: str) -> bool:
    """Check if a runtime is available on PATH."""
    return shutil.which(name) is not None


def _check_binary(path: str) -> bool:
    """Check if a compiled binary exists."""
    return Path(path).exists()


def build_targets() -> tuple[object, list[object], list[str]]:
    """Build primary target and reference target list.

    Returns (primary_target, reference_targets, target_names).
    """
    targets = []
    names = []

    for name, cmd_type, cmd in CORE_TARGETS:
        # Check binary existence for process targets
        if cmd_type == "process":
            binary_path = cmd.split(" {input}")[0].strip()
            if not _check_binary(binary_path):
                print(f"  SKIP {name}: binary not found at {binary_path}",
                      file=sys.stderr)
                continue

        if cmd_type == "persistent":
            t = PersistentTarget(cmd, timeout_seconds=10.0,
                                 working_dir=Path("."))
        else:
            t = ProcessTarget(cmd, timeout_seconds=10.0,
                              working_dir=Path("."))
        targets.append(t)
        names.append(name)

    # Optional targets
    for name, cmd_type, cmd, runtime in OPTIONAL_TARGETS:
        if not _check_runtime(runtime):
            print(f"  SKIP {name}: {runtime} not found", file=sys.stderr)
            continue
        if cmd_type == "process" and "{input}" in cmd:
            binary_path = cmd.split(" {input}")[0].strip()
            if not _check_binary(binary_path) and runtime != "php":
                print(f"  SKIP {name}: binary not found", file=sys.stderr)
                continue

        if cmd_type == "persistent":
            t = PersistentTarget(cmd, timeout_seconds=10.0,
                                 working_dir=Path("."))
        else:
            t = ProcessTarget(cmd, timeout_seconds=10.0,
                              working_dir=Path("."))
        targets.append(t)
        names.append(name)

    if len(targets) < 2:
        print("ERROR: Need at least 2 targets for differential fuzzing",
              file=sys.stderr)
        sys.exit(1)

    primary = targets[0]
    references = targets[1:]

    print(f"\nTargets ({len(targets)} total):")
    print(f"  Primary:    {names[0]}")
    for n in names[1:]:
        print(f"  Reference:  {n}")
    print()

    return primary, references, names


def main():
    parser = argparse.ArgumentParser(
        description="URL Differential Fuzzing — Full multi-parser session")
    parser.add_argument("--time", type=float, default=3600,
                        help="Max fuzzing time in seconds (default: 3600)")
    parser.add_argument("--count", type=int, default=0,
                        help="Max iterations (0=unlimited)")
    parser.add_argument("--output-dir", type=str,
                        default="results/url_diff_full",
                        help="Output directory")
    parser.add_argument("--seed", type=int, default=None,
                        help="Random seed for reproducibility")
    parser.add_argument("--initial-seeds", type=int, default=200,
                        help="Number of initial grammar seeds")
    args = parser.parse_args()

    seed = args.seed

    # Build targets
    print("Building targets...")
    primary, references, names = build_targets()

    # Grammar
    registry = GrammarRegistry()
    registry.load_builtins()
    input_source = GrammarInputSource(registry, "uri", seed=seed)

    # Mutators
    mutators = [
        GrammarMutator(registry, "uri", seed=seed),
        HavocMutator(seed=seed),
    ]

    # Scheduler
    scheduler = EntropicScheduler(seed=seed)

    # Oracle — SSRF-aware differential strategy
    strategies = get_ssrf_strategies()
    diff_oracle = DiffOracle(
        reference_targets=references,
        strategies=strategies,
    )

    # Coverage
    coverage = DiffCoverageCollector(reference_targets=references)

    # Output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Engine
    engine = FuzzEngine(
        target=primary,
        input_source=input_source,
        mutators=mutators,
        oracles=[diff_oracle],
        coverage=coverage,
        seed_scheduler=scheduler,
        max_iterations=args.count,
        max_time_seconds=args.time,
        initial_seed_count=args.initial_seeds,
        seed=seed,
        output_dir=output_dir,
        reference_targets=references,
    )

    print(f"Starting URL differential fuzzing...")
    print(f"  Grammar:     uri")
    print(f"  Oracle:      SSRF differential")
    print(f"  Time limit:  {args.time}s")
    print(f"  Output:      {output_dir}")
    print()

    stats = engine.run()
    print("\n" + stats.report())


if __name__ == "__main__":
    main()
