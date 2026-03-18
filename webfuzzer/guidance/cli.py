"""CLI for the guidance system.

Usage:
    python -m webfuzzer.guidance analyze --protocol jwt
    python -m webfuzzer.guidance analyze --protocol saml
    python -m webfuzzer.guidance analyze --protocol jwt --library pyjwt
    python -m webfuzzer.guidance summary --protocol jwt
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from webfuzzer.guidance.spec import ProtocolSpec
from webfuzzer.guidance.profile import GuidanceProfile
from webfuzzer.guidance.engine import GuidanceEngine
from webfuzzer.guidance.analyzers.python_analyzer import (
    PythonAnalyzer,
    JWT_PYTHON_LIBRARIES,
    SAML_PYTHON_LIBRARIES,
)
from webfuzzer.guidance.analyzers.base import LibraryTarget


def _get_libraries(protocol: str, library: str | None) -> list[LibraryTarget]:
    """Get library targets for a protocol, optionally filtered."""
    if protocol == "jwt":
        libs = JWT_PYTHON_LIBRARIES
    elif protocol == "saml":
        libs = SAML_PYTHON_LIBRARIES
    else:
        print(f"Unknown protocol: {protocol}", file=sys.stderr)
        sys.exit(1)

    if library:
        libs = [lib for lib in libs if lib.name == library]
        if not libs:
            print(f"Unknown library: {library}", file=sys.stderr)
            sys.exit(1)

    return libs


def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyze libraries and produce GuidanceProfiles."""
    spec = ProtocolSpec.load_builtin(args.protocol)
    analyzer = PythonAnalyzer(spec)
    libraries = _get_libraries(args.protocol, args.library)

    profiles: list[GuidanceProfile] = []
    output_dir = Path(args.output) if args.output else None

    for lib_target in libraries:
        print(f"Analyzing {lib_target.name}...", end=" ", flush=True)
        profile = analyzer.analyze(lib_target)
        if profile is None:
            print("SKIP (not installed)")
            continue

        found, total = profile.checkpoint_score
        missing = profile.missing_checkpoints
        print(f"{found}/{total} checkpoints", end="")
        if missing:
            print(f"  MISSING: {', '.join(missing)}", end="")
        if profile.conditional_bypasses > 0:
            print(f"  BYPASSES: {profile.conditional_bypasses}", end="")
        print()

        profiles.append(profile)

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            path = output_dir / f"{lib_target.name}.json"
            profile.save(path)
            print(f"  → saved to {path}")

    if not profiles:
        print("No libraries found to analyze.")
        return 1

    # Build guidance engine and print summary
    engine = GuidanceEngine(spec, profiles)
    summary = engine.summary()

    print()
    print(f"=== Guidance Summary ({args.protocol.upper()}) ===")
    print(f"Libraries: {summary['libraries_analyzed']}")
    print(f"Gaps: {summary['total_gaps']} "
          f"(active: {summary['active_gaps']})")
    if summary["current_focus"]:
        print(f"Top focus: {summary['current_focus']}")

    print()
    for gap in summary["gaps"]:
        marker = "CRITICAL" if gap["severity"] == "critical" else gap["severity"].upper()
        print(
            f"  [{marker}] {gap['checkpoint']:24s} "
            f"affected={gap['affected']}  "
            f"safe={gap['safe']}  "
            f"diff={gap['differential_potential']:.0%}"
        )

    # Print mutation weights
    weights = engine.get_mutation_weights()
    if weights:
        print()
        print("Mutation weights:")
        for field, weight in sorted(weights.items(), key=lambda x: -x[1]):
            bar = "█" * int(weight * 20)
            print(f"  {field:24s} {weight:.1f} {bar}")

    # Print targeted seeds
    seeds = engine.generate_targeted_seeds()
    if seeds:
        print()
        print(f"Targeted seeds: {len(seeds)}")
        for s in seeds[:10]:
            print(f"  [{s['severity']}] {s['description']}")
        if len(seeds) > 10:
            print(f"  ... and {len(seeds) - 10} more")

    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    """Load saved profiles and show guidance summary."""
    profile_dir = Path(args.profiles)
    if not profile_dir.exists():
        print(f"Profile directory not found: {profile_dir}", file=sys.stderr)
        return 1

    profiles = []
    for path in sorted(profile_dir.glob("*.json")):
        profiles.append(GuidanceProfile.load(path))

    if not profiles:
        print("No profiles found.")
        return 1

    spec = ProtocolSpec.load_builtin(args.protocol)
    engine = GuidanceEngine(spec, profiles)
    print(json.dumps(engine.summary(), indent=2))
    return 0


def main() -> int:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="python -m webfuzzer.guidance",
        description="Static analysis guidance for differential fuzzing",
    )
    sub = parser.add_subparsers(dest="command")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyze libraries")
    p_analyze.add_argument("--protocol", required=True, choices=["jwt", "saml"])
    p_analyze.add_argument("--library", default=None, help="Specific library name")
    p_analyze.add_argument("--output", "-o", default=None, help="Output directory for profiles")

    # summary
    p_summary = sub.add_parser("summary", help="Show guidance summary from saved profiles")
    p_summary.add_argument("--protocol", required=True, choices=["jwt", "saml"])
    p_summary.add_argument("--profiles", required=True, help="Directory with profile JSONs")

    args = parser.parse_args()

    if args.command == "analyze":
        return cmd_analyze(args)
    elif args.command == "summary":
        return cmd_summary(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
