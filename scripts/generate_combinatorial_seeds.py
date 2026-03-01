#!/usr/bin/env python3
"""Generate pairwise URL seeds from grammar-derived parameter dimensions.

Usage:
    python scripts/generate_combinatorial_seeds.py \\
        --output-dir targets/url_seeds_combinatorial \\
        --strength 2 --seed 42
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from webfuzzer.combinatorial.covering_array import generate_covering_array

# ── Parameter dimensions (values extracted from uri.grammar patterns) ───

DIMENSIONS: dict[str, list[tuple[str, str]]] = {
    # (value_name, URL fragment template)
    "scheme": [
        ("http", "http"),
        ("https", "https"),
        ("file", "file"),
        ("javascript", "javascript"),
        ("data", "data"),
        ("gopher", "gopher"),
        ("casemix", "HTTP"),
        ("tabinj", "ht\ttp"),
    ],
    "userinfo": [
        ("none", ""),
        ("simple", "user:pass@"),
        ("doubleat", "evil.com@good.com@"),
        ("bslashat", "evil.com\\@"),
        ("encodat", "evil.com%40host@"),
        ("colonbs", "localhost:\\@"),
        ("hostlike", "evil.com:80@"),
    ],
    "host": [
        ("domain", "example.com"),
        ("ipv4", "10.0.0.1"),
        ("hexip", "0x7f000001"),
        ("octalip", "0177.0.0.01"),
        ("decip", "2130706433"),
        ("ipv6lo", "[::1]"),
        ("ipv6map", "[::ffff:127.0.0.1]"),
        ("bracket", "[example.com]"),
        ("localhost", "localhost"),
        ("wildcard", "127.0.0.1.nip.io"),
    ],
    "port": [
        ("none", ""),
        ("std", ":80"),
        ("high", ":8080"),
        ("overflow", ":65536"),
        ("leadzero", ":0080"),
        ("neg", ":-1"),
        ("nonnumeric", ":abc"),
    ],
    "path": [
        ("simple", "/index.html"),
        ("dotdot", "/a/../b"),
        ("enctrav", "/a/%2e%2e/b"),
        ("overutf8", "/a/%c0%ae%c0%ae/b"),
        ("semicol", "/a;b=c/d"),
        ("bslash", "/a\\b"),
        ("null", "/a%00b"),
    ],
    "query": [
        ("none", ""),
        ("simplekv", "?key=value"),
        ("encoded", "?k=%3cscript%3e"),
        ("dblquest", "??double"),
        ("semicol", "?a=1;b=2"),
        ("hpp", "?x=1&x=2"),
    ],
    "fragment": [
        ("none", ""),
        ("simple", "#section"),
        ("atauth", "#@evil.com"),
        ("dblhash", "##double"),
        ("querylike", "#?q=search"),
        ("authlike", "#//evil.com/path"),
    ],
}


def assemble_url(config: dict[str, tuple[str, str]]) -> str:
    """Assemble a URL from component selections."""
    scheme = config["scheme"][1]
    userinfo = config["userinfo"][1]
    host = config["host"][1]
    port = config["port"][1]
    path = config["path"][1]
    query = config["query"][1]
    fragment = config["fragment"][1]

    # Build authority
    authority = f"{userinfo}{host}{port}"

    # Assemble
    url = f"{scheme}://{authority}{path}{query}{fragment}"
    return url


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate pairwise URL seeds")
    parser.add_argument(
        "--output-dir", type=Path, required=True,
        help="Output directory for seed files",
    )
    parser.add_argument(
        "--strength", type=int, default=2,
        help="Covering strength (2=pairwise, 3=3-way, default: 2)",
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    dim_names = list(DIMENSIONS.keys())
    parameters = [
        [v[0] for v in DIMENSIONS[name]]  # value names
        for name in dim_names
    ]

    print(f"Generating {args.strength}-way covering array...")
    print(f"  Dimensions: {', '.join(f'{n}({len(p)})' for n, p in zip(dim_names, parameters))}")

    array = generate_covering_array(parameters, strength=args.strength, seed=args.seed)
    print(f"  Array size: {len(array)} test configurations")

    # Create output directory
    args.output_dir.mkdir(parents=True, exist_ok=True)

    # Build lookup for value name → template
    dim_lookup: dict[str, dict[str, tuple[str, str]]] = {}
    for name, values in DIMENSIONS.items():
        dim_lookup[name] = {v[0]: v for v in values}

    # Write seed files
    for idx, row in enumerate(array):
        config = {}
        for i, dim_name in enumerate(dim_names):
            val_name = row[i]
            config[dim_name] = dim_lookup[dim_name][val_name]

        url = assemble_url(config)
        short_vals = "_".join(row)
        filename = f"{200 + idx:03d}_comb_{short_vals}.txt"
        (args.output_dir / filename).write_text(url, encoding="utf-8")

    print(f"  Wrote {len(array)} seed files to {args.output_dir}")

    # Verify coverage
    if args.strength == 2:
        total_pairs = 0
        covered_pairs = 0
        for i in range(len(dim_names)):
            for j in range(i + 1, len(dim_names)):
                for vi in range(len(parameters[i])):
                    for vj in range(len(parameters[j])):
                        total_pairs += 1
                        pair_covered = any(
                            row[i] == parameters[i][vi] and row[j] == parameters[j][vj]
                            for row in array
                        )
                        if pair_covered:
                            covered_pairs += 1
        print(f"  Pairwise coverage: {covered_pairs}/{total_pairs} ({100*covered_pairs/total_pairs:.1f}%)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
