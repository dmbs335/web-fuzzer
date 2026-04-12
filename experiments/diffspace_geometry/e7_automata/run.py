"""CLI entry point for E7 — passive differential automata learning.

Reads a feature-dump JSONL file (produced by
:class:`webfuzzer.fuzzer.oracles.feature_dump.FeatureDumpSink`) and
emits, under
``<outputs-root>/<run-id>/e7_automata/``:

* ``library_surface.json`` — per-library bucket table over the observed
  feature vectors (majority verdict + sharp flag per bucket).
* ``pairwise_symdiff.json`` — pairwise empirical symmetric differences
  with up to ``--max-witnesses-per-pair`` witness vectors.
* ``disagreement_trie.json`` — the greedy-IG prefix trie plus the list
  of witness prefixes that discriminate at least one library pair.
* ``summary.json`` — scalar aggregates for the dashboard.

Example:
    python -m experiments.diffspace_geometry.e7_automata.run \\
        --feature-dump output/saml_pilot/features.jsonl \\
        --run-id pilot_saml_2026-04-12
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np

from .disagreement_trie import (
    build_disagreement_trie,
    collect_witness_prefixes,
    serialize_trie,
    trie_depth,
)
from .feature_trace import FeatureTrace, load_feature_trace
from .rpni import run_rpni
from .symmetric_difference import pairwise_symmetric_differences


def _build_library_surface(trace: FeatureTrace) -> dict[str, list[dict]]:
    """Return per-library bucketized verdict table.

    Rows sharing a feature-vector key are collapsed into a single row
    carrying ``count`` (how many dump rows hit the bucket), ``positives``
    (how many of those flipped the library bit on), the majority-vote
    ``verdict``, and a ``sharp`` flag that is true when all dump rows in
    the bucket agree.
    """
    X = trace.X
    Y = trace.Y
    n = X.shape[0]
    field_names = trace.field_names
    library_names = trace.library_names

    buckets: dict[bytes, dict] = {}
    for j in range(n):
        key = bytes(X[j])
        info = buckets.get(key)
        if info is None:
            info = {
                "count": 0,
                "labels": np.zeros(Y.shape[1], dtype=np.int64),
            }
            buckets[key] = info
        info["count"] += 1
        info["labels"] += Y[j]

    surface: dict[str, list[dict]] = {lib: [] for lib in library_names}
    for key, bucket in buckets.items():
        count = int(bucket["count"])
        coords = [field_names[i] for i, bit in enumerate(key) if bit]
        for k, lib in enumerate(library_names):
            on = int(bucket["labels"][k])
            majority = 1 if 2 * on > count else 0
            sharp = on == 0 or on == count
            surface[lib].append(
                {
                    "coordinates": coords,
                    "count": count,
                    "positives": on,
                    "verdict": majority,
                    "sharp": bool(sharp),
                },
            )
    for lib in surface:
        surface[lib].sort(key=lambda r: (-r["count"], r["coordinates"]))
    return surface


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="e7_automata",
        description="Passive differential automata learning (E7).",
    )
    parser.add_argument(
        "--feature-dump",
        required=True,
        type=Path,
        help="Path to a feature-dump JSONL file.",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Run identifier; used as the leaf directory under --outputs-root.",
    )
    parser.add_argument(
        "--outputs-root",
        type=Path,
        default=Path("experiments/diffspace_geometry/outputs"),
    )
    parser.add_argument("--max-prefix", type=int, default=4)
    parser.add_argument("--max-witnesses-per-pair", type=int, default=10)
    parser.add_argument(
        "--rpni",
        action="store_true",
        help="Run Phase 3A RPNI suffix-closure merge after trie construction "
             "and write library_dfas.json to the output directory.",
    )
    parser.add_argument("--rpni-suffix-depth", type=int, default=3)
    args = parser.parse_args(argv)

    trace = load_feature_trace(args.feature_dump)
    n, m = trace.X.shape
    print(
        f"[e7] loaded trace: n={n} m={m} "
        f"libraries={len(trace.library_names)}",
    )

    surface = _build_library_surface(trace)
    symdiffs = pairwise_symmetric_differences(
        trace, max_witnesses=args.max_witnesses_per_pair,
    )
    trie = build_disagreement_trie(trace, max_depth=args.max_prefix)
    witnesses = collect_witness_prefixes(trie, trace.library_names)

    densities = [s.density for s in symdiffs] or [0.0]
    summary = {
        "n_rows": int(n),
        "n_coordinates": int(m),
        "n_libraries": len(trace.library_names),
        "library_names": list(trace.library_names),
        "n_pairs": len(symdiffs),
        "mean_pairwise_symdiff": float(np.mean(densities)),
        "max_pairwise_symdiff": float(np.max(densities)),
        "n_witness_prefixes": len(witnesses),
        "trie_depth": trie_depth(trie),
    }

    out_dir = args.outputs_root / args.run_id / "e7_automata"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "library_surface.json").write_text(
        json.dumps(surface, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    pairwise_payload = [
        {
            "lib_a": s.lib_a,
            "lib_b": s.lib_b,
            "n_disagreements": s.n_disagreements,
            "density": s.density,
            "witness_vectors": s.witness_vectors,
        }
        for s in symdiffs
    ]
    (out_dir / "pairwise_symdiff.json").write_text(
        json.dumps(pairwise_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (out_dir / "disagreement_trie.json").write_text(
        json.dumps(
            {
                "tree": serialize_trie(trie, trace.library_names),
                "witness_prefixes": witnesses,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    # Phase 3A: optional RPNI per-library DFA minimization.
    if args.rpni:
        print("[e7] running RPNI per-library DFA minimization …")
        library_dfas = run_rpni(
            trace,
            max_prefix_depth=args.max_prefix,
            max_suffix_depth=args.rpni_suffix_depth,
        )
        (out_dir / "library_dfas.json").write_text(
            json.dumps(library_dfas, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        for lib, dfa in library_dfas.items():
            print(
                f"[e7]   {lib}: {dfa['n_states']} states, "
                f"{len(dfa['discriminating_coordinates'])} discriminating coords"
            )

    print(f"[e7] outputs written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
