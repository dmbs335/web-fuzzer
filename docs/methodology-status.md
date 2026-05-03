# Methodology Status

This document separates stable fuzzer mechanics from experimental methodology.
It is deliberately conservative: a feature is not considered validated just
because it has unit tests or a paper-inspired name.

## Status Levels

| Level | Meaning |
| --- | --- |
| Stable | Runtime behavior is part of the normal fuzzer path and has regression tests |
| Supported heuristic | Useful implementation with tests, but no campaign-level claim attached |
| Experimental | Research hook or exploratory feature; use for campaigns, not for claims |
| External | Depends on artifacts from another workspace or post-run analysis pipeline |

## Stable Core

| Area | Status | Notes |
| --- | --- | --- |
| Grammar generation | Stable | Grammar parser/generator are core runtime pieces |
| Process targets | Stable | Normal process-per-input execution path |
| Persistent targets | Stable | Useful when target wrappers support the protocol; speedup is workload-dependent |
| Differential execution | Stable | Primary/reference target model is central to the project |
| Finding pipeline | Stable | Normalization, dedup, publication, and reports are core |
| Domain mutators/oracles | Stable per domain | Correctness is domain-specific and covered by targeted tests |

## Experimental Or Heuristic Features

| Feature | Status | Current interpretation | Risk |
| --- | --- | --- | --- |
| `--mcts` | Supported heuristic | UCB1 production selection shared by grammar source/mutator | Name overstates the implementation if called full MCTS |
| `--scheduler map-elites` | Experimental | Archive scheduler over `(category, ref_index)` cells | Category adjacency is not a proven behavioral metric |
| `--mutator-scheduler linucb` | Supported heuristic | Contextual bandit over hand-picked seed features | Needs ablation before claiming yield improvement |
| `--adaptive-coverage` | Experimental | Adaptive differential feature granularity | CEGAR-inspired, not formal CEGAR |
| `--concolic` | Experimental | Constraint/property/source-guided targeted mutation | Name may overclaim unless a mode records path constraints, solves them, and replays solver-derived inputs |
| `--guidance` | Experimental | Regex/AST/profile hints for JWT/SAML | Shallow, pattern-dependent, and not a general static-analysis engine |
| `--danger-boost` | Supported heuristic | Priority boost from domain danger levels | Can over-focus noisy oracle signals |
| `--target-coverage` | Experimental | Merges target coverage into diff coverage | Coverage plumbing depends on wrapper support |

## External Research Hooks

These options should be treated as import points from external research, not as
core fuzzer methodology.

| Option | Status | Expected source |
| --- | --- | --- |
| `--lattice-atoms` | External | `fuzzing-formal-research` strategy atom weights |
| `--automaton-witnesses` | External | `fuzzing-formal-research` disagreement witness weights |
| `--stopping-signal` | External | `fuzzing-formal-research` stopping-signal analysis |
| `--dedup-atoms` | External | FCA atom summary |
| `--implication-base` | External | FCA implication base |
| `--diff-trace` | External output feed | Pre-dedup stream for offline analysis |
| `--feature-dump` | External output feed | Per-input feature stream for offline analysis |

## Campaign Manifest

When `--output-dir` is set, the fuzzer writes `campaign_manifest.json` next to
the normal report. This is not a new fuzzing heuristic. It is the provenance
envelope used by `fuzzing-formal-research` to join a run with external artifact
schemas and campaign protocols.

The manifest records:

- target command hashes, not executable copies
- seed source or generated-seed hash
- method and condition labels
- iteration/time budget
- CLI and output artifact paths

Use `--manifest-method` and `--manifest-condition` when an experiment needs a
stable label that should not be inferred from CLI flags.

## Known Documentation/Implementation Mismatches Fixed

- The old README described adaptive coverage transitions in the opposite
  direction from the implementation.
- The old README described MAP-Elites as a fixed `16 x 5` archive even though
  the code uses dynamic categories and `MAX_REF_INDEX = 8`.
- The old README presented UCB1 grammar production selection as MCTS without
  enough caveat.
- The old README described experimental concolic and guidance modes as stronger
  than their current implementations support.

## Guidance/Concolic Scope Decision

Treat `--guidance` and `--concolic` as quarantined research features. They are
useful as targeted-mutation accelerators, but they are not part of the stable
fuzzer methodology.

- `--guidance` means regex/AST/profile hints, not general static analysis.
- `--concolic` means targeted mutation unless the active mode performs real
  path-constraint collection, solver invocation, and solver-output replay.
- Both features require same-budget baseline comparisons, held-out targets, and
  FP/replay-fragility checks before any stronger claim.

## Evidence Needed Before Strong Claims

Before promoting an experimental feature to stable methodology, add at least:

- a reproducible campaign script or fixture
- baseline comparison against a simpler scheduler/mutator path
- fixed seed or repeated-run protocol
- output metrics that include executions, coverage growth, unique findings,
  false-positive rate where applicable, and run duration
- short notes about target set, versions, and environment

Until then, use language like "heuristic", "experimental", "inspired by", and
"may help" instead of "proves", "guarantees", or "validated".
