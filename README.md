# web-fuzzer

`webfuzzer` is a grammar-driven differential fuzzing framework for web-facing
parsers, normalizers, sanitizers, and protocol handlers.

The stable core is intentionally simple:

- generate or mutate inputs from grammars and seed corpora
- execute one primary target and optional reference targets
- collect crash, response, and differential signals
- run domain-specific oracles
- persist corpus, findings, and runtime reports

Several research-oriented scheduling, guidance, and post-run analysis hooks are
available, but they are experimental. They should be treated as heuristics until
they have campaign-level benchmarks and reproducible evaluation notes.

## Current Scope

This repository is for the fuzzer runtime and target harnesses. Large fuzzing
outputs, private triage data, and external research workspaces should stay out
of this repo.

In scope:

- `webfuzzer/core`: grammar parsing and generation
- `webfuzzer/fuzzer`: runtime loop, corpus, coverage, oracles, mutators,
  schedulers, reporting
- `webfuzzer/app`: CLI-to-runtime assembly
- `targets`: target wrappers, public seed corpora, and lightweight harness files
- `tests`: unit and regression tests for runtime behavior

Out of scope:

- raw fuzzing results and campaign artifacts
- private finding triage
- standalone formal-research workspaces such as `fuzzing-formal-research`
- unrelated product/server research that is not a fuzzer target harness

## Installation

```bash
cd web-fuzzer
pip install -e .
```

Optional runtimes are needed for some target families:

- Node.js for JavaScript targets
- Java for JVM targets
- Go, Rust, PHP, or .NET for language-specific parser targets
- Redis only when integrating with an external orchestrator

## Basic Usage

Generate inputs:

```bash
webfuzzer generate --grammar json --count 10
```

Fuzz one target:

```bash
webfuzzer fuzz --grammar json --target-cmd "python targets/json_strict.py {input}"
```

Run differential fuzzing:

```bash
webfuzzer fuzz --grammar json \
  --target-cmd "python targets/json_strict.py {input}" \
  --diff-cmd "python targets/json_json5.py {input}" \
  --oracle crash,response \
  --mutators grammar,havoc,token \
  --scheduler entropic \
  --seeds-dir targets/json_seeds \
  --output-dir artifacts/fuzz-runs/json_diff
```

Use `artifacts/` or another ignored directory for run output. Do not commit raw
campaign results.

Each fuzzing run with an output directory also writes
`campaign_manifest.json`. The manifest records the grammar, target hashes, seed
source hash, budget, condition, method label, CLI, and related artifact paths so
`fuzzing-formal-research` can validate the run without guessing how it was
produced.

## Main Commands

| Command | Purpose |
| --- | --- |
| `webfuzzer generate` | Generate inputs from a grammar |
| `webfuzzer fuzz` | Run a fuzzing campaign |
| `webfuzzer list` | List available grammars and rules |
| `webfuzzer validate` | Validate grammar syntax |

## Common Fuzz Options

| Option | Purpose |
| --- | --- |
| `--grammar NAME` | Input grammar |
| `--target-cmd CMD` | Primary target command with `{input}` placeholder |
| `--diff-cmd CMD` | Reference target command; repeatable |
| `--oracle LIST` | Comma-separated oracle names |
| `--mutators LIST` | Comma-separated mutator names |
| `--scheduler NAME` | Seed scheduler |
| `--mutator-scheduler NAME` | Mutator scheduler |
| `--seeds-dir DIR` | Initial seed directory |
| `--persistent` | Keep target subprocesses alive when wrappers support it |
| `--output-dir DIR` | Write corpus, findings, and reports |
| `--manifest-method LABEL` | Override the validation method label written to `campaign_manifest.json` |
| `--manifest-condition NAME` | Override the validation condition, such as `baseline` or `candidate` |

## Architecture

```text
CLI
  -> app factories
    -> FuzzEngine
      -> seeding
      -> mutators
      -> targets
      -> coverage
      -> oracles
      -> finding pipeline
      -> runtime reporting
```

The important runtime contracts live in `webfuzzer/fuzzer/protocols.py`.
Factories under `webfuzzer/app/factories/` turn CLI flags into concrete runtime
objects. The main loop lives in `webfuzzer/fuzzer/engine.py`.

For a fuller map, read `docs/architecture-overview.md`.

## Experimental Features

These features exist and have tests for local behavior, but they should not be
presented as validated methodology without separate campaign evidence.

| Feature | Current status |
| --- | --- |
| `--mcts` | UCB1-guided grammar production selection, not a full MCTS implementation |
| `--scheduler map-elites` | Quality-diversity-inspired archive over domain categories and reference indices |
| `--mutator-scheduler linucb` | Contextual-bandit mutator picker with hand-chosen seed features |
| `--adaptive-coverage` | Adaptive differential feature level; CEGAR-inspired but not formal CEGAR |
| `--concolic` | Constraint/property/source-guided targeted mutation; do not treat as true concolic execution unless the active mode records path constraints, solves them, and replays solver-derived inputs |
| `--guidance` | Regex/AST/profile hints for JWT/SAML; useful as shallow guidance, not a general static-analysis engine |
| `--lattice-atoms`, `--dedup-atoms`, `--implication-base` | External `fuzzing-formal-research` hooks |
| `--danger-boost` | Heuristic seed priority boost from domain danger levels |

See `docs/methodology-status.md` before relying on these options for claims.

## Repository Layout

```text
docs/                         project notes and architecture docs
scripts/                      developer and target-check helper scripts
seeds/                        small public seed sets not tied to one target tree
targets/                      target wrappers, harnesses, and public seed corpora
tests/                        unit and regression tests
tools/                        offline helper tools
webfuzzer/app/                CLI assembly layer
webfuzzer/core/               grammar parser and generator
webfuzzer/fuzzer/             runtime engine and fuzzing components
webfuzzer/guidance/           experimental guidance hooks
webfuzzer/native/             optional native speedups
```

## Result Hygiene

Generated outputs should stay ignored. In particular:

- use `artifacts/` for local campaign output
- do not commit `findings/`, `corpus/`, `results/`, `out/`, logs, or JSONL run
  streams
- keep private or sensitive triage outside this repository

## Development

Compile-check the Python runtime:

```bash
python -m compileall -q webfuzzer scripts
```

Run tests when `pytest` is installed:

```bash
pytest
```

The test suite is mainly unit and regression coverage. It does not by itself
prove that an experimental scheduler or research hook improves fuzzing yield.
