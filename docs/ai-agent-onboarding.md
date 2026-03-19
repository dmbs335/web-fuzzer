# AI Agent Onboarding

This guide is written for an autonomous coding agent entering the repository mid-stream.

## Fast Start

If you only have a few minutes, read in this order:

1. `webfuzzer/fuzzer/protocols.py`
2. `docs/architecture-overview.md`
3. `webfuzzer/cli.py`
4. `webfuzzer/app/factories/__init__.py`
5. `webfuzzer/fuzzer/engine.py`

That sequence gives you:

- the contracts
- the system map
- the entrypoint
- the runtime assembly layer
- the loop that coordinates everything

## Mental Model

Treat the codebase as four layers:

### Layer 1: Contracts

`webfuzzer/fuzzer/protocols.py`

This is the source of truth for what is swappable.

### Layer 2: Assembly

`webfuzzer/cli.py` and `webfuzzer/app/*`

This layer decides which concrete target, mutator, oracle, scheduler, and coverage collector to build.

### Layer 3: Runtime

`webfuzzer/fuzzer/engine.py` and helper services

This layer runs the fuzz loop and delegates sub-jobs to focused services.

### Layer 4: Domain Knowledge

`webfuzzer/fuzzer/domain_*` and `domain_profiles/*`

This layer tells the fuzzer how to interpret domain-specific output fields, categories, and danger ladders.

## Best Entry File For Common Tasks

### "I need to add a new runtime component"

Start with:

- `webfuzzer/fuzzer/protocols.py`
- matching factory in `webfuzzer/app/factories/*`

### "I need to add a new fuzzing domain"

Start with:

- `webfuzzer/fuzzer/domain_profiles/*`
- `webfuzzer/fuzzer/domain_model.py`

### "I need to change the loop behavior"

Start with:

- `webfuzzer/fuzzer/engine.py`
- then inspect `seeding.py`, `finding_pipeline.py`, `runtime_reporting.py`, `checkpointing.py`, or `command_channel.py`

### "I need to understand why a feature exists"

Search in this order:

1. `protocols.py`
2. `cli.py`
3. `app/factories/*`
4. `engine.py`
5. concrete implementation under `mutators/`, `oracles/`, `schedulers/`, or target scripts

## Change Strategy

When making edits, prefer this sequence:

1. Identify the contract.
2. Find the assembly point.
3. Find the runtime call site.
4. Change the concrete implementation.
5. Update docs if the entry path for future agents changes.

This reduces the risk of adding behavior that exists but is hard to discover.

## Repository Heuristics

Use these heuristics to avoid wasted exploration:

- If something is selected from CLI flags, the answer is usually in `webfuzzer/app/*`.
- If something happens every iteration, the answer is usually in `engine.py`.
- If something affects seed import, grammar seeding, or initial corpus shape, the answer is usually in `seeding.py`.
- If something affects finding dedup, publishing, or metadata normalization, the answer is usually in `finding_pipeline.py`.
- If something looks like a long table of field names and severities, it belongs in `domain_profiles/*`.

## Safe Refactoring Directions

These directions are aligned with the current architecture:

- Extracting more orchestration helpers out of `engine.py`
- Replacing `hasattr(...)` extension points with explicit protocols
- Moving more data declarations into dedicated modules
- Keeping `cli.py` thin and moving selection logic into factories

## High-Risk Refactoring Directions

Be more careful with:

- changing the meaning of `ScheduleResult`
- changing checkpoint serialization shape
- changing `Corpus` semantics
- changing the primary/reference rotation model
- moving domain profile registration order without understanding downstream assumptions

## What Good Changes Look Like Here

A good change usually has these properties:

- one clear entry path
- a small number of edit sites
- explicit protocol or factory wiring
- no hidden runtime magic needed to discover it later

If you can answer "where do I add the next one?" in one sentence after your change, the design likely improved.

