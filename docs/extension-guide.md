# Extension Guide

This guide explains where new features should be added after the recent refactors.

## Add A New Target

1. Implement the target behavior behind the `Target` protocol.
2. Add construction logic in `webfuzzer/app/factories/targets.py`.
3. If the target needs a persistent wrapper or special timeout mapping, update `webfuzzer/app/persistent_targets.py`.
4. If the target should be selectable from a campaign preset, update `webfuzzer/app/campaigns.py`.

Use this path when the main question is "how do we execute inputs?"

## Add A New Mutator

1. Implement `mutate(...)` in `webfuzzer/fuzzer/mutators/*`.
2. If the mutator supports optional behaviors, implement the relevant protocols from `webfuzzer/fuzzer/protocols.py`.
3. Register or select it from `webfuzzer/app/factories/mutators.py`.
4. Add tests or fixtures that exercise the new strategy.

Optional protocols commonly used by mutators:

- `StrategyFeedbackMutator`
- `ExceptionHintMutator`
- `ResettableMutatorWeights`
- `GuidanceWeightedMutator`
- `LearnedWeightMutator`

## Add A New Oracle

1. Implement the `Oracle` protocol in `webfuzzer/fuzzer/oracles/*`.
2. If the oracle needs differential reference results, keep the specialized logic in the oracle and let `FindingProcessor` normalize the output.
3. Wire selection in `webfuzzer/app/factories/oracles.py`.

Use this path when the main question is "how do we decide something is interesting or broken?"

## Add A New Scheduler

1. Implement `SeedScheduler` or `MutatorScheduler`.
2. If the scheduler needs cleanup after corpus compaction, implement `CleanupAwareSeedScheduler`.
3. Register it in `webfuzzer/app/factories/schedulers.py`.

## Add A New Domain Profile

1. Pick the right group under `webfuzzer/fuzzer/domain_profiles/`.
2. Add a new `register(DomainProfile(...))` block in that file.
3. Only touch `domain_model.py` if a genuinely new concept is required.
4. Do not put new built-in profiles directly into `domain.py`.

Use this path when the change is mostly:

- comparison keys
- finding categories
- field severity mapping
- danger ladder rules

## Add A New Campaign Preset

1. Update `webfuzzer/app/campaigns.py`.
2. Keep the preset declarative.
3. Let existing factories build the runtime from those flags instead of duplicating assembly logic in `cli.py`.

## Add A New Optional Hook

Before adding another `hasattr(...)` check:

1. Decide whether the behavior is a reusable capability.
2. If yes, add a runtime-checkable protocol in `webfuzzer/fuzzer/protocols.py`.
3. Update the engine or service to use `isinstance(..., YourProtocol)`.
4. Implement the protocol only on components that need it.

This keeps extension points visible to both humans and AI agents.

## File Placement Rules

Use these placement rules consistently:

- runtime assembly: `webfuzzer/app/*`
- runtime orchestration: `webfuzzer/fuzzer/*`
- reusable contracts: `webfuzzer/fuzzer/protocols.py`
- domain data: `webfuzzer/fuzzer/domain_profiles/*`
- concrete fuzzing logic: `webfuzzer/fuzzer/mutators/*`, `oracles/*`, `schedulers/*`

## Checklist Before You Finish

- Is the contract explicit?
- Is the assembly point obvious?
- Is the runtime call site easy to find?
- Did the change avoid making `cli.py` or `engine.py` larger without a strong reason?
- Would a new contributor know where to add the second instance of the same thing?

