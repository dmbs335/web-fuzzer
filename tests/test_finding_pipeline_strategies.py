"""Verifies the mutator-sub-strategy breadcrumb propagation in FindingProcessor.

SamlMutator.mutate attaches ``metadata["strategies"] = [<applied ops>]`` to
the Input it returns. Prior to the fix, ``FindingProcessor.check`` only
copied ``mutator_name`` onto the finding, silently dropping the composed
sub-strategy list. E4 strategy_atom_weights therefore saw only the oracle
name and could not weight SamlMutator sub-strategies.

This test exercises the pipeline with a fake oracle/dedup/publisher and
asserts that an Input carrying ``strategies`` lands in the published
finding metadata verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from webfuzzer.fuzzer.finding_pipeline import FindingProcessor
from webfuzzer.fuzzer.protocols import (
    ExecutionResult,
    Finding,
    Input,
    Severity,
)


class _FakeDeduplicator:
    def __init__(self) -> None:
        self._counter = 0

    def fingerprint(self, finding: Finding) -> str:
        self._counter += 1
        return f"fp-{self._counter}"

    def is_duplicate(self, finding: Finding) -> bool:
        return False

    def register(self, finding: Finding) -> None:
        pass


@dataclass
class _FakePublisher:
    emitted: list[dict] = field(default_factory=list)

    def publish_finding(self, **kwargs: Any) -> None:
        self.emitted.append(kwargs)


@dataclass
class _FakeStats:
    def record_finding(self, finding: Finding, mutator_name: str = "") -> None:
        pass


class _StaticOracle:
    oracle_name = "static"

    def __init__(self, finding: Finding) -> None:
        self._finding = finding

    def check(self, inp: Input, result: ExecutionResult) -> Finding:
        return self._finding


def _make_processor() -> tuple[FindingProcessor, _FakePublisher]:
    publisher = _FakePublisher()
    processor = FindingProcessor(
        oracles=[],
        deduplicator=_FakeDeduplicator(),
        publisher=publisher,
        stats=_FakeStats(),
        guidance_hooks=None,
        all_targets=[object()],
        target_lib_names=["lib"],
    )
    return processor, publisher


def _run(processor: FindingProcessor, inp: Input, finding: Finding) -> None:
    processor.oracles = [_StaticOracle(finding)]
    processor.check(inp, finding.result, mutator_name="saml_mutator")


def _make_finding(inp: Input) -> Finding:
    return Finding(
        title="test",
        severity=Severity.MEDIUM,
        input=inp,
        result=ExecutionResult(),
        oracle_name="static",
        metadata={},
    )


def test_input_strategies_propagate_to_finding_metadata():
    processor, publisher = _make_processor()

    inp = Input(
        data=b"<saml:Response/>",
        metadata={
            "strategies": [
                "xsw_assertion_envelope",
                "parser_xml_whitespace",
            ],
        },
    )
    finding = _make_finding(inp)
    _run(processor, inp, finding)

    assert len(publisher.emitted) == 1
    meta = publisher.emitted[0]["metadata"]
    assert meta["strategies"] == [
        "xsw_assertion_envelope",
        "parser_xml_whitespace",
    ]
    # Ensure the copy is defensive (a new list, not the same object) so
    # downstream mutation of finding metadata cannot retroactively alter
    # the Input's strategies list.
    assert meta["strategies"] is not inp.metadata["strategies"]
    assert meta["mutator"] == "saml_mutator"


def test_missing_strategies_does_not_inject_empty_list():
    processor, publisher = _make_processor()

    inp = Input(data=b"<saml:Response/>", metadata={})
    finding = _make_finding(inp)
    _run(processor, inp, finding)

    assert len(publisher.emitted) == 1
    meta = publisher.emitted[0]["metadata"]
    # No breadcrumb → no key. We don't want downstream to confuse
    # "unknown" with "explicitly empty".
    assert "strategies" not in meta


def test_existing_finding_strategies_are_not_overwritten():
    """Some oracles may already emit their own ``strategies`` list —
    the breadcrumb copy must use setdefault so oracle intent wins."""
    processor, publisher = _make_processor()

    inp = Input(
        data=b"<saml:Response/>",
        metadata={"strategies": ["from_input"]},
    )
    finding = _make_finding(inp)
    finding.metadata["strategies"] = ["from_oracle"]
    _run(processor, inp, finding)

    assert len(publisher.emitted) == 1
    meta = publisher.emitted[0]["metadata"]
    assert meta["strategies"] == ["from_oracle"]
