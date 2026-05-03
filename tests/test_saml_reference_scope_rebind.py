"""Unit tests for the _reference_scope_rebind SAML sub-strategy.

E2 Stage B (2026-04-12 pilot) flagged reference_matches_selected_assertion
as the #3 pivotal feature. This strategy was added to target that gap
directly. The tests verify each of the four sub-modes terminates with a
well-formed rebind and that the Assertion subtree — the attacker-controlled
subject — is never mutated.
"""

from __future__ import annotations

import random
import re

import pytest

from webfuzzer.fuzzer.mutators.saml_mutator import SamlMutator

SAMPLE = (
    b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
    b' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
    b' Version="2.0">'
    b'<saml:Assertion ID="_a123" Version="2.0">'
    b'<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>'
    b'<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
    b'<ds:SignedInfo><ds:Reference URI="#_a123"/></ds:SignedInfo>'
    b'<ds:SignatureValue>aaaa</ds:SignatureValue>'
    b'</ds:Signature>'
    b'</saml:Assertion>'
    b'</samlp:Response>'
)


@pytest.fixture
def mutator() -> SamlMutator:
    return SamlMutator(seed=0)


def _current_uri(blob: bytes) -> bytes | None:
    m = re.search(rb'<ds:Reference\s+URI="([^"]*)"', blob)
    return m.group(1) if m else None


def _assertion_block(blob: bytes) -> bytes | None:
    m = re.search(
        rb"(<saml:Assertion\b.*?</saml:Assertion>)", blob, re.DOTALL,
    )
    return m.group(1) if m else None


def test_registered_in_strategy_list(mutator: SamlMutator) -> None:
    assert "reference_scope_rebind" in mutator._strategy_names
    idx = mutator._strategy_names.index("reference_scope_rebind")
    # Must be in the "blocks" set so the post-mutation re-signer does
    # not undo our SignedInfo edit.
    assert idx in mutator._blocks_resign
    # Weights array aligned with strategies.
    assert len(mutator._weights) == len(mutator._strategies)


def test_returns_none_without_reference_element(mutator: SamlMutator) -> None:
    data = bytearray(
        b'<samlp:Response><saml:Assertion/></samlp:Response>',
    )
    assert mutator._reference_scope_rebind(data) is None


def test_decoy_in_extensions_mode(mutator: SamlMutator) -> None:
    mutator.rng = random.Random()
    # Force mode to decoy_in_extensions by stubbing rng.choice.
    mutator.rng.choice = lambda seq: seq[0]  # type: ignore[attr-defined]
    mutator.rng.randbytes = lambda n: b"\x01" * n  # type: ignore[attr-defined]
    out = mutator._reference_scope_rebind(bytearray(SAMPLE))
    assert out is not None
    blob = bytes(out)
    uri = _current_uri(blob)
    assert uri == b"#_decoy_01010101"
    assert b"<samlp:Extensions" in blob
    assert b'ID="_decoy_01010101"' in blob
    # Original assertion (including NameID) is untouched.
    assn = _assertion_block(blob)
    assert assn is not None
    assert b"<saml:NameID>admin</saml:NameID>" in assn
    assert b'ID="_a123"' in assn


def test_decoy_before_sig_mode(mutator: SamlMutator) -> None:
    mutator.rng = random.Random()
    mutator.rng.choice = lambda seq: seq[1]  # type: ignore[attr-defined]
    mutator.rng.randbytes = lambda n: b"\x02" * n  # type: ignore[attr-defined]
    out = mutator._reference_scope_rebind(bytearray(SAMPLE))
    assert out is not None
    blob = bytes(out)
    # Decoy sits before the Signature open tag.
    sig_pos = blob.index(b"<ds:Signature")
    advice_pos = blob.index(b"<saml:Advice")
    assert advice_pos < sig_pos
    assert _current_uri(blob) == b"#_decoy_02020202"


def test_response_id_mode_reuses_existing_id() -> None:
    m = SamlMutator(seed=0)
    m.rng = random.Random()
    m.rng.choice = lambda seq: seq[2]  # type: ignore[attr-defined]
    m.rng.randbytes = lambda n: b"\x03" * n  # type: ignore[attr-defined]
    sample_with_resp_id = SAMPLE.replace(
        b'<samlp:Response xmlns:samlp',
        b'<samlp:Response ID="_resp_original" xmlns:samlp',
    )
    out = m._reference_scope_rebind(bytearray(sample_with_resp_id))
    assert out is not None
    blob = bytes(out)
    # Reference URI is retargeted at the existing Response ID.
    assert _current_uri(blob) == b"#_resp_original"
    # No decoy element injected.
    assert b"<saml:Advice" not in blob


def test_response_id_mode_injects_id_when_absent() -> None:
    m = SamlMutator(seed=0)
    m.rng = random.Random()
    m.rng.choice = lambda seq: seq[2]  # type: ignore[attr-defined]
    m.rng.randbytes = lambda n: b"\x04" * n  # type: ignore[attr-defined]
    out = m._reference_scope_rebind(bytearray(SAMPLE))
    assert out is not None
    blob = bytes(out)
    # New synthetic Response ID.
    expected_id = b"_resp_040404"
    uri = _current_uri(blob)
    assert uri == b"#" + expected_id
    # Injected into the Response open tag, not the Assertion.
    resp_open = re.search(rb"<samlp:Response[^>]*>", blob)
    assert resp_open is not None
    assert b'ID="' + expected_id + b'"' in resp_open.group(0)


def test_fake_id_mode_leaves_document_otherwise_identical() -> None:
    m = SamlMutator(seed=0)
    m.rng = random.Random()
    m.rng.choice = lambda seq: seq[3]  # type: ignore[attr-defined]
    m.rng.randbytes = lambda n: b"\x05" * n  # type: ignore[attr-defined]
    out = m._reference_scope_rebind(bytearray(SAMPLE))
    assert out is not None
    blob = bytes(out)
    # Only the Reference URI changes — no Advice, no new Response ID.
    assert b"<saml:Advice" not in blob
    assert _current_uri(blob) == b"#_decoy_05050505"
    # Attacker-controlled subject is untouched (the Signature sits inside
    # the Assertion in this fixture, so the Assertion block differs by
    # exactly the Reference URI rewrite and nothing else).
    assert b"<saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>" in blob
    assert b'ID="_a123"' in blob


def test_guidance_routing_includes_reference_scope(mutator: SamlMutator) -> None:
    """Guidance on Reference.URI must be able to boost this strategy."""
    mutator.apply_guidance_weights({"Reference.URI": 1.0})
    idx = mutator._strategy_names.index("reference_scope_rebind")
    base = mutator._base_weights[idx]
    assert mutator._weights[idx] >= base  # boosted, not attenuated
