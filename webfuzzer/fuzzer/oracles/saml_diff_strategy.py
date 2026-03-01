"""SAML differential strategies for cross-library comparison.

Detects exploitable divergences between SAML library implementations:
  1. Signature Bypass  (CRITICAL) — one accepts, another rejects
  2. Subject Confusion (CRITICAL) — both accept but extract different NameID
  3. Attribute Confusion (HIGH) — same subject, different attributes
  4. Assertion Count Divergence (HIGH) — different assertion counts (XSW)
  5. Algorithm Confusion (MEDIUM) — different algorithm interpretation
  6. Issuer/Audience Mismatch (MEDIUM) — scope confusion

Architecture mirrors UrlConfusionStrategy — pluggable DiffStrategy
for composition with DiffOracle.

References:
  - SAML Vulnerability Mutation Taxonomy (S1-S8)
  - PortSwigger "The Fragile Lock" (2025)
  - WorkOS "SAMLStorm" (2025)
  - GitHub Security Lab ruby-saml parser differentials (2025)
"""

from __future__ import annotations

import json
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_saml_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a SAML target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and ("signature_valid" in data or "subject" in data):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _diff_attributes(
    a: dict[str, Any], b: dict[str, Any],
) -> list[str]:
    """Return list of attribute keys with differing values."""
    all_keys = set(a) | set(b)
    diffs = []
    for k in sorted(all_keys):
        av = a.get(k)
        bv = b.get(k)
        if av != bv:
            diffs.append(k)
    return diffs


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


# ── Primary strategy: Signature Bypass + Subject Confusion ──────


class SamlDiffStrategy:
    """Primary SAML differential strategy.

    Detects signature bypass and subject confusion between two
    SAML library implementations.  These are the highest-impact
    findings (both CRITICAL) that directly enable auth bypass.
    """

    name = "saml_bypass"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)

        # Both failed to parse — no interesting divergence
        if p is None and r is None:
            return None

        # One-sided parse: one succeeded, other totally failed
        if p is None or r is None:
            return self._check_one_sided(inp, primary, reference, ref_index, p, r)

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)
        p_subject = (p.get("subject") or "").strip()
        r_subject = (r.get("subject") or "").strip()

        # ── CRITICAL: Signature bypass ──
        if p_valid != r_valid:
            accepting = "primary" if p_valid else f"ref[{ref_index}]"
            rejecting = f"ref[{ref_index}]" if p_valid else "primary"
            acc_data = p if p_valid else r
            return Finding(
                title=(
                    f"SAML Signature Bypass: {accepting} accepts "
                    f"(subject={acc_data.get('subject')}) "
                    f"but {rejecting} rejects"
                ),
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "signature_bypass",
                    "primary_valid": p_valid,
                    "ref_valid": r_valid,
                    "ref_index": ref_index,
                    "primary_subject": p_subject,
                    "ref_subject": r_subject,
                    "primary_error": p.get("signature_error"),
                    "ref_error": r.get("signature_error"),
                    "input_preview": _input_preview(inp),
                },
            )

        # ── CRITICAL: Subject confusion (both accept, different NameID) ──
        if p_valid and r_valid and p_subject and r_subject:
            if p_subject.lower() != r_subject.lower():
                return Finding(
                    title=(
                        f"SAML Subject Confusion: "
                        f"primary='{p_subject}' vs ref[{ref_index}]='{r_subject}'"
                    ),
                    severity=Severity.CRITICAL,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "subject_confusion",
                        "primary_subject": p_subject,
                        "ref_subject": r_subject,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )

        # ── MEDIUM: Subject extraction divergence (sig not required) ──
        # Different subject extraction = parsers interpret DOM differently.
        # Prerequisite for XSW attacks; lower severity than subject_confusion
        # because signatures are not validated.
        if p_subject and r_subject and p_subject.lower() != r_subject.lower():
            return Finding(
                title=(
                    f"SAML Subject Extraction Divergence: "
                    f"primary='{p_subject}' vs ref[{ref_index}]='{r_subject}'"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "subject_extraction_divergence",
                    "primary_subject": p_subject,
                    "ref_subject": r_subject,
                    "primary_valid": p_valid,
                    "ref_valid": r_valid,
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        # ── HIGH: Attribute confusion ──
        if p_valid and r_valid:
            p_attrs = p.get("attributes") or {}
            r_attrs = r.get("attributes") or {}
            diff_attrs = _diff_attributes(p_attrs, r_attrs)
            if diff_attrs:
                return Finding(
                    title=(
                        f"SAML Attribute Confusion: "
                        f"differs on {', '.join(diff_attrs)} (ref[{ref_index}])"
                    ),
                    severity=Severity.HIGH,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "attribute_confusion",
                        "diff_fields": diff_attrs,
                        "primary_attrs": p_attrs,
                        "ref_attrs": r_attrs,
                        "ref_index": ref_index,
                    },
                )

        # ── Assertion count divergence ──
        # Report when parsers see different numbers of assertions.
        # This is an XSW indicator even without valid signature — different
        # assertion counts mean different DOM interpretation, which is the
        # prerequisite for signature wrapping attacks.
        p_count = p.get("assertion_count", 0)
        r_count = r.get("assertion_count", 0)
        if p_count != r_count and (p_count > 0 or r_count > 0):
            return Finding(
                title=(
                    f"SAML Assertion Count Divergence: "
                    f"primary={p_count} vs ref[{ref_index}]={r_count}"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "assertion_count_divergence",
                    "primary_count": p_count,
                    "ref_count": r_count,
                    "ref_index": ref_index,
                },
            )

        return None

    def _check_one_sided(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
        p: dict | None,
        r: dict | None,
    ) -> Finding | None:
        """One target parsed successfully, the other didn't."""
        if p is not None and p.get("signature_valid") and p.get("subject"):
            return Finding(
                title=(
                    f"SAML One-Sided Accept: primary accepts "
                    f"(subject={p.get('subject')}) but ref[{ref_index}] crashes/rejects"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "one_sided_accept",
                    "accepting_side": "primary",
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )
        if r is not None and r.get("signature_valid") and r.get("subject"):
            return Finding(
                title=(
                    f"SAML One-Sided Accept: ref[{ref_index}] accepts "
                    f"(subject={r.get('subject')}) but primary crashes/rejects"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "one_sided_accept",
                    "accepting_side": f"ref[{ref_index}]",
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )
        return None


# ── Secondary: Algorithm confusion ──────────────────────────────


class SamlAlgorithmConfusionStrategy:
    """Detect algorithm interpretation differences across libraries."""

    name = "saml_algorithm"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if p is None or r is None:
            return None

        p_algos = p.get("algorithms") or {}
        r_algos = r.get("algorithms") or {}
        if not p_algos and not r_algos:
            return None

        # Only report when at least one side validates signature
        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)
        if not p_valid and not r_valid:
            return None

        for field in ("signature", "digest"):
            pa = (p_algos.get(field) or "").lower()
            ra = (r_algos.get(field) or "").lower()
            if pa and ra and pa != ra:
                return Finding(
                    title=(
                        f"SAML Algorithm Confusion ({field}): "
                        f"primary='{pa}' vs ref[{ref_index}]='{ra}'"
                    ),
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "algorithm_confusion",
                        "field": field,
                        "primary_algo": pa,
                        "ref_algo": ra,
                        "ref_index": ref_index,
                    },
                )
        return None


# ── Secondary: Issuer/Audience confusion ────────────────────────


class SamlIssuerConfusionStrategy:
    """Detect issuer or audience extraction differences."""

    name = "saml_issuer"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if p is None or r is None:
            return None

        # Only report when at least one side validates signature
        # Otherwise it's just parser extraction noise
        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)
        if not p_valid and not r_valid:
            return None

        for field, label in [("issuer", "Issuer"), ("audience", "Audience")]:
            pv = (p.get(field) or "").strip()
            rv = (r.get(field) or "").strip()
            if pv and rv and pv != rv:
                return Finding(
                    title=(
                        f"SAML {label} Confusion: "
                        f"primary='{pv}' vs ref[{ref_index}]='{rv}'"
                    ),
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": f"{field}_confusion",
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                    },
                )
        return None


# ── Encoding confusion ─────────────────────────────────────────


class SamlEncodingConfusionStrategy:
    """Detect encoding interpretation differences across libraries.

    BOM injection, encoding mismatch, and UTF-16/UTF-7 confusion
    cause some parsers to fail while others succeed, or both succeed
    but extract different text content.
    """

    name = "saml_encoding"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)

        # Check if input has encoding indicators
        raw = inp.data[:20]
        has_encoding_indicator = (
            raw.startswith(b"\xff\xfe")
            or raw.startswith(b"\xfe\xff")
            or raw.startswith(b"\xef\xbb\xbf")
            or b"encoding=" in inp.data[:200]
        )
        if not has_encoding_indicator:
            return None

        # One parsed, other didn't — encoding caused parse divergence
        # Only report when the parsing side accepts signature (exploitable).
        # sig=FALSE → just parser tolerance difference, skip entirely.
        if (p is not None) != (r is not None):
            parsed = p if p is not None else r
            if parsed.get("signature_valid", False):
                parsed_side = "primary" if p is not None else f"ref[{ref_index}]"
                return Finding(
                    title=(
                        f"SAML Encoding Confusion: {parsed_side} parses "
                        f"but the other fails (ref[{ref_index}])"
                    ),
                    severity=Severity.HIGH,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "encoding_parse_divergence",
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
            return None

        # Both parsed but extracted different subjects
        # Only report when at least one side validates signature
        if p is not None and r is not None:
            ps = (p.get("subject") or "").strip()
            rs = (r.get("subject") or "").strip()
            p_valid = p.get("signature_valid", False)
            r_valid = r.get("signature_valid", False)
            if ps and rs and ps != rs and (p_valid or r_valid):
                return Finding(
                    title=(
                        f"SAML Encoding Subject Confusion: "
                        f"primary='{ps}' vs ref[{ref_index}]='{rs}'"
                    ),
                    severity=Severity.HIGH,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "encoding_subject_confusion",
                        "primary_subject": ps,
                        "ref_subject": rs,
                        "ref_index": ref_index,
                    },
                )

        return None


# ── Transform chain confusion ──────────────────────────────────


class SamlTransformConfusionStrategy:
    """Detect transform chain interpretation differences.

    Non-standard transforms (XPath filter, inclusive c14n, base64)
    or missing enveloped-signature transform cause different
    signature validation outcomes across libraries.
    """

    name = "saml_transform"

    _TRANSFORM_INDICATORS = [
        b"xmldsig-filter2",
        b"REC-xml-c14n-20010315",
        b"xml-c14n11",
        b"exc-c14n#WithComments",
        b"xmldsig#base64",
    ]

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        # Only trigger on inputs with transform-related mutations
        raw = inp.data
        has_transform_indicator = any(
            ind in raw for ind in self._TRANSFORM_INDICATORS
        )
        # Also trigger if enveloped-signature is missing
        has_sig = b"<ds:Signature" in raw or b"<Signature" in raw
        no_enveloped = has_sig and b"enveloped-signature" not in raw

        if not has_transform_indicator and not no_enveloped:
            return None

        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if p is None or r is None:
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)

        if p_valid != r_valid:
            accepting = "primary" if p_valid else f"ref[{ref_index}]"
            return Finding(
                title=(
                    f"SAML Transform Confusion: {accepting} accepts "
                    f"with non-standard transform chain (ref[{ref_index}])"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "transform_confusion",
                    "primary_valid": p_valid,
                    "ref_valid": r_valid,
                    "ref_index": ref_index,
                    "no_enveloped": no_enveloped,
                    "input_preview": _input_preview(inp),
                },
            )

        return None


# ── Factory ─────────────────────────────────────────────────────


def get_saml_strategies() -> list:
    """Return DEFAULT + SAML differential strategies.

    Includes ExitCodeStrategy (accept/reject mismatch) and OutputStrategy
    (JSON field diff) from defaults alongside SAML-specific strategies.
    This ensures exit code divergences and output field differences are
    detected even when SAML-specific conditions don't trigger.
    """
    from .diff_oracle import DEFAULT_STRATEGIES
    return list(DEFAULT_STRATEGIES) + [
        SamlDiffStrategy(),
        SamlAlgorithmConfusionStrategy(),
        SamlIssuerConfusionStrategy(),
        SamlEncodingConfusionStrategy(),
        SamlTransformConfusionStrategy(),
    ]
