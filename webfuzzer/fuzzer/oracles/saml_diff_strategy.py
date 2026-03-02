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
        # HIGH when at least one side accepts (real XSW risk),
        # MEDIUM when both reject (structural difference, lower risk).
        p_count = p.get("assertion_count", 0)
        r_count = r.get("assertion_count", 0)
        if p_count != r_count and (p_count > 0 or r_count > 0):
            severity = Severity.HIGH if (p_valid or r_valid) else Severity.MEDIUM
            return Finding(
                title=(
                    f"SAML Assertion Count Divergence: "
                    f"primary={p_count} vs ref[{ref_index}]={r_count}"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "assertion_count_divergence",
                    "primary_count": p_count,
                    "ref_count": r_count,
                    "primary_valid": p_valid,
                    "ref_valid": r_valid,
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


# ── Algorithm downgrade detection ─────────────────────────────


class SamlAlgorithmDowngradeStrategy:
    """Detect weak algorithm acceptance divergence.

    Flags when one target accepts a weak/deprecated algorithm (SHA-1,
    HMAC-SHA256 with public key, MD5, "none") while another rejects it.
    This indicates the accepting target lacks algorithm restriction —
    a common real-world vulnerability (CVE-2016-5697 pattern for HMAC,
    algorithm downgrade for SHA-1).

    Severity: CRITICAL for HMAC confusion (attacker can forge signatures
    using the public key as HMAC secret), HIGH for SHA-1/MD5 downgrade.
    """

    name = "saml_algo_downgrade"

    _WEAK_INDICATORS = [
        (b"hmac-sha", "hmac_confusion"),
        (b"hmac-sha1", "hmac_confusion"),
        (b"hmac-sha256", "hmac_confusion"),
        (b"rsa-sha1", "sha1_downgrade"),
        (b"#sha1", "sha1_downgrade"),
        (b"#md5", "md5_downgrade"),
        (b'"none"', "algo_none"),
        (b'Algorithm=""', "algo_empty"),
    ]

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        # Check if input has weak algorithm indicators
        raw = inp.data.lower()
        triggered_category = None
        for indicator, category in self._WEAK_INDICATORS:
            if indicator in raw:
                triggered_category = category
                break
        if not triggered_category:
            return None

        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if p is None or r is None:
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)

        # Only interesting if one accepts and other rejects
        if p_valid == r_valid:
            return None

        accepting = "primary" if p_valid else f"ref[{ref_index}]"
        acc_data = p if p_valid else r

        # ── False-positive guard: verify the ACCEPTING library actually
        # uses the weak algorithm.  In XSW scenarios, the weak-algorithm
        # indicator (e.g. "hmac-sha256") may appear in a non-validated
        # evil assertion while the accepting library validates a different
        # assertion signed with RSA-SHA256.  Checking the accepting
        # library's *reported* algorithm avoids this false positive.
        if triggered_category == "hmac_confusion":
            acc_algos = acc_data.get("algorithms") or {}
            acc_sig = (acc_algos.get("signature") or "").lower()
            if acc_sig and "hmac" not in acc_sig:
                # Accepting library reports a non-HMAC algorithm (e.g.
                # rsa-sha256).  The HMAC indicator in the input is in a
                # different scope — let SamlDiffStrategy handle this as
                # a regular signature_bypass.
                return None

        severity = (
            Severity.CRITICAL if triggered_category == "hmac_confusion"
            else Severity.HIGH
        )

        return Finding(
            title=(
                f"SAML Algorithm Downgrade: {accepting} accepts "
                f"{triggered_category} "
                f"(subject={acc_data.get('subject')})"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": f"algo_downgrade_{triggered_category}",
                "primary_valid": p_valid,
                "ref_valid": r_valid,
                "ref_index": ref_index,
                "downgrade_type": triggered_category,
                "input_preview": _input_preview(inp),
            },
        )


# ── KeyInfo precedence detection ─────────────────────────────


class SamlKeyInfoPrecedenceStrategy:
    """Detect KeyInfo-based signature validation divergence.

    When KeyInfo is manipulated (empty, removed, replaced with KeyValue,
    or contains a different certificate), tests whether libraries:
    - Reject: requires pre-configured cert (correct behavior)
    - Accept with embedded cert: allows attacker-supplied cert (CRITICAL)
    - Accept without KeyInfo: falls back to pre-configured cert (safe)

    The dangerous case is when a library uses the embedded X509Certificate
    from KeyInfo to validate, ignoring the pre-configured IdP cert.
    An attacker can then sign with their own key and embed their own cert.
    """

    name = "saml_keyinfo"

    _KEYINFO_INDICATORS = [
        b"<ds:KeyInfo/>",           # empty KeyInfo
        b"<ds:KeyInfo></ds:KeyInfo>",
        b"<ds:KeyValue>",           # KeyValue instead of X509
        b"<RSAKeyValue>",           # raw RSA key
    ]

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        raw = inp.data
        has_keyinfo_manipulation = any(
            ind in raw for ind in self._KEYINFO_INDICATORS
        )
        # Also check if KeyInfo is completely absent but Signature exists
        has_sig = b"<ds:Signature" in raw or b"<Signature" in raw
        no_keyinfo = has_sig and b"<ds:KeyInfo" not in raw and b"<KeyInfo" not in raw

        if not has_keyinfo_manipulation and not no_keyinfo:
            return None

        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if p is None or r is None:
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)

        if p_valid == r_valid:
            return None

        # ── False-positive guard: multi-assertion scope confusion.
        # In XSW inputs with multiple assertions, the manipulated KeyInfo
        # is typically in an evil assertion while the accepting library
        # validates a different assertion with proper KeyInfo.  This is
        # an assertion-selection divergence, not a KeyInfo precedence
        # issue.  Let SamlDiffStrategy handle it as signature_bypass.
        p_count = p.get("assertion_count", 0)
        r_count = r.get("assertion_count", 0)
        if p_count > 1 or r_count > 1:
            return None

        # ── Single-assertion case: the accepting library validates with
        # a corrupted/empty/missing KeyInfo.  Since the assertion was
        # signed with the real IdP key (and the mutation only corrupts
        # KeyInfo without providing a working attacker key), signature
        # validation succeeding proves the library uses the pre-configured
        # IdP cert, ignoring the manipulated KeyInfo.  This is the SAFE
        # behavior — downgrade from CRITICAL to HIGH.
        # The truly dangerous case (library trusts embedded attacker cert)
        # requires an attacker-signed assertion, which is tested by the
        # Golden SAML PoC, not by the fuzzer's KeyInfo corruption mutation.

        accepting = "primary" if p_valid else f"ref[{ref_index}]"
        acc_data = p if p_valid else r

        return Finding(
            title=(
                f"SAML KeyInfo Precedence: {accepting} accepts with "
                f"manipulated KeyInfo (subject={acc_data.get('subject')})"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "keyinfo_precedence",
                "primary_valid": p_valid,
                "ref_valid": r_valid,
                "ref_index": ref_index,
                "no_keyinfo": no_keyinfo,
                "keyinfo_behavior": "ignores_keyinfo",
                "input_preview": _input_preview(inp),
            },
        )


# ── Assertion selection divergence ────────────────────────────


class SamlAssertionSelectionStrategy:
    """Detect when libraries extract from different assertions.

    When multiple assertions exist (XSW attacks), different libraries
    may pick different assertions based on Reference URI matching,
    getElementById, or simple first-child selection.  This directly
    indicates XSW attack success potential.

    Requires ``assertion_id`` field in target output.
    """

    name = "saml_assertion_selection"

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

        p_aid = (p.get("assertion_id") or "").strip()
        r_aid = (r.get("assertion_id") or "").strip()

        if not p_aid or not r_aid:
            return None
        if p_aid == r_aid:
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)

        # CRITICAL when at least one side validates (real XSW risk)
        severity = Severity.CRITICAL if (p_valid or r_valid) else Severity.HIGH

        return Finding(
            title=(
                f"SAML Assertion Selection Divergence: "
                f"primary uses '{p_aid}' vs ref[{ref_index}] uses '{r_aid}'"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "assertion_selection_divergence",
                "primary_assertion_id": p_aid,
                "ref_assertion_id": r_aid,
                "primary_valid": p_valid,
                "ref_valid": r_valid,
                "primary_subject": (p.get("subject") or ""),
                "ref_subject": (r.get("subject") or ""),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


# ── Extraction method divergence ─────────────────────────────


class SamlExtractionDivergenceStrategy:
    """Detect extraction method differences within the same assertion.

    When both libraries select the same assertion (same assertion_id)
    but extract different subjects, it indicates a text extraction
    method divergence (e.g., ruby-saml .text vs itertext/textContent).

    This is CRITICAL when combined with sig=TRUE — same signed assertion,
    different identity extracted.
    """

    name = "saml_extraction"

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

        p_aid = (p.get("assertion_id") or "").strip()
        r_aid = (r.get("assertion_id") or "").strip()

        # Only fire when both extract from the SAME assertion
        if not p_aid or not r_aid or p_aid != r_aid:
            return None

        p_subject = (p.get("subject") or "").strip()
        r_subject = (r.get("subject") or "").strip()

        if not p_subject or not r_subject:
            return None
        if p_subject.lower() == r_subject.lower():
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)

        # Require at least one side to validate
        if not p_valid and not r_valid:
            return None

        return Finding(
            title=(
                f"SAML Extraction Divergence: same assertion '{p_aid}' "
                f"but primary='{p_subject}' vs ref[{ref_index}]='{r_subject}'"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "extraction_divergence",
                "assertion_id": p_aid,
                "primary_subject": p_subject,
                "ref_subject": r_subject,
                "primary_valid": p_valid,
                "ref_valid": r_valid,
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


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
        SamlAlgorithmDowngradeStrategy(),
        SamlKeyInfoPrecedenceStrategy(),
        SamlAssertionSelectionStrategy(),
        SamlExtractionDivergenceStrategy(),
    ]
