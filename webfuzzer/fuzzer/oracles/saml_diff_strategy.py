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

from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity
from ._saml_parsing import parse_saml_output as _parse_saml_output


# ── Mechanism classifiers ────────────────────────────────────────


import re as _re

# Precomputed empty-string digests used by void c14n attacks
_EMPTY_SHA256 = b"47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
_EMPTY_SHA1 = b"2jmj7l5rSw0yVb/vlWAYkK/YBwk="

# Regex to detect relative/malformed namespace URIs (void c14n indicator)
_VOID_NS_RE = _re.compile(
    rb'xmlns:\w+="(?:'
    rb'[0-9]+|'          # numeric: xmlns:x="1"
    rb'\.|'              # dot relative: xmlns:x="."
    rb'[a-z]+/[a-z]+|'   # path relative: xmlns:x="relative/path"
    rb'#|'               # fragment only: xmlns:x="#"
    rb'//|'              # scheme relative: xmlns:x="//"
    rb'\?[a-z]+|'        # query only: xmlns:x="?query"
    rb'%00|'             # null byte: xmlns:x="%00"
    rb'data:,|'          # data URI empty
    rb')"'
)

# Also detect empty xmlns: xmlns:x=""
_EMPTY_NS_RE = _re.compile(rb'xmlns:\w+=""')


def _has_void_c14n_indicators(raw: bytes) -> bool:
    """Check if input has void c14n attack indicators."""
    return bool(_VOID_NS_RE.search(raw) or _EMPTY_NS_RE.search(raw))


def _has_precomputed_empty_digest(raw: bytes) -> bool:
    """Check if input uses precomputed empty-string digest."""
    return _EMPTY_SHA256 in raw or _EMPTY_SHA1 in raw


def _saml_sig_mechanism(
    p_error: str, r_error: str, p_valid: bool,
    inp_data: bytes | None = None,
    p_data: dict | None = None, r_data: dict | None = None,
) -> str:
    # XSW detection: multiple assertions or assertion count divergence
    if inp_data:
        raw = inp_data[:8000]
        assertion_count = raw.count(b"<saml:Assertion") + raw.count(b"<Assertion")
        if assertion_count > 1:
            return "xsw"

        # Void c14n detection: relative namespace URIs or empty-string digest
        if _has_void_c14n_indicators(raw):
            if _has_precomputed_empty_digest(raw):
                return "void_c14n_precomputed"
            return "void_c14n"

    if p_data and r_data:
        p_ac = p_data.get("assertion_count", 1)
        r_ac = r_data.get("assertion_count", 1)
        if p_ac != r_ac:
            return "xsw"

    # Structural checks on error messages
    for err in (p_error or "", r_error or ""):
        el = err.lower()
        if "c14n" in el or "canonical" in el:
            return "c14n_divergence"
        if "transform" in el or "enveloped" in el:
            return "transform_mismatch"
        if "algorithm" in el or "digest" in el:
            return "algorithm_mismatch"
        if "reference" in el or "uri" in el:
            return "reference_mismatch"
        if "certificate" in el or "key" in el or "x509" in el:
            return "key_mismatch"

    return "validation_bypass" if p_valid else "parse_divergence"


def _saml_subject_mechanism(ps: str, rs: str) -> str:
    if not ps or not rs:
        return "absent_vs_present"
    if ps.lower() == rs.lower():
        return "case_normalization"
    return "extraction_divergence"


def _saml_encoding_mechanism(inp_data: bytes) -> str:
    if b"\xff\xfe" in inp_data[:4] or b"\xfe\xff" in inp_data[:4]:
        return "bom"
    if b"encoding=" in inp_data[:100]:
        return "declaration"
    return "content_encoding"


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


def _both_sig_true(p: dict | None, r: dict | None) -> bool:
    """Return True only when both parsed outputs report signature_valid=true."""
    return bool(
        p is not None
        and r is not None
        and p.get("signature_valid") is True
        and r.get("signature_valid") is True
    )


class SamlSigTrueOnlyStrategy:
    """Gate a SAML strategy so it only fires when both sides validate signatures."""

    def __init__(self, inner) -> None:
        self.inner = inner
        self.name = f"{inner.name}_sigtrue"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if not _both_sig_true(p, r):
            return None

        result = self.inner.compare(inp, primary, reference, ref_index)
        if result is None:
            return None

        # Handle both single Finding and list[Finding] from inner
        items = result if isinstance(result, list) else [result]
        for finding in items:
            finding.metadata.setdefault("campaign", "saml_sigtrue")
            finding.metadata["sigtrue_only"] = True
        return items


# ── Primary strategy: Signature Bypass + Subject Confusion ──────


class SamlDiffStrategy:
    """Primary SAML differential strategy.

    Detects signature bypass and subject confusion between two
    SAML library implementations.  These are the highest-impact
    findings (both CRITICAL) that directly enable auth bypass.

    Optionally accepts an ``acceptance_tracker`` to downgrade bypass
    findings from always-accepting targets (noise reduction).
    """

    name = "saml_bypass"

    def __init__(self, acceptance_tracker=None) -> None:
        self._tracker = acceptance_tracker

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)

        # Feed acceptance tracker if available
        if self._tracker is not None:
            if p is not None:
                self._tracker.record(0, p.get("signature_valid"))
            if r is not None:
                self._tracker.record(ref_index + 1, r.get("signature_valid"))

        # Both failed to parse — no interesting divergence
        if p is None and r is None:
            return None

        # One-sided parse: one succeeded, other totally failed
        if p is None or r is None:
            one = self._check_one_sided(inp, primary, reference, ref_index, p, r)
            return [one] if one else None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)
        p_subject = (p.get("subject") or "").strip()
        r_subject = (r.get("subject") or "").strip()

        all_findings: list[Finding] = []

        # ── CRITICAL: Signature bypass ──
        if p_valid != r_valid:
            accepting = "primary" if p_valid else f"ref[{ref_index}]"
            rejecting = f"ref[{ref_index}]" if p_valid else "primary"
            acc_data = p if p_valid else r

            # Exploit confidence: did the accepting library extract our sentinel?
            sentinel = inp.metadata.get("evil_sentinel")
            acc_subject = (acc_data.get("subject") or "")
            if sentinel and sentinel in acc_subject:
                exploit_confidence = "HIGH"
            elif p_subject != r_subject:
                exploit_confidence = "MEDIUM"
            else:
                exploit_confidence = "LOW"

            # Downgrade severity if the accepting side is always-accepting
            severity = Severity.CRITICAL
            accepting_idx = 0 if p_valid else ref_index + 1
            downgraded = False
            if (
                self._tracker is not None
                and self._tracker.is_always_accepting(accepting_idx)
            ):
                severity = Severity.MEDIUM
                downgraded = True

            all_findings.append(Finding(
                title=(
                    f"SAML Signature Bypass: {accepting} accepts "
                    f"(subject={acc_data.get('subject')}) "
                    f"but {rejecting} rejects"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "signature_bypass",
                    "exploit_confidence": exploit_confidence,
                    "primary_valid": p_valid,
                    "ref_valid": r_valid,
                    "ref_index": ref_index,
                    "primary_subject": p_subject,
                    "ref_subject": r_subject,
                    "primary_error": p.get("signature_error"),
                    "ref_error": r.get("signature_error"),
                    "input_preview": _input_preview(inp),
                    "acceptance_downgraded": downgraded,
                    "mechanism": _saml_sig_mechanism(
                        p.get("signature_error", ""),
                        r.get("signature_error", ""),
                        p_valid,
                        inp_data=inp.data,
                        p_data=p, r_data=r,
                    ),
                },
            ))

        # ── CRITICAL: Subject confusion (both accept, different NameID) ──
        if p_valid and r_valid and p_subject and r_subject:
            if p_subject.lower() != r_subject.lower():
                all_findings.append(Finding(
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
                        "mechanism": _saml_subject_mechanism(p_subject, r_subject),
                    },
                ))

        # ── MEDIUM: Subject extraction divergence (sig not required) ──
        # Different subject extraction = parsers interpret DOM differently.
        # Only emit when subject_confusion was NOT already emitted.
        if (
            p_subject and r_subject
            and p_subject.lower() != r_subject.lower()
            and not (p_valid and r_valid)
        ):
            all_findings.append(Finding(
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
                    "mechanism": "unsigned" if not p_valid and not r_valid else "signed",
                },
            ))

        # ── HIGH: Attribute confusion ──
        if p_valid and r_valid:
            p_attrs = p.get("attributes") or {}
            r_attrs = r.get("attributes") or {}
            diff_attrs = _diff_attributes(p_attrs, r_attrs)
            if diff_attrs:
                all_findings.append(Finding(
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
                        "mechanism": "count_diff" if len(diff_attrs) > 2 else "value_diff",
                    },
                ))

        # ── Assertion count divergence ──
        p_count = p.get("assertion_count", 0)
        r_count = r.get("assertion_count", 0)
        if p_count != r_count and (p_count > 0 or r_count > 0):
            severity = Severity.HIGH if (p_valid or r_valid) else Severity.MEDIUM
            all_findings.append(Finding(
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
                    "mechanism": "xsw_potential" if p_valid != r_valid else "structural",
                },
            ))

        return all_findings or None

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
                    "mechanism": "primary_accepts",
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
                    "mechanism": "ref_accepts",
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
                        "mechanism": field,
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
                        "mechanism": _saml_encoding_mechanism(inp.data),
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
                        "mechanism": _saml_encoding_mechanism(inp.data),
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
                    "mechanism": "missing_enveloped" if no_enveloped else "non_standard",
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

        # ── False-positive guard ────────────────────────────────────
        # In multi-assertion payloads the weak-algorithm indicator
        # (e.g. "hmac-sha256") often lives in a non-validated evil
        # assertion while the accepting library validates a *different*
        # assertion signed with RSA-SHA256.
        #
        # Guard 1 (existing): if the accepting library's *reported*
        #   algorithm is non-HMAC, skip.
        # Guard 2 (new): targets report `algorithms.signature` from the
        #   FIRST <SignatureMethod> element in DOM order, which in XSW
        #   payloads is typically the evil assertion's signature — not
        #   the one that was actually validated.  When there are multiple
        #   assertions AND multiple signatures, the reported algorithm is
        #   unreliable.  Cross-check by requiring the validated node's ID
        #   to appear near the weak-algorithm indicator in the raw input.
        if triggered_category == "hmac_confusion":
            # Prefer validated_signature_algorithm (set by target when
            # signature_valid=true) over algorithms.signature (first in DOM).
            validated_algo = (acc_data.get("validated_signature_algorithm") or "").lower()
            if validated_algo:
                if "hmac" not in validated_algo:
                    return None
            else:
                acc_algos = acc_data.get("algorithms") or {}
                acc_sig = (acc_algos.get("signature") or "").lower()
                if acc_sig and "hmac" not in acc_sig:
                    return None

            # Multi-assertion / multi-signature FP prevention
            acc_assertion_count = acc_data.get("assertion_count", 1) or 1
            acc_sig_count = (
                acc_data.get("signature_element_count")
                or acc_data.get("signature_count")
                or 1
            )
            if acc_assertion_count > 1 and acc_sig_count > 1:
                # The validated assertion is likely RSA-signed while the
                # HMAC indicator is in a different (evil) assertion.
                # Cross-check: does the validated assertion's ID appear
                # near the HMAC indicator in the raw input?
                validated_id = (
                    acc_data.get("validated_node_id")
                    or acc_data.get("assertion_id")
                )
                if validated_id:
                    vid_lower = validated_id.encode(
                        "utf-8", errors="replace"
                    ).lower()
                    hmac_pos = raw.find(b"hmac-sha")
                    if hmac_pos >= 0:
                        # Check ~2KB window around the HMAC indicator
                        window = raw[max(0, hmac_pos - 2000):hmac_pos + 2000]
                        if vid_lower not in window:
                            # Validated assertion is far from the HMAC
                            # indicator → FP from a different assertion.
                            return None
                else:
                    # Can't identify validated node — assume FP in
                    # multi-assertion scenarios.
                    return None

        # General multi-assertion FP guard for sha1/md5 downgrade too:
        # the weak digest/signature indicator may live in a non-validated
        # evil assertion's SignatureMethod or DigestMethod.
        if triggered_category in ("sha1_downgrade", "md5_downgrade"):
            acc_assertion_count = acc_data.get("assertion_count", 1) or 1
            acc_sig_count = (
                acc_data.get("signature_element_count")
                or acc_data.get("signature_count")
                or 1
            )
            if acc_assertion_count > 1 and acc_sig_count > 1:
                # Check that the accepting library's validated assertion
                # is near the weak-algorithm indicator in the input.
                validated_id = (
                    acc_data.get("validated_node_id")
                    or acc_data.get("assertion_id")
                )
                if validated_id:
                    vid_lower = validated_id.encode(
                        "utf-8", errors="replace"
                    ).lower()
                    # Find the weak indicator position
                    indicator_bytes = {
                        "sha1_downgrade": b"sha1",
                        "md5_downgrade": b"md5",
                    }[triggered_category]
                    ind_pos = raw.find(indicator_bytes)
                    if ind_pos >= 0:
                        window = raw[max(0, ind_pos - 2000):ind_pos + 2000]
                        if vid_lower not in window:
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
                "mechanism": triggered_category,
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
                "mechanism": "missing_keyinfo" if no_keyinfo else "manipulated_keyinfo",
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
        p_idx = p.get("selected_assertion_index")
        r_idx = r.get("selected_assertion_index")

        if p_aid and r_aid:
            if p_aid == r_aid:
                return None
            primary_selected = p_aid
            ref_selected = r_aid
        elif p_idx is not None and r_idx is not None:
            if p_idx == r_idx:
                return None
            primary_selected = f"index:{p_idx}"
            ref_selected = f"index:{r_idx}"
        else:
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)

        # CRITICAL when at least one side validates (real XSW risk)
        severity = Severity.CRITICAL if (p_valid or r_valid) else Severity.HIGH

        return Finding(
            title=(
                f"SAML Assertion Selection Divergence: "
                f"primary uses '{primary_selected}' vs ref[{ref_index}] uses '{ref_selected}'"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "assertion_selection_divergence",
                "primary_assertion_id": p_aid or None,
                "ref_assertion_id": r_aid or None,
                "primary_selected_assertion": primary_selected,
                "ref_selected_assertion": ref_selected,
                "primary_selected_assertion_index": p_idx,
                "ref_selected_assertion_index": r_idx,
                "primary_valid": p_valid,
                "ref_valid": r_valid,
                "primary_subject": (p.get("subject") or ""),
                "ref_subject": (r.get("subject") or ""),
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
                "mechanism": "id_based" if p_aid and r_aid else "index_based",
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
                "mechanism": "text_method",
            },
        )


# ── Factory ─────────────────────────────────────────────────────


class SamlReferenceScopeStrategy:
    """Detect signature Reference URI scope mismatches across libraries."""

    name = "saml_reference_scope"

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

        p_match = p.get("reference_matches_selected_assertion")
        r_match = r.get("reference_matches_selected_assertion")
        if p_match is None and r_match is None:
            return None
        if p_match == r_match:
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)
        severity = Severity.CRITICAL if (p_valid or r_valid) else Severity.HIGH

        return Finding(
            title=(
                "SAML Reference Scope Divergence: "
                f"primary={p_match} vs ref[{ref_index}]={r_match}"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "reference_scope_divergence",
                "primary_reference_match": p_match,
                "ref_reference_match": r_match,
                "primary_reference_uri": p.get("reference_uri"),
                "ref_reference_uri": r.get("reference_uri"),
                "primary_assertion_id": p.get("assertion_id"),
                "ref_assertion_id": r.get("assertion_id"),
                "primary_valid": p_valid,
                "ref_valid": r_valid,
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
                "mechanism": "uri_match" if p.get("reference_uri") else "implicit_scope",
            },
        )


class SamlVoidC14nStrategy:
    """Detect void canonicalization attack divergence.

    Void c14n exploits relative namespace URIs (e.g., xmlns:x="1")
    that cause exc-c14n to produce empty output on some implementations.
    Combined with precomputed empty-string digest, this can bypass
    signature validation entirely.

    Signals:
    - Input contains relative/malformed namespace URIs
    - Precomputed empty-string SHA-256/SHA-1 digest present
    - Libraries diverge on sig_valid (one's c14n handles it, other doesn't)
    - Both accept but one produces empty canonical output (error-free failure)
    """

    name = "saml_void_c14n"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        raw = inp.data
        has_void = _has_void_c14n_indicators(raw)
        if not has_void:
            return None

        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)

        # One side completely failed to parse
        if p is None and r is None:
            return None

        has_precomputed = _has_precomputed_empty_digest(raw)

        # Case 1: sig_valid divergence with void c14n input
        if p is not None and r is not None:
            p_valid = p.get("signature_valid", False)
            r_valid = r.get("signature_valid", False)

            if p_valid != r_valid:
                accepting = "primary" if p_valid else f"ref[{ref_index}]"
                mechanism = "void_c14n_precomputed" if has_precomputed else "void_c14n_relative_ns"
                return Finding(
                    title=(
                        f"Void C14N Bypass: {accepting} accepts with "
                        f"relative namespace URI (ref[{ref_index}])"
                    ),
                    severity=Severity.CRITICAL,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "void_c14n_bypass",
                        "primary_valid": p_valid,
                        "ref_valid": r_valid,
                        "ref_index": ref_index,
                        "has_precomputed_digest": has_precomputed,
                        "mechanism": mechanism,
                        "primary_subject": (p.get("subject") or "").strip(),
                        "ref_subject": (r.get("subject") or "").strip(),
                        "primary_error": p.get("signature_error"),
                        "ref_error": r.get("signature_error"),
                        "input_preview": _input_preview(inp),
                    },
                )

            # Case 2: Both accept but error messages differ on c14n
            if p_valid and r_valid:
                p_err = (p.get("signature_error") or "").lower()
                r_err = (r.get("signature_error") or "").lower()
                if p_err != r_err and ("c14n" in p_err or "c14n" in r_err
                                       or "canonical" in p_err or "canonical" in r_err):
                    return Finding(
                        title=(
                            f"Void C14N Divergence: both accept but "
                            f"c14n errors differ (ref[{ref_index}])"
                        ),
                        severity=Severity.HIGH,
                        input=inp,
                        result=primary,
                        oracle_name="differential",
                        metadata={
                            "strategy": self.name,
                            "category": "void_c14n_error_divergence",
                            "ref_index": ref_index,
                            "primary_error": p.get("signature_error"),
                            "ref_error": r.get("signature_error"),
                            "mechanism": "c14n_error_divergence",
                            "input_preview": _input_preview(inp),
                        },
                    )

        # Case 3: One-sided parse failure on void c14n input
        if (p is None) != (r is None):
            parsed = p if p is not None else r
            parsed_side = "primary" if p is not None else f"ref[{ref_index}]"
            failed_side = f"ref[{ref_index}]" if p is not None else "primary"
            if parsed.get("signature_valid"):
                return Finding(
                    title=(
                        f"Void C14N Parse Divergence: {parsed_side} accepts "
                        f"but {failed_side} crashes on relative NS"
                    ),
                    severity=Severity.HIGH,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "void_c14n_parse_crash",
                        "ref_index": ref_index,
                        "parsed_side": parsed_side,
                        "has_precomputed_digest": has_precomputed,
                        "mechanism": "void_c14n_crash",
                        "input_preview": _input_preview(inp),
                    },
                )

        return None


def get_saml_strategies(
    target_count: int = 0,
    *,
    include_void_c14n: bool = False,
) -> list:
    """Return DEFAULT + SAML differential strategies.

    Uses the default strategies except generic OutputStrategy, then layers
    SAML-specific strategies on top.

    If ``target_count`` > 0, creates a shared ``SamlAcceptanceTracker``
    that downgrades bypass findings from always-accepting targets.
    """
    from .diff_oracle import DEFAULT_STRATEGIES

    tracker = None
    if target_count > 0:
        from ._saml_baseline import SamlAcceptanceTracker
        tracker = SamlAcceptanceTracker(target_count)

    base = [s for s in DEFAULT_STRATEGIES if getattr(s, "name", "") != "output"]
    strategies = [
        SamlDiffStrategy(acceptance_tracker=tracker),
        SamlAlgorithmConfusionStrategy(),
        SamlIssuerConfusionStrategy(),
        SamlEncodingConfusionStrategy(),
        SamlTransformConfusionStrategy(),
        SamlAlgorithmDowngradeStrategy(),
        SamlKeyInfoPrecedenceStrategy(),
        SamlAssertionSelectionStrategy(),
        SamlReferenceScopeStrategy(),
        SamlExtractionDivergenceStrategy(),
    ]
    if include_void_c14n:
        strategies.insert(0, SamlVoidC14nStrategy())
    return base + strategies


def get_saml_sigtrue_strategies(target_count: int = 0) -> list:
    """Return SAML strategies focused only on sig=true divergence."""
    from .diff_oracle import DEFAULT_STRATEGIES

    tracker = None
    if target_count > 0:
        from ._saml_baseline import SamlAcceptanceTracker
        tracker = SamlAcceptanceTracker(target_count)

    base = [s for s in DEFAULT_STRATEGIES if getattr(s, "name", "") != "output"]
    strict = [
        SamlDiffStrategy(acceptance_tracker=tracker),
        SamlAlgorithmConfusionStrategy(),
        SamlIssuerConfusionStrategy(),
        SamlAssertionSelectionStrategy(),
        SamlReferenceScopeStrategy(),
        SamlExtractionDivergenceStrategy(),
    ]
    return base + [SamlSigTrueOnlyStrategy(s) for s in strict]
