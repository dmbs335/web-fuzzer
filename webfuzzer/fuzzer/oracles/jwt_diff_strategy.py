"""JWT differential strategies for cross-library comparison.

Architecture mirrors SAML oracle patterns:
- Per-attack-class strategies with input-level gating
- SigTrueOnly wrapper for claim confusion (both sides must accept)
- exploit_confidence scoring via evil sentinel injection
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_jwt_output(stdout: bytes) -> dict | None:
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and (
            "signature_valid" in data
            or "effective_alg" in data
            or "sub" in data
        ):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


def _is_cross_config_noise(accepting: dict, rejecting: dict) -> bool:
    """Detect cross-configuration noise in signature_valid divergence.

    When comparing targets with different algorithm allowlists (e.g. HMAC-only
    vs RSA-only), signature divergence on standard tokens is expected — not a
    vulnerability. We detect this when:
    1. Accepting side used header_alg as-is (no algorithm confusion)
    2. Rejecting side's error mentions algorithm/allowlist issues

    Returns True if the divergence is likely cross-config noise.
    """
    acc_effective = str(accepting.get("effective_alg") or "").strip()
    acc_header = str(accepting.get("header_alg") or "").strip()

    # If accepting side shows algorithm confusion (effective != header),
    # this is interesting regardless of config
    if acc_effective and acc_header and acc_effective.lower() != acc_header.lower():
        return False

    # Check rejecting side's error for algorithm-related messages
    sig_error = str(rejecting.get("signature_error") or "").lower()
    alg_error_patterns = (
        "algorithm", "alg", "invalid_algorithm", "not allowed",
        "not supported", "unsupported", "invalidalgorithm",
    )
    if any(pat in sig_error for pat in alg_error_patterns):
        return True

    return False


def _exploit_confidence(inp: Input, accepting_data: dict) -> str:
    """Score exploit confidence based on sentinel extraction."""
    sentinel = inp.metadata.get("jwt_evil_sentinel") if inp.metadata else None
    if sentinel and str(accepting_data.get("sub", "")).find(sentinel) >= 0:
        return "HIGH"
    if accepting_data.get("signature_valid") and accepting_data.get("sub"):
        return "MEDIUM"
    return "LOW"


def _sig_bypass_mechanism(
    p_alg: str, r_alg: str, p_valid: bool, r_valid: bool,
    acc_data: dict | None = None,
) -> str:
    acc_alg = (p_alg if p_valid else r_alg or "").lower()
    if acc_alg == "none" or acc_alg == "":
        return "alg_none"
    # JWK injection — accepting side used inline jwk/jku from header
    if acc_data:
        ks = (acc_data.get("key_source") or "").lower()
        if ks in ("jwk", "jku", "x5u", "x5c"):
            return "key_injection"
    p_fam = (p_alg or "")[:2].upper()
    r_fam = (r_alg or "")[:2].upper()
    if p_fam == "HS" and r_fam == "RS":
        return "hmac_rsa_confusion"
    if p_fam == "RS" and r_fam == "HS":
        return "hmac_rsa_confusion"
    if p_fam != r_fam and p_fam and r_fam:
        return "algorithm_swap"
    return "verification_skip"


def _claim_mechanism(pv, rv) -> str:
    ps, rs = str(pv), str(rv)
    if not ps or not rs:
        return "absent_vs_present"
    if ps.lower() == rs.lower():
        return "case_folding"
    if "%" in ps or "%" in rs:
        return "encoding"
    if len(ps) > 2 * len(rs) or len(rs) > 2 * len(ps):
        return "truncation"
    return "value_diff"


def _alg_mechanism(p_alg: str, r_alg: str) -> str:
    pl, rl = (p_alg or "").lower(), (r_alg or "").lower()
    p_fam, r_fam = pl[:2], rl[:2]
    if p_fam == "hs" and r_fam == "rs":
        return "hmac_from_rsa"
    if p_fam == "rs" and r_fam == "hs":
        return "rsa_from_hmac"
    if p_fam == r_fam:
        return "variant_within_family"
    if "none" in (pl, rl):
        return "alg_none"
    return "unrelated"


def _temporal_mechanism(p_exp_state, r_exp_state) -> str:
    if not p_exp_state or not r_exp_state:
        return "missing_claim"
    return "tolerance_diff"


# ---------- SigTrueOnly Wrapper ----------


class JwtSigTrueOnlyWrapper:
    """Gate: only fires when both sides report signature_valid=True.

    Catches the highest-value class: both libraries accepted the token
    but extracted different claims. This is always a real bug, never
    an intentional design difference.
    """

    def __init__(self, inner) -> None:
        self.inner = inner
        self.name = f"{inner.name}_sigtrue"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | list[Finding] | None:
        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if not (
            p and r
            and p.get("signature_valid") is True
            and r.get("signature_valid") is True
        ):
            return None
        return self.inner.compare(inp, primary, reference, ref_index)


# ---------- Per-Attack-Class Strategies ----------


class JwtSignatureBypassStrategy:
    """Detect signature_valid divergence between libraries."""

    name = "jwt_bypass"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)

        # One side fails to parse entirely
        if p is None and r is None:
            return None
        if p is None or r is None:
            parsed = p if p is not None else r
            if parsed is not None and parsed.get("signature_valid"):
                accepting = "primary" if p is not None else f"ref[{ref_index}]"
                return Finding(
                    title=f"JWT One-Sided Accept: {accepting} validates token while the other fails to parse",
                    severity=Severity.HIGH,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "one_sided_accept",
                        "mechanism": "primary_accepts" if p is not None else "ref_accepts",
                        "exploit_confidence": _exploit_confidence(inp, parsed),
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
            return None

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)
        if p_valid != r_valid:
            accepting = "primary" if p_valid else f"ref[{ref_index}]"
            acc_data = p if p_valid else r
            rej_data = r if p_valid else p

            # Profile gating: suppress cross-config noise when targets have
            # different algorithm allowlists (e.g. HMAC-only vs RSA-only)
            if _is_cross_config_noise(acc_data, rej_data):
                return None

            return Finding(
                title=f"JWT Signature Bypass: {accepting} accepts but the other rejects",
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "signature_bypass",
                    "mechanism": _sig_bypass_mechanism(
                        p.get("effective_alg") or p.get("header_alg") or "",
                        r.get("effective_alg") or r.get("header_alg") or "",
                        p_valid, r_valid,
                        acc_data=acc_data,
                    ),
                    "exploit_confidence": _exploit_confidence(inp, acc_data),
                    "primary_valid": p_valid,
                    "ref_valid": r_valid,
                    "primary_alg": p.get("effective_alg") or p.get("header_alg"),
                    "ref_alg": r.get("effective_alg") or r.get("header_alg"),
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )
        return None


class JwtClaimConfusionStrategy:
    """Detect claim value divergence when both sides accept.

    Should be wrapped in JwtSigTrueOnlyWrapper — claim confusion only
    matters when both libraries accepted the token as valid.
    """

    name = "jwt_claim_confusion"

    _IDENTITY_FIELDS = [
        ("sub", "subject_confusion", Severity.CRITICAL),
        ("role", "role_confusion", Severity.HIGH),
        ("scope", "scope_confusion", Severity.HIGH),
        ("iss", "issuer_confusion", Severity.MEDIUM),
        ("aud", "audience_confusion", Severity.MEDIUM),
    ]

    _TEMPORAL_FIELDS = [
        ("exp", "temporal_value_confusion", Severity.HIGH),
        ("iat", "temporal_value_confusion", Severity.MEDIUM),
        ("nbf", "temporal_value_confusion", Severity.MEDIUM),
    ]

    @staticmethod
    def _numeric_equal(a, b) -> bool:
        """Compare numeric claim values with tolerance for float/int coercion."""
        try:
            return float(a) == float(b)
        except (TypeError, ValueError):
            return False

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | None:
        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        all_findings: list[Finding] = []

        # Identity / authorization fields — string comparison
        for field, category, severity in self._IDENTITY_FIELDS:
            pv = p.get(field)
            rv = r.get(field)
            if pv is not None and rv is not None and pv != rv:
                all_findings.append(Finding(
                    title=f"JWT {field} confusion: primary={pv!r} vs ref[{ref_index}]={rv!r}",
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "mechanism": _claim_mechanism(pv, rv),
                        "exploit_confidence": _exploit_confidence(inp, p),
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                    },
                ))

        # Temporal fields — numeric comparison (ignore int/float type diffs)
        for field, category, severity in self._TEMPORAL_FIELDS:
            pv = p.get(field)
            rv = r.get(field)
            if pv is None or rv is None:
                continue
            if pv == rv:
                continue
            # Skip if numerically equal (e.g. 1700000000 vs 1700000000.0)
            if self._numeric_equal(pv, rv):
                continue
            all_findings.append(Finding(
                title=f"JWT {field} value confusion: primary={pv!r} vs ref[{ref_index}]={rv!r}",
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": category,
                    "mechanism": _claim_mechanism(pv, rv),
                    "exploit_confidence": _exploit_confidence(inp, p),
                    "field": field,
                    "primary_value": pv,
                    "ref_value": rv,
                    "ref_index": ref_index,
                },
            ))

        # Nested claim type divergence — when claim_types shows different
        # types for the same field, the libraries parsed the structure
        # differently (e.g. string vs object vs array)
        p_types = p.get("claim_types")
        r_types = r.get("claim_types")
        if isinstance(p_types, dict) and isinstance(r_types, dict):
            for field in sorted(set(p_types) & set(r_types)):
                pt = JwtClaimTypeStrategy._normalize_type(p_types[field])
                rt = JwtClaimTypeStrategy._normalize_type(r_types[field])
                if pt is not None and rt is not None and pt != rt:
                    # Only add if not already covered by identity/temporal
                    covered = {f for f, _, _ in self._IDENTITY_FIELDS} | {
                        f for f, _, _ in self._TEMPORAL_FIELDS
                    }
                    if field not in covered:
                        all_findings.append(Finding(
                            title=f"JWT nested claim type divergence on {field}: {pt} vs {rt}",
                            severity=Severity.HIGH,
                            input=inp,
                            result=primary,
                            oracle_name="differential",
                            metadata={
                                "strategy": self.name,
                                "category": "nested_type_confusion",
                                "mechanism": f"{pt}_to_{rt}",
                                "field": field,
                                "primary_type": pt,
                                "ref_type": rt,
                                "ref_index": ref_index,
                            },
                        ))

        return all_findings or None


class JwtAlgorithmDivergenceStrategy:
    """Detect algorithm handling divergence.

    Input gate: only fires when input contains an alg field.
    """

    name = "jwt_alg_divergence"

    _GATE_BYTES = [b'"alg"', b'"ALG"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | None:
        # Input-level gate
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        all_findings: list[Finding] = []
        for field, category, severity in [
            ("effective_alg", "algorithm_confusion", Severity.CRITICAL),
            ("header_alg", "algorithm_confusion", Severity.HIGH),
        ]:
            pv = p.get(field)
            rv = r.get(field)
            if pv != rv and (pv is not None or rv is not None):
                all_findings.append(Finding(
                    title=f"JWT algorithm divergence on {field}: primary={pv!r} vs ref[{ref_index}]={rv!r}",
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "mechanism": _alg_mechanism(pv, rv),
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                ))
        return all_findings or None


class JwtKeySourceDivergenceStrategy:
    """Detect key resolution divergence.

    Input gate: only fires when input contains key source indicators.
    """

    name = "jwt_key_source"

    _GATE_BYTES = [b'"jku"', b'"jwk"', b'"x5u"', b'"x5c"', b'"kid"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        for field, category, severity in [
            ("key_source", "key_confusion", Severity.CRITICAL),
            ("resolved_kid", "key_confusion", Severity.HIGH),
        ]:
            pv = p.get(field)
            rv = r.get(field)
            if pv != rv and (pv is not None or rv is not None):
                return Finding(
                    title=f"JWT key source divergence on {field}: primary={pv!r} vs ref[{ref_index}]={rv!r}",
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "mechanism": "key_source" if field == "key_source" else "kid_resolution",
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
        return None


class JwtHeaderPolicyStrategy:
    """Detect header processing divergence (typ, cty, crit, nested).

    Should be wrapped in JwtSigTrueOnlyWrapper for noise reduction.
    """

    name = "jwt_header_policy"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | None:
        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        checks = [
            ("token_type_observed", "token_type_confusion", Severity.CRITICAL),
            ("nested_jwt", "nested_token_confusion", Severity.HIGH),
            ("inner_signature_valid", "nested_token_confusion", Severity.CRITICAL),
            ("typ", "header_policy_confusion", Severity.MEDIUM),
            ("cty", "header_policy_confusion", Severity.MEDIUM),
            ("crit_processed", "header_policy_confusion", Severity.HIGH),
            ("b64_mode", "header_policy_confusion", Severity.HIGH),
        ]
        # Fields where None and "" should be treated as equivalent
        _normalize_empty = {"typ", "cty"}
        all_findings: list[Finding] = []
        for field, category, severity in checks:
            pv = p.get(field)
            rv = r.get(field)
            # Normalize None/"" equivalence for typ/cty
            if field in _normalize_empty:
                pv = pv or None
                rv = rv or None
            if pv != rv and (pv is not None or rv is not None):
                all_findings.append(Finding(
                    title=f"JWT header policy divergence on {field}: primary={pv!r} vs ref[{ref_index}]={rv!r}",
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "mechanism": field,
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                ))
        return all_findings or None


class JwtTemporalConfusionStrategy:
    """Detect temporal validation divergence.

    Input gate: only fires when input manipulates time claims.
    Should be wrapped in JwtSigTrueOnlyWrapper.
    """

    name = "jwt_temporal"

    _GATE_BYTES = [b'"exp"', b'"nbf"', b'"iat"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        if p.get("time_valid") != r.get("time_valid"):
            return Finding(
                title=f"JWT temporal validation divergence: primary={p.get('time_valid')} vs ref[{ref_index}]={r.get('time_valid')}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "temporal_confusion",
                    "mechanism": _temporal_mechanism(p.get("exp_state"), r.get("exp_state")),
                    "primary_time_valid": p.get("time_valid"),
                    "ref_time_valid": r.get("time_valid"),
                    "primary_exp_state": p.get("exp_state"),
                    "ref_exp_state": r.get("exp_state"),
                    "ref_index": ref_index,
                },
            )
        return None


class JwtDuplicateKeyStrategy:
    """Detect duplicate claim/header parsing differences.

    Input gate: only fires when input contains duplicate key indicators.
    """

    name = "jwt_duplicate_keys"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        # Input gate: check for duplicate key indicators
        raw = inp.data
        has_dup = (
            raw.count(b'"role"') > 1
            or raw.count(b'"kid"') > 1
            or raw.count(b'"sub"') > 1
            or raw.count(b'"exp"') > 1
            or raw.count(b'"alg"') > 1
        )
        if not has_dup:
            return None

        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        fields = [
            "duplicate_header_keys",
            "duplicate_claim_keys",
            "claim_parse_mode",
        ]
        for field in fields:
            pv = p.get(field)
            rv = r.get(field)
            if pv != rv and (pv is not None or rv is not None):
                return Finding(
                    title=f"JWT duplicate-key handling divergence on {field}",
                    severity=Severity.HIGH,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "duplicate_key_confusion",
                        "mechanism": field,
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
        return None


class JwtClaimTypeStrategy:
    """Detect claim type divergence when both sides accept.

    Targets emit claim_types: {"sub": "string", "exp": "number"}.
    When library A sees sub as "string" and library B sees it as "null",
    that's a type coercion differential — real exploit potential.

    Should be wrapped in JwtSigTrueOnlyWrapper.
    """

    name = "jwt_claim_type"

    _FIELD_PRIORITY = [
        ("sub", Severity.CRITICAL),
        ("role", Severity.HIGH),
        ("scope", Severity.HIGH),
        ("exp", Severity.HIGH),
        ("iss", Severity.MEDIUM),
        ("aud", Severity.MEDIUM),
    ]

    # Cross-language type name equivalences (Node vs Python vs Go vs etc.)
    _TYPE_ALIASES: dict[str, str] = {
        "str": "string",
        "int": "number",
        "float": "number",
        "long": "number",
        "double": "number",
        "bool": "boolean",
        "dict": "object",
        "list": "array",
        "NoneType": "null",
        "none": "null",
        "nil": "null",
        "undefined": "null",
    }

    @classmethod
    def _normalize_type(cls, t: str | None) -> str | None:
        if t is None:
            return None
        return cls._TYPE_ALIASES.get(t, t)

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        p_types = p.get("claim_types")
        r_types = r.get("claim_types")
        if not isinstance(p_types, dict) or not isinstance(r_types, dict):
            return None

        for field, severity in self._FIELD_PRIORITY:
            pt = self._normalize_type(p_types.get(field))
            rt = self._normalize_type(r_types.get(field))
            if pt is not None and rt is not None and pt != rt:
                return Finding(
                    title=f"JWT claim type divergence on {field}: primary={pt!r} vs ref[{ref_index}]={rt!r}",
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "claim_type_confusion",
                        "mechanism": f"{pt}_to_{rt}",
                        "field": field,
                        "primary_type": pt,
                        "ref_type": rt,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
        return None


class JwtZipConfusionStrategy:
    """Detect zip-in-JWS format confusion.

    RFC 7516 §4.1.3: zip is JWE-only. If a JWS token contains zip
    and one library processes it (decompresses) while another ignores it,
    that's a format confusion vulnerability.
    """

    name = "jwt_zip_confusion"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if b'"zip"' not in inp.data:
            return None

        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        p_zip = p.get("zip_processed")
        r_zip = r.get("zip_processed")
        if p_zip != r_zip and (p_zip is not None or r_zip is not None):
            return Finding(
                title=f"JWT zip-in-JWS format confusion: primary={p_zip!r} vs ref[{ref_index}]={r_zip!r}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "zip_format_confusion",
                    "mechanism": "compression_divergence",
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )
        return None


class JwtPayloadContentStrategy:
    """Detect payload content divergence when both sides accept (exit_code=0).

    Complements JwtClaimConfusionStrategy by comparing raw payload content
    rather than individual fields. Catches truncation, normalization,
    and duplicate-key handling differences.
    """

    name = "jwt_payload_content"

    # Fields to compare for content divergence
    _CONTENT_FIELDS = [
        ("sub", "subject_content", Severity.CRITICAL),
        ("role", "role_content", Severity.HIGH),
        ("scope", "scope_content", Severity.HIGH),
        ("iss", "issuer_content", Severity.MEDIUM),
        ("aud", "audience_content", Severity.MEDIUM),
    ]

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | None:
        # Only when both sides successfully parsed
        if primary.exit_code != 0 or reference.exit_code != 0:
            return None

        p = _parse_jwt_output(primary.stdout)
        r = _parse_jwt_output(reference.stdout)
        if p is None or r is None:
            return None

        all_findings: list[Finding] = []
        # Compare string representation length differences (truncation detection)
        for field, category, severity in self._CONTENT_FIELDS:
            pv = p.get(field)
            rv = r.get(field)
            if pv is None or rv is None:
                continue
            ps, rs = str(pv), str(rv)
            if ps == rs:
                continue

            # Skip JSON key-ordering false positives for dict values
            if isinstance(pv, dict) and isinstance(rv, dict) and pv == rv:
                continue

            # Classify the divergence type
            if len(ps) > 2 * len(rs) or len(rs) > 2 * len(ps):
                mechanism = "truncation"
            elif ps.lower() == rs.lower():
                mechanism = "case_normalization"
            elif type(pv) != type(rv):
                mechanism = "type_coercion"
            else:
                mechanism = "content_diff"

            all_findings.append(Finding(
                title=f"JWT payload content divergence on {field}: len={len(ps)} vs len={len(rs)}",
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": category,
                    "mechanism": mechanism,
                    "field": field,
                    "primary_value": ps[:100],
                    "ref_value": rs[:100],
                    "primary_len": len(ps),
                    "ref_len": len(rs),
                    "ref_index": ref_index,
                },
            ))
        return all_findings or None


def get_jwt_strategies() -> list:
    """Return JWT-focused differential strategies plus default non-output checks.

    Architecture:
    - JwtSignatureBypassStrategy: ungated, detects sig_valid divergence
    - JwtAlgorithmDivergenceStrategy: input-gated on alg bytes
    - JwtKeySourceDivergenceStrategy: input-gated on key source bytes
    - JwtClaimConfusionStrategy: wrapped in SigTrueOnly (both must accept)
    - JwtHeaderPolicyStrategy: wrapped in SigTrueOnly (noise reduction)
    - JwtTemporalConfusionStrategy: wrapped in SigTrueOnly + input-gated
    - JwtDuplicateKeyStrategy: input-gated on duplicate key bytes
    - JwtPayloadContentStrategy: wrapped in SigTrueOnly, exit_code gated
    """
    from .diff_oracle import DEFAULT_STRATEGIES

    base = [s for s in DEFAULT_STRATEGIES if getattr(s, "name", "") != "output"]
    return base + [
        JwtSignatureBypassStrategy(),
        JwtAlgorithmDivergenceStrategy(),
        JwtKeySourceDivergenceStrategy(),
        JwtSigTrueOnlyWrapper(JwtClaimConfusionStrategy()),
        JwtSigTrueOnlyWrapper(JwtHeaderPolicyStrategy()),
        JwtSigTrueOnlyWrapper(JwtTemporalConfusionStrategy()),
        JwtDuplicateKeyStrategy(),
        JwtSigTrueOnlyWrapper(JwtClaimTypeStrategy()),
        JwtSigTrueOnlyWrapper(JwtZipConfusionStrategy()),
        JwtSigTrueOnlyWrapper(JwtPayloadContentStrategy()),
    ]
