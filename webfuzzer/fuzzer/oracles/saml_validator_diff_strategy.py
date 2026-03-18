"""Validator-focused SAML differential strategies.

These strategies compare low-level XML-DSig validator state rather than
application-level SAML semantics. They are intended for campaigns that hunt
for canonicalization, reference-resolution, and transform-processing bugs.
"""

from __future__ import annotations

from ..protocols import ExecutionResult, Finding, Input, Severity
from ._saml_parsing import parse_saml_output as _parse_saml_output


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


def _both_sig_true(p: dict | None, r: dict | None) -> bool:
    return bool(
        p is not None
        and r is not None
        and p.get("signature_valid") is True
        and r.get("signature_valid") is True
    )


class SamlValidatorAcceptRejectStrategy:
    """One validator accepts the signature while another rejects it."""

    name = "saml_validator_accept"

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

        p_valid = p.get("signature_valid", False)
        r_valid = r.get("signature_valid", False)
        if p_valid == r_valid:
            return None

        accepting = p if p_valid else r
        accepting_side = "primary" if p_valid else f"ref[{ref_index}]"
        return Finding(
            title=f"SAML validator divergence: {accepting_side} accepts signature while the other rejects",
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "validator_accept_reject",
                "primary_valid": p_valid,
                "ref_valid": r_valid,
                "ref_index": ref_index,
                "primary_error": p.get("signature_error"),
                "ref_error": r.get("signature_error"),
                "validated_reference_uri": accepting.get("validated_reference_uri"),
                "validated_node_id": accepting.get("validated_node_id"),
                "input_preview": _input_preview(inp),
            },
        )


class SamlValidatorReferenceTargetStrategy:
    """Both validators accept but disagree on what node/reference was validated."""

    name = "saml_validator_reference"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if not _both_sig_true(p, r):
            return None

        fields = ("validated_reference_uri", "validated_node_id", "validated_node_tag")
        for field in fields:
            pv = p.get(field)
            rv = r.get(field)
            if pv != rv and (pv is not None or rv is not None):
                severity = Severity.CRITICAL if field == "validated_node_id" else Severity.HIGH
                return Finding(
                    title=f"SAML validator target divergence on {field}: primary={pv!r} vs ref[{ref_index}]={rv!r}",
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "validator_reference_target_divergence",
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                    },
                )
        return None


class SamlValidatorDigestStrategy:
    """Both validators accept but compute different digest input hashes."""

    name = "saml_validator_digest"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if not _both_sig_true(p, r):
            return None

        p_hash = p.get("digest_input_hash")
        r_hash = r.get("digest_input_hash")
        if p_hash and r_hash and p_hash != r_hash:
            return Finding(
                title=f"SAML validator digest-input divergence: primary={p_hash} vs ref[{ref_index}]={r_hash}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "validator_digest_input_divergence",
                    "primary_digest_input_hash": p_hash,
                    "ref_digest_input_hash": r_hash,
                    "ref_index": ref_index,
                },
            )
        return None


class SamlValidatorC14NStrategy:
    """Both validators accept but disagree on canonicalization-related state."""

    name = "saml_validator_c14n"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if not _both_sig_true(p, r):
            return None

        p_hash = p.get("signed_info_hash")
        r_hash = r.get("signed_info_hash")
        if p_hash and r_hash and p_hash != r_hash:
            return Finding(
                title=f"SAML validator SignedInfo divergence: primary={p_hash} vs ref[{ref_index}]={r_hash}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "validator_c14n_divergence",
                    "field": "signed_info_hash",
                    "primary_value": p_hash,
                    "ref_value": r_hash,
                    "ref_index": ref_index,
                },
            )

        p_method = p.get("c14n_method")
        r_method = r.get("c14n_method")
        if p_method != r_method and (p_method is not None or r_method is not None):
            return Finding(
                title=f"SAML validator canonicalization-method divergence: primary={p_method!r} vs ref[{ref_index}]={r_method!r}",
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "validator_c14n_divergence",
                    "field": "c14n_method",
                    "primary_value": p_method,
                    "ref_value": r_method,
                    "ref_index": ref_index,
                },
            )
        return None


class SamlValidatorTransformStrategy:
    """Both validators accept but process transform or ID resolution differently."""

    name = "saml_validator_transform"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_saml_output(primary.stdout)
        r = _parse_saml_output(reference.stdout)
        if not _both_sig_true(p, r):
            return None

        checks = [
            ("transform_chain", "validator_transform_divergence", Severity.HIGH),
            ("resolved_id_attribute", "validator_id_resolution_divergence", Severity.HIGH),
            ("id_resolution_mode", "validator_id_resolution_divergence", Severity.MEDIUM),
            ("key_source", "validator_key_source_divergence", Severity.HIGH),
            ("keyinfo_type", "validator_key_source_divergence", Severity.MEDIUM),
        ]
        for field, category, severity in checks:
            pv = p.get(field)
            rv = r.get(field)
            if pv != rv and (pv is not None or rv is not None):
                return Finding(
                    title=f"SAML validator state divergence on {field}: primary={pv!r} vs ref[{ref_index}]={rv!r}",
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "field": field,
                        "primary_value": pv,
                        "ref_value": rv,
                        "ref_index": ref_index,
                    },
                )
        return None


def get_saml_validator_strategies() -> list:
    """Return validator-bug-focused SAML strategies plus default checks."""
    from .diff_oracle import DEFAULT_STRATEGIES

    base = [s for s in DEFAULT_STRATEGIES if getattr(s, "name", "") != "output"]
    return base + [
        SamlValidatorAcceptRejectStrategy(),
        SamlValidatorReferenceTargetStrategy(),
        SamlValidatorDigestStrategy(),
        SamlValidatorC14NStrategy(),
        SamlValidatorTransformStrategy(),
    ]
