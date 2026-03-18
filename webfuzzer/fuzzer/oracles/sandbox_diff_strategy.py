"""Sandbox escape differential strategy.

Compares sandbox execution results across targets to detect:
  - CRITICAL: one sandbox escaped, another blocked (escape differential)
  - HIGH: different error types (behavioral divergence)
  - MEDIUM: same error type but different messages (implementation leak)
"""

from __future__ import annotations

import hashlib
from typing import Any

from webfuzzer.fuzzer.protocols import (
    ExecutionResult,
    Finding,
    Input,
    Severity,
)


class SandboxEscapeDiffStrategy:
    """Detect sandbox escape differentials between implementations."""

    name = "sandbox_escape"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | list[Finding] | None:
        p = primary.parsed_json() or {}
        r = reference.parsed_json() or {}

        p_escaped = p.get("escaped", False)
        r_escaped = r.get("escaped", False)
        p_error = p.get("type", "")
        r_error = r.get("type", "")
        p_payload = p.get("payload", "")

        findings: list[Finding] = []

        # CRITICAL: escape differential
        if p_escaped and not r_escaped:
            fp = self._fingerprint("escape", ref_index, p_payload)
            findings.append(Finding(
                title=f"Sandbox escape: primary escaped (payload={p_payload[:50]}), ref[{ref_index}] blocked",
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="sandbox",
                fingerprint=fp,
                metadata={
                    "category": "sandbox_escape",
                    "primary_escaped": True,
                    "ref_escaped": False,
                    "ref_index": ref_index,
                    "payload": p_payload[:200],
                    "primary_error": p_error,
                    "ref_error": r_error,
                },
            ))

        if not p_escaped and r_escaped:
            fp = self._fingerprint("escape_ref", ref_index, r.get("payload", ""))
            findings.append(Finding(
                title=f"Sandbox escape: ref[{ref_index}] escaped, primary blocked",
                severity=Severity.CRITICAL,
                input=inp,
                result=reference,
                oracle_name="sandbox",
                fingerprint=fp,
                metadata={
                    "category": "sandbox_escape",
                    "primary_escaped": False,
                    "ref_escaped": True,
                    "ref_index": ref_index,
                    "payload": r.get("payload", "")[:200],
                },
            ))

        # HIGH: different error types (behavioral divergence)
        if not p_escaped and not r_escaped and p_error and r_error:
            if p_error != r_error:
                fp = self._fingerprint("error_diff", ref_index,
                                        f"{p_error}:{r_error}")
                findings.append(Finding(
                    title=f"Sandbox behavioral diff: primary={p_error}, ref[{ref_index}]={r_error}",
                    severity=Severity.HIGH,
                    input=inp,
                    result=primary,
                    oracle_name="sandbox",
                    fingerprint=fp,
                    metadata={
                        "category": "sandbox_behavioral_diff",
                        "primary_error_type": p_error,
                        "ref_error_type": r_error,
                        "ref_index": ref_index,
                        "primary_error_msg": p.get("error", "")[:100],
                        "ref_error_msg": r.get("error", "")[:100],
                    },
                ))

        # MEDIUM: one errored, other succeeded (without escape)
        if not p_escaped and not r_escaped:
            p_ok = primary.exit_code == 0 and not p_error
            r_ok = reference.exit_code == 0 and not r_error
            if p_ok != r_ok:
                erroring = "primary" if not p_ok else f"ref[{ref_index}]"
                fp = self._fingerprint("accept_diff", ref_index,
                                        f"{p_ok}:{r_ok}")
                findings.append(Finding(
                    title=f"Sandbox accept/reject diff: {erroring} errored",
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=primary,
                    oracle_name="sandbox",
                    fingerprint=fp,
                    metadata={
                        "category": "sandbox_accept_reject",
                        "ref_index": ref_index,
                        "primary_ok": p_ok,
                        "ref_ok": r_ok,
                    },
                ))

        return findings if findings else None

    @staticmethod
    def _fingerprint(category: str, ref_index: int, detail: str) -> str:
        h = hashlib.md5(
            f"sandbox:{category}:{ref_index}:{detail}".encode()
        ).hexdigest()[:12]
        return f"sandbox_{category}_{h}"
