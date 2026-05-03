"""Process crash oracle — detects crashes via exit code and signals."""

from __future__ import annotations

import signal
import sys

from ..protocols import ExecutionResult, Finding, Input, Severity


# Signal numbers to severity mapping
_SIGNAL_SEVERITY = {
    11: Severity.CRITICAL,   # SIGSEGV
    6: Severity.HIGH,        # SIGABRT
    8: Severity.HIGH,        # SIGFPE
    4: Severity.HIGH,        # SIGILL
    7: Severity.MEDIUM,      # SIGBUS
}


class CrashOracle:
    """Detects crashes based on exit code and signal number.

    Severity mapping:
      SIGSEGV      → CRITICAL
      SIGABRT/FPE  → HIGH
      timeout      → MEDIUM
      nonzero exit → LOW
    """

    name = "crash"

    def __init__(self, timeout_ms: float = 0) -> None:
        self.timeout_ms = timeout_ms

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        exit_code = result.exit_code
        result_meta = result.metadata or {}

        if exit_code == 0:
            return None

        error_type = str(result_meta.get("error_type", "") or "")
        error_message = str(result_meta.get("error", "") or "") or (
            result.stderr.decode("utf-8", errors="replace")[:160] if result.stderr else ""
        )

        # On Unix, negative exit_code = killed by signal
        if exit_code < 0:
            if error_type == "TimeoutError":
                timeout_meta = {
                    "timeout": True,
                    "error_type": error_type,
                    "error_message": error_message,
                }
                timeout_meta.update(_extract_waf_timeout_metadata(inp))
                return Finding(
                    title=f"Timeout: {result.duration_ms:.0f}ms",
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata=timeout_meta,
                )
            sig_num = -exit_code
            severity = _SIGNAL_SEVERITY.get(sig_num, Severity.MEDIUM)
            sig_name = _signal_name(sig_num)
            return Finding(
                title=f"Crash: signal {sig_name} ({sig_num})",
                severity=severity,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={"signal": sig_num, "signal_name": sig_name},
            )

        # Timeout detection
        if self.timeout_ms and result.duration_ms >= self.timeout_ms:
            timeout_meta = {
                "timeout": True,
                "error_type": error_type,
                "error_message": error_message,
            }
            timeout_meta.update(_extract_waf_timeout_metadata(inp))
            return Finding(
                title=f"Timeout: {result.duration_ms:.0f}ms (limit={self.timeout_ms:.0f}ms)",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata=timeout_meta,
            )

        # Some wrappers emit structured JSON for the real target outcome but
        # still exit nonzero (for example, a supervising harness or adapter
        # failed after the response was already captured). Treat those as
        # non-crash outcomes unless we also have stderr/error metadata.
        if (
            exit_code > 0
            and not error_type
            and not error_message
            and result.parsed_json() is not None
        ):
            return None

        # Generic nonzero exit
        return Finding(
            title=f"Non-zero exit code: {exit_code}",
            severity=Severity.LOW,
            input=inp,
            result=result,
            oracle_name=self.name,
            metadata={
                "exit_code": exit_code,
                "error_type": error_type,
                "error_message": error_message,
            },
        )


def _signal_name(sig_num: int) -> str:
    """Try to get human-readable signal name."""
    try:
        return signal.Signals(sig_num).name
    except (ValueError, AttributeError):
        return f"SIG{sig_num}"


def _extract_waf_timeout_metadata(inp: Input) -> dict[str, object]:
    meta = _extract_waf_timeout_metadata_from_headers(inp)
    meta = _merge_waf_timeout_metadata_from_input(meta, inp)
    return meta


def _extract_waf_timeout_metadata_from_headers(inp: Input) -> dict[str, object]:
    data = getattr(inp, "data", b"") or b""
    if b"X-WF-" not in data:
        return {}

    try:
        head = data.split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        if len(lines) == 1:
            head = data.split(b"\n\n", 1)[0]
            lines = head.split(b"\n")
    except Exception:
        return {}

    meta: dict[str, object] = {}
    for raw_line in lines[1:]:
        if b":" not in raw_line:
            continue
        name, value = raw_line.split(b":", 1)
        lower_name = name.strip().lower()
        decoded = value.strip().decode("latin-1", errors="replace")
        if lower_name == b"x-wf-family":
            meta["waf_timeout_family"] = decoded
        elif lower_name == b"x-wf-axis-evasion":
            meta["waf_timeout_axis_evasion"] = decoded
        elif lower_name == b"x-wf-axis-parser":
            meta["waf_timeout_axis_parser"] = decoded
        elif lower_name == b"x-wf-axis-variant":
            meta["waf_timeout_axis_variant"] = decoded
        elif lower_name == b"x-wf-transforms":
            meta["waf_timeout_transforms"] = sorted(
                part.strip() for part in decoded.split(",") if part.strip()
            )
    return meta


def _merge_waf_timeout_metadata_from_input(
    current: dict[str, object],
    inp: Input,
) -> dict[str, object]:
    """Backfill timeout family metadata from Input.metadata when headers are lost."""
    meta = dict(current)
    input_meta = getattr(inp, "metadata", {}) or {}

    if not meta.get("waf_timeout_family"):
        family = str(
            input_meta.get("variant_family")
            or input_meta.get("technique_family")
            or ""
        ).strip()
        if family:
            meta["waf_timeout_family"] = family

    if not meta.get("waf_timeout_axis_evasion"):
        evasion = str(input_meta.get("axis_evasion") or "").strip()
        if evasion:
            meta["waf_timeout_axis_evasion"] = evasion

    if not meta.get("waf_timeout_axis_parser"):
        parser = str(input_meta.get("axis_parser") or "").strip()
        if parser:
            meta["waf_timeout_axis_parser"] = parser

    if not meta.get("waf_timeout_axis_variant"):
        variant = str(input_meta.get("axis_variant") or "").strip()
        if variant:
            meta["waf_timeout_axis_variant"] = variant

    if not meta.get("waf_timeout_transforms"):
        transforms = input_meta.get("applied_transforms") or []
        if isinstance(transforms, list):
            cleaned = sorted(str(part).strip() for part in transforms if str(part).strip())
            if cleaned:
                meta["waf_timeout_transforms"] = cleaned

    return meta
