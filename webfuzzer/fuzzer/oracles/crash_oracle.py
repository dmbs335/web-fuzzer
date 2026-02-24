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

        if exit_code == 0:
            return None

        # On Unix, negative exit_code = killed by signal
        if exit_code < 0:
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
            return Finding(
                title=f"Timeout: {result.duration_ms:.0f}ms (limit={self.timeout_ms:.0f}ms)",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={"timeout": True},
            )

        # Generic nonzero exit
        return Finding(
            title=f"Non-zero exit code: {exit_code}",
            severity=Severity.LOW,
            input=inp,
            result=result,
            oracle_name=self.name,
            metadata={"exit_code": exit_code},
        )


def _signal_name(sig_num: int) -> str:
    """Try to get human-readable signal name."""
    try:
        return signal.Signals(sig_num).name
    except (ValueError, AttributeError):
        return f"SIG{sig_num}"
