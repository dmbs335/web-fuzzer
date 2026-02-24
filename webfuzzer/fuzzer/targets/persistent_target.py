"""Persistent target — keeps a long-running subprocess alive.

Instead of spawning a new process per execution, maintains a persistent
process and communicates via a length-prefixed binary protocol over
stdin/stdout.  Eliminates process spawn + module loading overhead.

Protocol (big-endian):
    Request:  [4-byte length][input bytes]
    Response: [4-byte length][output bytes][4-byte exit code]

Usage:
    target = PersistentTarget("node targets/persistent_wrapper.js targets/sanitizer_dompurify_module.js")
    target.setup()
    result = target.execute(inp)   # ~5ms instead of ~950ms
    target.teardown()
"""

from __future__ import annotations

import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from ..protocols import ExecutionResult, Input


class PersistentTarget:
    """Fuzzing target using a persistent subprocess with binary protocol."""

    def __init__(
        self,
        command: str,
        timeout_seconds: float = 10.0,
        working_dir: Path | None = None,
    ) -> None:
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.working_dir = working_dir
        self._proc: subprocess.Popen | None = None

    def setup(self) -> None:
        self._proc = subprocess.Popen(
            self.command,
            shell=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.working_dir,
        )

    def teardown(self) -> None:
        if self._proc is not None:
            try:
                self._proc.stdin.close()
            except Exception:
                pass
            try:
                self._proc.kill()
                self._proc.wait(timeout=3)
            except Exception:
                pass
            self._proc = None

    def is_alive(self) -> bool:
        if self._proc is None:
            return False
        return self._proc.poll() is None

    def reset(self) -> None:
        self.teardown()
        self.setup()

    @property
    def pipe_handles(self) -> tuple[int, int] | None:
        """Return (stdin_handle, stdout_handle) as raw OS integers.

        On Windows: returns OS HANDLEs via msvcrt.get_osfhandle().
        On Unix: returns file descriptors via fileno().
        Returns None if process is not alive.
        """
        if self._proc is None or not self.is_alive():
            return None
        try:
            if sys.platform == "win32":
                import msvcrt
                return (msvcrt.get_osfhandle(self._proc.stdin.fileno()),
                        msvcrt.get_osfhandle(self._proc.stdout.fileno()))
            else:
                return (self._proc.stdin.fileno(), self._proc.stdout.fileno())
        except (OSError, ValueError):
            return None

    def execute(self, inp: Input) -> ExecutionResult:
        if self._proc is None or not self.is_alive():
            self.setup()

        start = time.monotonic()
        try:
            # Send: [4-byte length][data]
            data = inp.data
            header = struct.pack(">I", len(data))
            self._proc.stdin.write(header + data)
            self._proc.stdin.flush()

            # Recv: [4-byte length][output][4-byte exit_code]
            resp_header = self._read_exact(4, start)
            out_len = struct.unpack(">I", resp_header)[0]
            output = self._read_exact(out_len, start)
            exit_code_bytes = self._read_exact(4, start)
            exit_code = struct.unpack(">I", exit_code_bytes)[0]

            duration_ms = (time.monotonic() - start) * 1000
            return ExecutionResult(
                exit_code=exit_code,
                stdout=output,
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = (time.monotonic() - start) * 1000
            # Process died or timed out — restart on next call
            self.teardown()
            return ExecutionResult(
                exit_code=-1,
                stderr=str(e).encode("utf-8", errors="replace"),
                duration_ms=duration_ms,
                metadata={"error": "persistent_target_error"},
            )

    def _read_exact(self, n: int, start: float | None = None) -> bytes:
        """Read exactly n bytes from stdout, with timeout.

        Uses a background thread to avoid blocking the main thread
        if the persistent target hangs on a specific input.
        """
        result = [None]  # [bytes | Exception]

        def _reader():
            try:
                buf = b""
                while len(buf) < n:
                    chunk = self._proc.stdout.read(n - len(buf))
                    if not chunk:
                        result[0] = EOFError("Persistent target process died")
                        return
                    buf += chunk
                result[0] = buf
            except Exception as e:
                result[0] = e

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        remaining = self.timeout_seconds
        if start is not None:
            remaining = max(0.1, self.timeout_seconds - (time.monotonic() - start))
        t.join(timeout=remaining)

        if t.is_alive():
            # Read timed out — kill the stuck process
            raise TimeoutError(
                f"Persistent target read timed out after {self.timeout_seconds}s"
            )

        if isinstance(result[0], Exception):
            raise result[0]
        if result[0] is None:
            raise EOFError("Read returned no data")
        return result[0]
