"""Persistent target — keeps a long-running subprocess alive.

Instead of spawning a new process per execution, maintains a persistent
process and communicates via a length-prefixed binary protocol over
stdin/stdout.  Eliminates process spawn + module loading overhead.

Protocol (big-endian):
    Request:  [4-byte length][input bytes]
    Response: [4-byte length][output bytes][4-byte exit code]

Extended protocol (backward-compatible):
    If exit_code has bit 0x01000000 set, coverage data follows:
    Response: [4B len][output][4B exit_code|0x01000000][4B cov_len][coverage bytes]
    The real exit code is exit_code & 0x00FFFFFF.

Usage:
    target = PersistentTarget("node targets/persistent_wrapper.js targets/sanitizer_dompurify_module.js")
    target.setup()
    result = target.execute(inp)   # ~5ms instead of ~950ms
    target.teardown()
"""

from __future__ import annotations

import atexit
import logging
import os
import shlex
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from ..protocols import ExecutionResult, Input

logger = logging.getLogger(__name__)

# Global registry of all live PersistentTarget instances for atexit cleanup.
_live_targets: list[PersistentTarget] = []


def _atexit_cleanup() -> None:
    """Kill all live persistent target process trees on interpreter exit."""
    for target in list(_live_targets):
        try:
            target.teardown()
        except Exception:
            pass


atexit.register(_atexit_cleanup)


def _kill_process_tree(pid: int) -> None:
    """Kill a process and all its children (cross-platform).

    On Windows, shell=True spawns cmd.exe → node.exe.  A plain proc.kill()
    only kills cmd.exe, leaving node.exe (and its children like Chromium)
    as orphans.  taskkill /T kills the entire tree.
    """
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        # Unix: kill the process group
        import os
        import signal
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _read_nbytes(stream, n: int) -> bytes:
    """Read exactly *n* bytes from an unbuffered stream."""
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError("Persistent target process died")
        buf += chunk
    return buf


class PersistentTarget:
    """Fuzzing target using a persistent subprocess with binary protocol."""

    # Restart the subprocess every N executions to cap memory growth.
    # Typical target processes leak 1-5 KB/exec; at 50K execs this limits
    # peak RSS to ~250 MB above baseline before recycling.
    RESTART_EVERY: int = 50_000

    # RSS threshold in bytes.  If the subprocess exceeds this, restart
    # immediately instead of waiting for the counter.  Default 512 MB.
    MAX_RSS_BYTES: int = 512 * 1024 * 1024

    # Check RSS every N executions (psutil call has ~0.2ms overhead).
    RSS_CHECK_EVERY: int = 1_000

    def __init__(
        self,
        command: str,
        timeout_seconds: float = 10.0,
        working_dir: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.command = command
        self.timeout_seconds = timeout_seconds
        self.working_dir = working_dir
        self.env = env
        self._proc: subprocess.Popen | None = None
        self._exec_count: int = 0
        self._consecutive_crashes: int = 0
        self._has_psutil: bool = False
        try:
            import psutil  # noqa: F401
            self._has_psutil = True
        except ImportError:
            pass

    def setup(self) -> None:
        # Parse command string into list to avoid shell=True, which on
        # Windows spawns cmd.exe as intermediary — making proc.kill()
        # unable to reach the actual child (node/ruby/java), causing
        # orphan process accumulation (fork bomb).
        if sys.platform == "win32":
            # shlex.split doesn't handle Windows paths well; use simple split
            # but preserve quoted arguments.
            cmd_list = shlex.split(self.command, posix=False)
        else:
            cmd_list = shlex.split(self.command)

        popen_kwargs = dict(
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=self.working_dir,
            bufsize=0,  # Unbuffered: prevents Python BufferedReader readahead
                        # that steals pipe data from Rust parallel_pipe_execute.
        )
        if self.env:
            popen_kwargs["env"] = {**os.environ, **self.env}

        # Unix: create new process group for clean tree kill
        if sys.platform != "win32":
            import os
            popen_kwargs["preexec_fn"] = os.setsid

        self._proc = subprocess.Popen(cmd_list, **popen_kwargs)
        _live_targets.append(self)

        # Warmup: send a minimal request to ensure module is fully loaded.
        # This absorbs slow startup (Ruby ~800ms, Node ~300ms) so that
        # real requests can use the short timeout.
        self._warmup()

    def _warmup(self) -> None:
        """Send a dummy request to let the process finish loading."""
        warmup_data = b"<x/>"
        try:
            header = struct.pack(">I", len(warmup_data))
            self._proc.stdin.write(header + warmup_data)
            self._proc.stdin.flush()
            result = [None]

            def _reader():
                try:
                    h = _read_nbytes(self._proc.stdout, 4)
                    out_len = struct.unpack(">I", h)[0]
                    _read_nbytes(self._proc.stdout, out_len)  # body
                    ec_bytes = _read_nbytes(self._proc.stdout, 4)  # exit code
                    raw_exit = struct.unpack(">I", ec_bytes)[0]
                    # Drain extended coverage data if present
                    if raw_exit & self._COV_FLAG:
                        cov_len_b = _read_nbytes(self._proc.stdout, 4)
                        cov_len = struct.unpack(">I", cov_len_b)[0]
                        if cov_len > 0:
                            _read_nbytes(self._proc.stdout, cov_len)
                    result[0] = True
                except Exception:
                    pass

            t = threading.Thread(target=_reader, daemon=True)
            t.start()
            t.join(timeout=5.0)  # 5s generous startup timeout
        except Exception:
            pass  # Warmup failure is non-fatal; target will restart on next use

    def teardown(self) -> None:
        if self._proc is not None:
            pid = self._proc.pid
            try:
                self._proc.stdin.close()
            except Exception:
                pass
            try:
                # Kill entire process tree (node, chromium, etc.)
                _kill_process_tree(pid)
                self._proc.wait(timeout=3)
            except Exception:
                # Fallback: direct kill if tree kill failed
                try:
                    self._proc.kill()
                    self._proc.wait(timeout=3)
                except Exception:
                    pass
            self._proc = None
            # Remove from global live registry
            try:
                _live_targets.remove(self)
            except ValueError:
                pass

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

    def _should_restart(self) -> bool:
        """Return True if the subprocess should be recycled for memory health."""
        if self._exec_count >= self.RESTART_EVERY:
            return True
        if (
            self._has_psutil
            and self._exec_count > 0
            and self._exec_count % self.RSS_CHECK_EVERY == 0
        ):
            try:
                import psutil
                if self._proc is None:
                    return False
                proc = psutil.Process(self._proc.pid)
                rss = proc.memory_info().rss
                # Include children (node → chromium, ruby → sub-interpreters)
                for child in proc.children(recursive=True):
                    try:
                        rss += child.memory_info().rss
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                if rss > self.MAX_RSS_BYTES:
                    logger.info(
                        "Persistent target RSS %d MB > %d MB limit, restarting",
                        rss // (1024 * 1024),
                        self.MAX_RSS_BYTES // (1024 * 1024),
                    )
                    return True
            except Exception:
                pass
        return False

    def execute(self, inp: Input) -> ExecutionResult:
        if self._proc is None or not self.is_alive():
            self._exec_count = 0
            self.setup()
        elif self._should_restart():
            logger.debug(
                "Recycling persistent target after %d execs", self._exec_count
            )
            self._exec_count = 0
            self.reset()

        start = time.monotonic()
        try:
            # Send: [4-byte length][data]
            data = inp.data
            header = struct.pack(">I", len(data))
            self._write_with_timeout(header + data, start)

            # Recv entire response in a single background thread to avoid
            # creating 3 threads per execute (header + body + exit_code).
            # Profiling showed thread create+join costs ~215μs each;
            # 3 per call = ~645μs of pure overhead per target per iteration.
            output, exit_code, coverage = self._read_response(start)

            self._exec_count += 1
            self._consecutive_crashes = 0  # reset on success
            duration_ms = (time.monotonic() - start) * 1000
            metadata = {}
            if coverage is not None:
                metadata["target_coverage"] = coverage
            return ExecutionResult(
                exit_code=exit_code,
                stdout=output,
                duration_ms=duration_ms,
                metadata=metadata,
            )

        except Exception as e:
            duration_ms = (time.monotonic() - start) * 1000
            error_type = type(e).__name__
            poll_code = self._proc.poll() if self._proc else None
            self._consecutive_crashes += 1
            if self._consecutive_crashes <= 3:
                logger.debug(
                    "Persistent target error after %d execs: %s (%s), "
                    "duration=%.0fms, input_len=%d, poll=%s",
                    self._exec_count, error_type, str(e)[:100],
                    duration_ms, len(inp.data), poll_code,
                )
            elif self._consecutive_crashes % 50 == 0:
                logger.warning(
                    "Persistent target crash loop: %d consecutive failures, "
                    "last: %s (%s), poll=%s",
                    self._consecutive_crashes, error_type,
                    str(e)[:100], poll_code,
                )
            # Back off if target keeps crashing (sleep up to 2s)
            if self._consecutive_crashes >= 5:
                backoff = min(0.1 * (self._consecutive_crashes - 4), 2.0)
                time.sleep(backoff)
            # Process died or timed out — restart on next call
            self.teardown()
            return ExecutionResult(
                exit_code=-1,
                stderr=str(e).encode("utf-8", errors="replace"),
                duration_ms=duration_ms,
                metadata={"error": "persistent_target_error",
                           "error_type": error_type},
            )

    def _write_with_timeout(self, data: bytes, start: float) -> None:
        """Write data to stdin with timeout to prevent deadlock.

        If the child process's stdout buffer is full (it hasn't read our
        previous response), stdin.write will block indefinitely.  This
        wraps the write in a background thread with the same timeout
        used for reads.
        """
        err = [None]  # [Exception | None]

        def _writer():
            try:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
            except Exception as e:
                err[0] = e

        t = threading.Thread(target=_writer, daemon=True)
        t.start()
        remaining = max(0.1, self.timeout_seconds - (time.monotonic() - start))
        t.join(timeout=remaining)

        if t.is_alive():
            raise TimeoutError(
                f"Persistent target stdin write timed out after {self.timeout_seconds}s"
            )
        if err[0] is not None:
            raise err[0]

    # Flag bit in exit_code indicating coverage data follows.
    _COV_FLAG = 0x01000000

    def _read_response(self, start: float) -> tuple[bytes, int, bytes | None]:
        """Read complete response (header + body + exit code) in one thread.

        Reduces per-execute threading overhead from 3 thread creations to 1.

        Returns (output, exit_code, coverage_bitmap_or_None).
        """
        result = [None]  # [tuple[bytes, int, bytes|None] | Exception]
        proc = self._proc
        cov_flag = self._COV_FLAG

        def _reader():
            try:
                # Read header (4 bytes)
                h = _read_nbytes(proc.stdout, 4)
                out_len = struct.unpack(">I", h)[0]
                # Read body
                output = _read_nbytes(proc.stdout, out_len)
                # Read exit code (4 bytes)
                ec_bytes = _read_nbytes(proc.stdout, 4)
                raw_exit = struct.unpack(">I", ec_bytes)[0]

                # Extended protocol: coverage bitmap follows if flag set
                coverage = None
                if raw_exit & cov_flag:
                    exit_code = raw_exit & 0x00FFFFFF
                    cov_len_bytes = _read_nbytes(proc.stdout, 4)
                    cov_len = struct.unpack(">I", cov_len_bytes)[0]
                    if cov_len > 0:
                        coverage = _read_nbytes(proc.stdout, cov_len)
                else:
                    exit_code = raw_exit

                result[0] = (output, exit_code, coverage)
            except Exception as e:
                result[0] = e

        t = threading.Thread(target=_reader, daemon=True)
        t.start()

        remaining = max(0.1, self.timeout_seconds - (time.monotonic() - start))
        t.join(timeout=remaining)

        if t.is_alive():
            raise TimeoutError(
                f"Persistent target read timed out after {self.timeout_seconds}s"
            )
        if isinstance(result[0], Exception):
            raise result[0]
        if result[0] is None:
            raise EOFError("Read returned no data")
        return result[0]

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
