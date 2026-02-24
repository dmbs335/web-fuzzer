"""Process target — executes a local command with fuzzed input.

Writes the input to a temporary file, runs the command with the file path
substituted into the {input} placeholder, and captures the result.

Usage:
    target = ProcessTarget("./parser {input}", timeout_seconds=5)
    target.setup()
    result = target.execute(inp)
    target.teardown()
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path

from ..protocols import ExecutionResult, Input


class ProcessTarget:
    """Fuzzing target that executes a local command-line program.

    The command template should contain ``{input}`` as a placeholder
    for the path to a temporary file containing the fuzzed input.

    Example commands:
        "./parser {input}"
        "python script.py --file {input}"
        "cat {input} | ./processor"
    """

    def __init__(
        self,
        command_template: str,
        timeout_seconds: float = 10.0,
        working_dir: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.command_template = command_template
        self.timeout_seconds = timeout_seconds
        self.working_dir = working_dir
        self.env = env
        self._tmp_dir: tempfile.TemporaryDirectory[str] | None = None
        self._alive = True

    def setup(self) -> None:
        self._tmp_dir = tempfile.TemporaryDirectory(prefix="webfuzzer_")
        self._alive = True

    def teardown(self) -> None:
        if self._tmp_dir is not None:
            self._tmp_dir.cleanup()
            self._tmp_dir = None

    def is_alive(self) -> bool:
        return self._alive

    def reset(self) -> None:
        pass

    def execute(self, inp: Input) -> ExecutionResult:
        if self._tmp_dir is None:
            self.setup()

        # Write input to temp file
        input_path = os.path.join(self._tmp_dir.name, "input")  # type: ignore[union-attr]
        with open(input_path, "wb") as f:
            f.write(inp.data)

        # Build command
        cmd = self.command_template.replace("{input}", input_path)

        # Prepare environment
        env = None
        if self.env:
            env = {**os.environ, **self.env}

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=self.timeout_seconds,
                cwd=self.working_dir,
                env=env,
            )
            duration_ms = (time.monotonic() - start) * 1000

            return ExecutionResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_ms=duration_ms,
            )

        except subprocess.TimeoutExpired:
            duration_ms = (time.monotonic() - start) * 1000
            return ExecutionResult(
                exit_code=-9,  # simulate SIGKILL
                stderr=b"Process timed out",
                duration_ms=duration_ms,
                metadata={"timeout": True},
            )

        except OSError as e:
            duration_ms = (time.monotonic() - start) * 1000
            self._alive = False
            return ExecutionResult(
                exit_code=-1,
                stderr=str(e).encode("utf-8", errors="replace"),
                duration_ms=duration_ms,
                metadata={"error": "os_error"},
            )
