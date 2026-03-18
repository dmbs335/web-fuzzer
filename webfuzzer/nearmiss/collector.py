"""Coverage collector: replay corpus through instrumented targets.

Uses PersistentTarget with --coverage-lines-only to collect per-input
covered lines without the overhead of full bitmap transfer.
"""

from __future__ import annotations

import json
import logging
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class InputCoverage:
    """Coverage result for a single corpus input."""

    input_id: str
    input_data: bytes
    covered_lines: dict[str, set[int]]  # {filename: {lineno, ...}}
    new_lines: dict[str, set[int]]  # lines first seen on this input
    output: dict  # parsed target output JSON
    exit_code: int = 0


@dataclass
class TargetCoverage:
    """Aggregated coverage for one target across all corpus entries."""

    target_name: str
    target_cmd: str
    global_covered: dict[str, set[int]]  # {filename: {lineno, ...}}
    per_input: list[InputCoverage]
    total_lines_covered: int = 0


@dataclass
class CoverageReport:
    """Full coverage report across all targets."""

    targets: dict[str, TargetCoverage]  # {target_name: TargetCoverage}
    corpus_size: int = 0
    elapsed_seconds: float = 0.0


class CoverageCollector:
    """Replay corpus entries through instrumented targets and collect line coverage.

    Uses the persistent wrapper's --coverage-lines-only mode which injects
    _covered_lines into the JSON output without sending the bitmap over the
    binary protocol.
    """

    def __init__(
        self,
        target_configs: dict[str, str],
        working_dir: Path | None = None,
        timeout: float = 10.0,
    ) -> None:
        """
        Args:
            target_configs: {target_name: persistent_wrapper_command}
                Commands should NOT include --coverage-lines-only (added automatically).
            working_dir: Working directory for target processes.
            timeout: Per-execution timeout in seconds.
        """
        self.target_configs = target_configs
        self.working_dir = working_dir
        self.timeout = timeout

    def collect(
        self,
        corpus_dir: Path,
        input_ids: list[str] | None = None,
    ) -> CoverageReport:
        """Replay corpus through all targets, collect line coverage.

        Args:
            corpus_dir: Path to corpus/ directory containing id_NNNNNN files.
            input_ids: Optional subset of input IDs to analyze.
                       If None, analyzes all corpus entries.
        """
        # Load corpus entries
        entries = self._load_corpus(corpus_dir, input_ids)
        if not entries:
            logger.warning("No corpus entries found in %s", corpus_dir)
            return CoverageReport(targets={})

        logger.info("Loaded %d corpus entries", len(entries))

        start_time = time.monotonic()
        report = CoverageReport(targets={}, corpus_size=len(entries))

        for target_name, base_cmd in self.target_configs.items():
            logger.info("Collecting coverage for target: %s", target_name)
            target_cov = self._collect_target(target_name, base_cmd, entries)
            report.targets[target_name] = target_cov
            logger.info(
                "  %s: %d files, %d lines covered",
                target_name,
                len(target_cov.global_covered),
                target_cov.total_lines_covered,
            )

        report.elapsed_seconds = time.monotonic() - start_time
        return report

    def _collect_target(
        self,
        target_name: str,
        base_cmd: str,
        entries: list[tuple[str, bytes]],
    ) -> TargetCoverage:
        """Collect coverage for one target across all corpus entries."""
        from ..fuzzer.targets.persistent_target import PersistentTarget

        # Ensure coverage-lines-only is enabled
        cmd = base_cmd
        if "--coverage-lines-only" not in cmd and "--coverage" not in cmd:
            cmd += " --coverage-lines-only"
        elif "--coverage" in cmd and "--coverage-lines-only" not in cmd:
            cmd = cmd.replace("--coverage", "--coverage-lines-only")

        target = PersistentTarget(
            command=cmd,
            timeout_seconds=self.timeout,
            working_dir=self.working_dir,
        )

        global_covered: dict[str, set[int]] = {}
        per_input: list[InputCoverage] = []

        try:
            target.setup()

            for i, (input_id, input_data) in enumerate(entries):
                if i > 0 and i % 100 == 0:
                    logger.info("  %s: %d/%d entries...", target_name, i, len(entries))

                from ..fuzzer.protocols import Input
                inp = Input(data=input_data)
                result = target.execute(inp)

                # Parse output JSON to extract _covered_lines
                covered_lines: dict[str, set[int]] = {}
                new_lines: dict[str, set[int]] = {}
                output_json = {}

                try:
                    output_json = json.loads(result.stdout)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

                raw_lines = output_json.pop("_covered_lines", None)
                if raw_lines and isinstance(raw_lines, list):
                    for item in raw_lines:
                        if isinstance(item, list) and len(item) == 2:
                            fname, lineno = item[0], item[1]
                            covered_lines.setdefault(fname, set()).add(lineno)

                            # Track new lines (not previously in global)
                            if lineno not in global_covered.get(fname, set()):
                                new_lines.setdefault(fname, set()).add(lineno)

                    # Update global coverage
                    for fname, lines in covered_lines.items():
                        global_covered.setdefault(fname, set()).update(lines)

                per_input.append(InputCoverage(
                    input_id=input_id,
                    input_data=input_data,
                    covered_lines=covered_lines,
                    new_lines=new_lines,
                    output=output_json,
                    exit_code=result.exit_code,
                ))

        except Exception as e:
            logger.error("Error collecting coverage for %s: %s", target_name, e)
        finally:
            target.teardown()

        total = sum(len(lines) for lines in global_covered.values())
        return TargetCoverage(
            target_name=target_name,
            target_cmd=cmd,
            global_covered=global_covered,
            per_input=per_input,
            total_lines_covered=total,
        )

    @staticmethod
    def _load_corpus(
        corpus_dir: Path,
        input_ids: list[str] | None = None,
    ) -> list[tuple[str, bytes]]:
        """Load corpus entries as (input_id, data) pairs."""
        if not corpus_dir.is_dir():
            return []

        entries = []
        for f in sorted(corpus_dir.iterdir()):
            if f.suffix == ".meta" or f.is_dir():
                continue
            input_id = f.name
            if input_ids is not None and input_id not in input_ids:
                continue
            try:
                data = f.read_bytes()
                entries.append((input_id, data))
            except OSError:
                continue

        return entries
