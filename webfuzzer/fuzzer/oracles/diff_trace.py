"""JSONL sink that records one row per differential oracle invocation.

Used by the E1 class-census experiment (finding-level counts collapse because
the engine deduplicates on ``diff_pattern_hash``; to get a meaningful species
frequency distribution we need the raw pre-dedup stream).

Each row describes one execution. When no strategy observed a divergence,
``patterns`` is an empty list and the row still carries the execution
sequence so E1 can treat "no-divergence" as a dominant species. Format is
JSON-Lines (one object per line); the writer flushes after every line and
is safe for tail-reading while the fuzzer is running.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any


class DiffTraceSink:
    """Append-only JSONL sink for differential oracle executions.

    The sink is opened lazily on the first ``emit`` call so that the file
    is not touched if no differential executions happen (e.g. when the
    oracle is assembled but never called). It is safe for concurrent
    ``emit`` calls from multiple executor threads.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._fh = None  # type: ignore[var-annotated]
        self._seq = 0

    @property
    def path(self) -> Path:
        return self._path

    def _ensure_open(self) -> None:
        if self._fh is not None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # ``line buffering`` so readers (E1 consumer, tail -f) see rows
        # without waiting for a block flush.
        self._fh = open(self._path, "a", encoding="utf-8", buffering=1)

    def emit(self, row: dict[str, Any]) -> None:
        """Append a single JSONL row.

        The caller owns the row schema. This class adds only ``seq``
        (monotonic per-sink counter) if not already present.
        """
        with self._lock:
            self._ensure_open()
            if "seq" not in row:
                row = dict(row)
                row["seq"] = self._seq
            self._seq += 1
            assert self._fh is not None
            self._fh.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False))
            self._fh.write("\n")

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.flush()
                    os.fsync(self._fh.fileno())
                except (OSError, ValueError):
                    pass
                try:
                    self._fh.close()
                except OSError:
                    pass
                self._fh = None

    def __enter__(self) -> "DiffTraceSink":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
