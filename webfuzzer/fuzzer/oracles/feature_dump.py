"""Per-input feature sink for E2/E3 offline analysis.

Where :class:`~webfuzzer.fuzzer.oracles.diff_trace.DiffTraceSink` records
the *output* side of every differential oracle invocation (which strategy
groups diverged, on which fields), this sink records the *input* side —
features computable from the mutated wire bytes plus the mutator's own
``metadata["strategies"]`` breadcrumb.

Its intended consumers are:

* **E2 preservation** — needs ``(x_i, outcome_i)`` pairs where ``x_i`` is
  a Boolean feature vector of the input, to estimate singleton Fourier
  coefficients and run the perturbation replay driver (Stage B).
* **E3 manifold** — needs a stream of length-normalized feature vectors
  to estimate intrinsic dimension via Levina–Bickel MLE.

Payload schema (JSONL, one row per execution)::

    {
        "seq": <monotonic int>,
        "input_sha1": "<first 16 hex chars of sha1>",
        "input_len": <int>,
        "input_head": "<hex(first 16 bytes)>",
        "input_tail": "<hex(last 16 bytes)>",
        "applied_strategies": [<mutator sub-strategy names>],
        "mutator": "<mutator.name>",
        "divergence": <bool>,
        "n_refs": <int>,
        "n_diverged_refs": <int>,
        "diff_fields": [<sorted unique diff_fields from all patterns>],
        "affected_refs": [<sorted ref indices that disagreed with primary>]
    }

The ``affected_refs`` field is the E7 per-library disagreement vector:
index ``i`` appears iff the primary target and reference target ``i``
emitted differing verdicts on at least one oracle pattern for this
input. Consumers that want per-pair disagreement surfaces read this
directly. Older feature dumps produced before this field was added
default to an empty list on load.

The sink is deliberately oracle-agnostic — it receives the already-computed
``patterns_out`` list that the oracle was going to write to ``diff_trace``
anyway, plus the raw :class:`Input` so input-side features stay cheap
(no extra target executions).

Thread safety matches :class:`DiffTraceSink`: per-sink lock, line-buffered
flush, lazy file open on first emit.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any


class FeatureDumpSink:
    """Append-only JSONL sink for per-input feature records.

    See module docstring for payload schema. The writer is *lazy* — no
    file is touched until :meth:`emit_input` is called at least once, so
    configuring a feature-dump path without actually running the fuzz
    loop does not litter the filesystem.
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
        self._fh = open(self._path, "a", encoding="utf-8", buffering=1)

    def emit_input(
        self,
        *,
        input_bytes: bytes,
        mutator_name: str | None,
        applied_strategies: list[str] | tuple[str, ...] | None,
        divergence: bool,
        n_refs: int,
        n_diverged_refs: int,
        diff_fields: list[str] | tuple[str, ...] | None,
        affected_refs: list[int] | tuple[int, ...] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Append one feature row for a single execution.

        The caller is expected to hand in already-computed aggregates
        (``divergence``, ``diff_fields``, ``n_diverged_refs``) so the sink
        stays cheap on the hot path. ``extra`` is merged last and may add
        domain-specific features (e.g., number of Signature elements for
        SAML, Content-Length for HRS) without needing a schema bump here.
        """
        head = input_bytes[:16].hex()
        tail = input_bytes[-16:].hex() if len(input_bytes) > 16 else head
        row: dict[str, Any] = {
            "input_sha1": hashlib.sha1(input_bytes).hexdigest()[:16],
            "input_len": len(input_bytes),
            "input_head": head,
            "input_tail": tail,
            "mutator": mutator_name or "",
            "applied_strategies": list(applied_strategies or ()),
            "divergence": bool(divergence),
            "n_refs": int(n_refs),
            "n_diverged_refs": int(n_diverged_refs),
            "diff_fields": sorted(set(diff_fields or ())),
            "affected_refs": sorted({int(r) for r in (affected_refs or ())}),
        }
        if extra:
            # Extra fields never overwrite core fields.
            for k, v in extra.items():
                row.setdefault(k, v)
        with self._lock:
            self._ensure_open()
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

    def __enter__(self) -> "FeatureDumpSink":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
