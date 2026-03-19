"""Checkpoint persistence helpers for the fuzzing engine."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

logger = logging.getLogger(__name__)


def json_to_rng_state(raw: list) -> tuple:
    """Convert JSON-deserialized RNG state to the tuple setstate() expects."""
    version = raw[0]
    internal = tuple(raw[1])
    gauss_next = raw[2]
    return (version, internal, gauss_next)


class CheckpointService:
    """Save and restore engine checkpoint state."""

    def __init__(
        self,
        *,
        output_dir: Path | None,
        corpus,
        stats,
        rng,
        dedup_exporter,
        dedup_importer,
    ) -> None:
        self.output_dir = output_dir
        self.corpus = corpus
        self.stats = stats
        self.rng = rng
        self.dedup_exporter = dedup_exporter
        self.dedup_importer = dedup_importer

    def checkpoint_dir(self) -> Path | None:
        if self.output_dir is None:
            return None
        return self.output_dir / "checkpoint"

    def save(self) -> None:
        """Save full engine state to the checkpoint directory."""
        ckpt = self.checkpoint_dir()
        if ckpt is None:
            return

        try:
            self.corpus.save_checkpoint(ckpt / "corpus")
            state: dict = {
                "stats": self.stats.to_checkpoint_dict(),
                "rng_state": self.rng.getstate(),
            }
            dedup_seen = self.dedup_exporter()
            if dedup_seen is not None:
                state["dedup_seen"] = dedup_seen

            ckpt.mkdir(parents=True, exist_ok=True)
            (ckpt / "state.json").write_text(
                json.dumps(state, default=str),
                encoding="utf-8",
            )
            logger.debug(
                "Checkpoint saved: %d seeds, %d edges",
                len(self.corpus),
                self.stats.total_edges,
            )
        except Exception as exc:
            logger.warning("Failed to save checkpoint: %s", exc)

    def load(self) -> bool:
        """Load engine state from the checkpoint directory."""
        ckpt = self.checkpoint_dir()
        if ckpt is None:
            return False

        state_file = ckpt / "state.json"
        if not state_file.exists():
            return False

        try:
            if not self.corpus.load_checkpoint(ckpt / "corpus"):
                return False

            state = json.loads(state_file.read_text(encoding="utf-8"))
            self.stats.load_checkpoint_dict(state.get("stats", {}))

            rng_state = state.get("rng_state")
            if rng_state is not None:
                self.rng.setstate(json_to_rng_state(rng_state))

            dedup_seen = state.get("dedup_seen")
            if dedup_seen:
                self.dedup_importer(dedup_seen)
            return True
        except Exception as exc:
            logger.warning("Failed to load checkpoint: %s", exc)
            return False

    def maybe_save(
        self,
        *,
        last_checkpoint_time: float,
        checkpoint_interval: float,
    ) -> float:
        """Save a checkpoint if the interval has elapsed."""
        if self.output_dir is None:
            return last_checkpoint_time

        now = time.time()
        if now - last_checkpoint_time >= checkpoint_interval:
            self.save()
            return now
        return last_checkpoint_time
