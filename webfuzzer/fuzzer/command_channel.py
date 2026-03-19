"""Command reader and in-process command handling for the fuzzing engine."""

from __future__ import annotations

import json
import logging
import queue
import sys
import threading

logger = logging.getLogger(__name__)


class CommandChannel:
    """Read JSON commands from stdin and apply them to engine state."""

    def __init__(self, *, corpus, publisher) -> None:
        self.corpus = corpus
        self.publisher = publisher
        self._queue: queue.Queue[dict] = queue.Queue()

    def start_reader(self) -> None:
        """Start a daemon thread that reads JSON commands from stdin."""
        if not sys.stdin or not hasattr(sys.stdin, "closed") or sys.stdin.closed:
            return

        def _reader() -> None:
            try:
                for line in sys.stdin:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        cmd = json.loads(line)
                        self._queue.put(cmd)
                    except json.JSONDecodeError:
                        pass
            except (EOFError, OSError, ValueError):
                pass

        thread = threading.Thread(target=_reader, daemon=True, name="cmd-reader")
        thread.start()

    def process_pending(self) -> None:
        """Process queued commands from stdin without blocking."""
        while True:
            try:
                cmd = self._queue.get_nowait()
            except queue.Empty:
                break

            cmd_type = cmd.get("cmd")
            if cmd_type == "set_priority":
                seed_id = cmd.get("seed_id")
                boost = cmd.get("boost", 1.0)
                if seed_id is not None:
                    ok = self.corpus.set_priority(seed_id, boost)
                    if ok:
                        self.publisher.publish_priority_update(seed_id, boost)
                        logger.debug(
                            "Priority set: seed=%d boost=%.2f",
                            seed_id,
                            boost,
                        )
            elif cmd_type == "reset_priorities":
                self.corpus.reset_priorities()
                logger.debug("All priorities reset to 1.0")
