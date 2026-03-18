"""File-based verification queue for async browser verification.

The JSDOM fuzzer publishes interesting inputs here; a separate
BrowserVerifier process consumes and re-parses in Chromium.
"""

from __future__ import annotations

import abc
import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class VerificationItem:
    """A single input queued for browser verification."""

    id: str
    input_data: bytes
    jsdom_sanitized: str
    trigger_reason: str
    metadata: dict[str, Any] = field(default_factory=dict)
    session_output_dir: str = ""
    iteration: int = 0

    def to_json(self) -> str:
        return json.dumps(
            {
                "id": self.id,
                "input_b64": base64.b64encode(self.input_data).decode("ascii"),
                "jsdom_sanitized": self.jsdom_sanitized[:2000],
                "trigger_reason": self.trigger_reason,
                "metadata": self.metadata,
                "session_output_dir": self.session_output_dir,
                "iteration": self.iteration,
                "timestamp": time.time(),
            },
            default=str,
        )

    @classmethod
    def from_json(cls, raw: str) -> VerificationItem:
        d = json.loads(raw)
        return cls(
            id=d["id"],
            input_data=base64.b64decode(d["input_b64"]),
            jsdom_sanitized=d.get("jsdom_sanitized", ""),
            trigger_reason=d.get("trigger_reason", ""),
            metadata=d.get("metadata", {}),
            session_output_dir=d.get("session_output_dir", ""),
            iteration=d.get("iteration", 0),
        )


class VerificationQueue(abc.ABC):
    """Abstract queue for browser verification items."""

    @abc.abstractmethod
    def push(self, item: VerificationItem) -> None: ...

    @abc.abstractmethod
    def pop(self, timeout: float = 1.0) -> VerificationItem | None: ...

    @abc.abstractmethod
    def size(self) -> int: ...

    @abc.abstractmethod
    def close(self) -> None: ...


class FileVerificationQueue(VerificationQueue):
    """File-based queue using pending/processing/done directories.

    Thread-safe for single producer + single consumer via NTFS atomic rename.
    """

    def __init__(self, base_dir: Path) -> None:
        self._pending = base_dir / "pending"
        self._processing = base_dir / "processing"
        self._done = base_dir / "done"
        for d in (self._pending, self._processing, self._done):
            d.mkdir(parents=True, exist_ok=True)
        self._counter = self._init_counter()

    def _init_counter(self) -> int:
        """Resume counter from existing files."""
        existing = list(self._pending.glob("*.json"))
        existing += list(self._processing.glob("*.json"))
        existing += list(self._done.glob("*.json"))
        if not existing:
            return 0
        nums = []
        for f in existing:
            try:
                nums.append(int(f.stem))
            except ValueError:
                pass
        return (max(nums) + 1) if nums else 0

    def push(self, item: VerificationItem) -> None:
        fname = f"{self._counter:06d}.json"
        self._counter += 1
        path = self._pending / fname
        path.write_text(item.to_json(), encoding="utf-8")

    def pop(self, timeout: float = 1.0) -> VerificationItem | None:
        files = sorted(self._pending.glob("*.json"))
        if not files:
            if timeout > 0:
                time.sleep(min(timeout, 0.5))
            return None

        src = files[0]
        dst = self._processing / src.name
        try:
            os.rename(str(src), str(dst))
        except OSError:
            return None  # race with another consumer

        try:
            raw = dst.read_text(encoding="utf-8")
            item = VerificationItem.from_json(raw)
            # Move to done
            os.rename(str(dst), str(self._done / dst.name))
            return item
        except Exception as e:
            logger.warning("Failed to parse queue item %s: %s", dst, e)
            try:
                os.rename(str(dst), str(self._done / dst.name))
            except OSError:
                pass
            return None

    def size(self) -> int:
        return len(list(self._pending.glob("*.json")))

    def close(self) -> None:
        pass


def create_verification_queue(
    output_dir: Path,
) -> VerificationQueue:
    """Create a file-based verification queue."""
    return FileVerificationQueue(output_dir / "verify_queue")
