"""Queue interesting sanitizer outputs for async browser verification."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from .protocols import ExecutionResult, Input
from .verification_queue import VerificationQueue, VerificationItem, create_verification_queue

logger = logging.getLogger(__name__)


class BrowserVerificationService:
    """Own the browser-verification queue and enqueue policy."""

    def __init__(self, *, enabled: bool, output_dir: Path | None, stats) -> None:
        self.output_dir = output_dir
        self.stats = stats
        self.queue: VerificationQueue | None = None
        self._seen: set[str] = set()

        if enabled and output_dir is not None:
            self.queue = create_verification_queue(output_dir)

    def maybe_queue(self, inp: Input, result: ExecutionResult) -> None:
        """Queue an interesting input for async browser verification."""
        if self.queue is None or not result.stdout:
            return

        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return
        if not isinstance(data, dict):
            return
        if not self._is_interesting(data):
            return

        input_hash = hashlib.md5(inp.data).hexdigest()
        if input_hash in self._seen:
            return
        self._seen.add(input_hash)
        if len(self._seen) > 10_000:
            self._seen.clear()

        item = VerificationItem(
            id=input_hash[:16],
            input_data=inp.data,
            jsdom_sanitized=data.get("sanitized", ""),
            trigger_reason=self._get_trigger_reason(data),
            metadata={
                key: data.get(key)
                for key in (
                    "mxss_security",
                    "danger_escalation",
                    "max_depth",
                    "new_elements_after_reparse",
                )
            },
            session_output_dir=str(self.output_dir) if self.output_dir else "",
            iteration=self.stats.total_iterations,
        )
        try:
            self.queue.push(item)
        except Exception as exc:
            logger.debug("Failed to queue for browser verify: %s", exc)

    @staticmethod
    def _is_interesting(data: dict) -> bool:
        if data.get("mxss_security"):
            return True
        if data.get("danger_escalation"):
            return True
        if any(
            data.get(key)
            for key in (
                "near_miss_img",
                "near_miss_a_href",
                "near_miss_style",
                "near_miss_form",
                "near_miss_svg",
                "near_miss_math",
            )
        ):
            return True
        if data.get("new_elements_after_reparse"):
            return True
        return (data.get("max_depth") or 0) >= 400

    @staticmethod
    def _get_trigger_reason(data: dict) -> str:
        if data.get("danger_escalation"):
            return "danger_escalation"
        if data.get("mxss_security"):
            return "mxss_security"
        if (data.get("max_depth") or 0) >= 400:
            return "depth_400+"
        if data.get("new_elements_after_reparse"):
            return "new_elements"
        return "near_miss"
