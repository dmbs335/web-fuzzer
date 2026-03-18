"""Async browser verifier — consumes verification queue items
and re-parses sanitized HTML in Chromium via Playwright.

Runs as a separate process alongside the JSDOM fuzzer.
Usage:
    python -m webfuzzer verify-browser -o output/session_X
"""

from __future__ import annotations

import hashlib
import json
import logging
import signal
import sys
import time
from pathlib import Path

from .oracles.mxss_oracle import _has_dangerous_pattern
from .protocols import Input
from .targets.persistent_target import PersistentTarget
from .verification_queue import VerificationItem, VerificationQueue

logger = logging.getLogger(__name__)

# Map sanitizer name → (wrapper_cmd, module_path)
_BROWSER_MODULES = {
    "dompurify": (
        "node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js",
        "targets/sanitizer_dompurify_mxss_browser_module.js",
    ),
    "jsxss": (
        "node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js",
        "targets/sanitizer_jsxss_mxss_browser_module.js",
    ),
    "sanitize-html": (
        "node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js",
        "targets/sanitizer_sanitize_html_mxss_browser_module.js",
    ),
}

_RECYCLE_EVERY = 1000


class BrowserVerifier:
    """Consumes queue items and verifies with Chromium."""

    def __init__(
        self,
        queue: VerificationQueue,
        output_dir: Path,
        sanitizer: str = "dompurify",
    ) -> None:
        self.queue = queue
        self.output_dir = output_dir
        self.sanitizer = sanitizer
        self._target: PersistentTarget | None = None
        self._findings_count = 0
        self._verified_count = 0
        self._skipped_count = 0
        self._running = False
        self._seen: set[str] = set()

    def run(self) -> None:
        """Main verification loop."""
        self._running = True
        signal.signal(signal.SIGINT, self._handle_signal)
        if sys.platform != "win32":
            signal.signal(signal.SIGTERM, self._handle_signal)

        try:
            self._setup_target()
        except Exception:
            self._cleanup()
            raise
        logger.info(
            "BrowserVerifier started (sanitizer=%s, output=%s)",
            self.sanitizer,
            self.output_dir,
        )
        self._print_status()

        try:
            while self._running:
                item = self.queue.pop(timeout=2.0)
                if item is None:
                    continue

                if item.id in self._seen:
                    self._skipped_count += 1
                    continue
                self._seen.add(item.id)
                if len(self._seen) > 100_000:
                    self._seen.clear()

                self._verify_item(item)
                self._verified_count += 1

                if self._verified_count % _RECYCLE_EVERY == 0:
                    self._recycle_target()

                if self._verified_count % 10 == 0:
                    self._print_status()
        except KeyboardInterrupt:
            pass
        finally:
            self._cleanup()
            self._print_status()
            logger.info("BrowserVerifier stopped.")

    def _handle_signal(self, signum: int, frame: object) -> None:
        self._running = False

    def _setup_target(self) -> None:
        if self.sanitizer not in _BROWSER_MODULES:
            raise ValueError(
                f"Unknown sanitizer '{self.sanitizer}'. "
                f"Available: {list(_BROWSER_MODULES)}"
            )
        wrapper, module = _BROWSER_MODULES[self.sanitizer]
        cmd = f"{wrapper} {module}"
        self._target = PersistentTarget(cmd, timeout_seconds=15.0)
        self._target.setup()

    def _recycle_target(self) -> None:
        logger.info("Recycling browser target after %d verifications", self._verified_count)
        if self._target:
            self._target.teardown()
        try:
            self._setup_target()
        except Exception as e:
            logger.error("Failed to recycle target: %s", e)
            self._target = None
            raise

    def _verify_item(self, item: VerificationItem) -> None:
        if self._target is None:
            return

        inp = Input(data=item.input_data)
        try:
            result = self._target.execute(inp)
        except Exception as e:
            logger.warning("Target execution failed: %s", e)
            self._recycle_target()
            return

        if not result.stdout:
            return

        try:
            data = json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return

        if not isinstance(data, dict):
            return

        browser_mxss = data.get("browser_mxss", False)
        cascade_mxss = data.get("cascade_mxss", False)

        if not browser_mxss and not cascade_mxss:
            return  # no browser-level mutation

        sanitized = data.get("sanitized", "")
        browser_reparsed = data.get("browser_reparsed", "")

        sanitized_danger = _has_dangerous_pattern(sanitized)
        browser_danger = _has_dangerous_pattern(browser_reparsed)

        if browser_danger and not sanitized_danger:
            severity = "critical"
            title = f"BROWSER VERIFIED mXSS: {browser_danger} after Chromium re-parse"
        elif browser_mxss:
            severity = "high"
            title = "BROWSER VERIFIED: structural DOM mutation in Chromium"
        elif cascade_mxss:
            severity = "high"
            title = "BROWSER VERIFIED: cascade mXSS in Chromium"
        else:
            return

        self._save_finding(item, data, title, severity)

    def _save_finding(
        self,
        item: VerificationItem,
        browser_data: dict,
        title: str,
        severity: str,
    ) -> None:
        fdir = (
            self.output_dir
            / "findings"
            / f"browser_{self._findings_count:04d}_{severity}_mxss"
        )
        try:
            fdir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.error("Failed to create finding dir: %s", e)
            return

        try:
            (fdir / "input").write_bytes(item.input_data)
        except OSError as e:
            logger.error("Failed to write finding input: %s", e)
            return

        info = {
            "title": title,
            "severity": severity,
            "oracle": "browser_mxss",
            "fingerprint": f"browser_mxss|{hashlib.md5(item.input_data).hexdigest()[:16]}",
            "verified_by": "chromium_playwright",
            "trigger_reason": item.trigger_reason,
            "jsdom_sanitized_preview": item.jsdom_sanitized[:500],
            "browser_reparsed_preview": browser_data.get("browser_reparsed", "")[:500],
            "browser_mxss": browser_data.get("browser_mxss", False),
            "cascade_mxss": browser_data.get("cascade_mxss", False),
            "browser_parser_diff": browser_data.get("browser_parser_diff", False),
            "browser_mxss_diff": browser_data.get("browser_mxss_diff"),
            "original_iteration": item.iteration,
            "verified_at": time.time(),
            "metadata": item.metadata,
        }
        try:
            (fdir / "info.json").write_text(
                json.dumps(info, indent=2, default=str), encoding="utf-8",
            )
        except OSError as e:
            logger.error("Failed to write finding info: %s", e)
            return

        self._findings_count += 1
        logger.info("BROWSER VERIFIED FINDING [%s]: %s", severity.upper(), title)
        print(
            f"[FINDING] {severity.upper()}: {title}",
            file=sys.stderr,
            flush=True,
        )

    def _print_status(self) -> None:
        pending = self.queue.size()
        print(
            f"[browser-verifier] verified={self._verified_count} "
            f"findings={self._findings_count} "
            f"pending={pending} "
            f"skipped={self._skipped_count}",
            file=sys.stderr,
            flush=True,
        )

    def _cleanup(self) -> None:
        if self._target:
            self._target.teardown()
            self._target = None
        self.queue.close()
