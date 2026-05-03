"""OOB file oracle — detects RCE and SSRF via marker file + HTTP callback.

Used for black-box Java deserialization testing where the target JVM
has no instrumentation.  TemplatesImpl bytecode creates a marker file
in a shared Docker volume; this oracle polls that directory after each
execution to detect when arbitrary code execution occurred.

Optionally runs a lightweight HTTP callback listener to detect SSRF
(e.g., JEditorPane.setPage → HTTP GET to our listener).
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ..protocols import ExecutionResult, Finding, Input, Severity

logger = logging.getLogger(__name__)


class _CallbackHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that records incoming requests."""

    callbacks: list[dict] = []
    lock = threading.Lock()

    def do_GET(self) -> None:
        with self.lock:
            self.callbacks.append({
                "method": "GET",
                "path": self.path,
                "remote": self.client_address[0],
                "headers": dict(self.headers),
            })
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, format: str, *args: object) -> None:
        logger.debug("OOB HTTP callback: %s", format % args)


class OobFileOracle:
    """Detect RCE via file creation and SSRF via HTTP callback.

    The target's TemplatesImpl bytecode creates files in ``oob_dir``
    (e.g. ``/tmp/oob/pwned``).  After each fuzzer execution, this oracle
    checks for new files — any new file is a CRITICAL RCE finding.

    When ``http_port`` is set, starts a background HTTP listener to detect
    SSRF from setter dispatch (e.g., JEditorPane.setPage).
    """

    name = "oob_file"

    def __init__(
        self,
        oob_dir: str | Path = "targets/webtob_jeus/oob",
        http_port: int | None = None,
    ) -> None:
        self.oob_dir = Path(oob_dir)
        self._known: set[str] = set()
        self._snapshot()
        self._http_server: HTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        self._callback_handler = _CallbackHandler
        self._callback_handler.callbacks = []
        self._callback_handler.lock = threading.Lock()
        self._last_callback_count = 0
        if http_port is not None:
            self._start_http(http_port)

    def _start_http(self, port: int) -> None:
        try:
            self._http_server = HTTPServer(("0.0.0.0", port), self._callback_handler)
            self._http_thread = threading.Thread(
                target=self._http_server.serve_forever,
                daemon=True,
            )
            self._http_thread.start()
            logger.info("OOB HTTP callback listener on :%d", port)
        except OSError as e:
            logger.warning("Cannot start OOB HTTP listener on :%d — %s", port, e)

    def _snapshot(self) -> None:
        """Capture current file set in the OOB directory."""
        if self.oob_dir.is_dir():
            self._known = {
                f.name
                for f in self.oob_dir.iterdir()
                if f.is_file() and f.name != "agent_cov.json"
            }
        else:
            self._known = set()

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        # --- File-based RCE detection ---
        if self.oob_dir.is_dir():
            current = {
                f.name
                for f in self.oob_dir.iterdir()
                if f.is_file() and f.name != "agent_cov.json"
            }
            new_files = current - self._known
            if new_files:
                self._known = current
                sorted_new = sorted(new_files)
                logger.warning("OOB RCE detected! New files: %s", sorted_new)
                return Finding(
                    title=f"OOB RCE: file created in {self.oob_dir.name}/ ({sorted_new[0]})",
                    severity=Severity.CRITICAL,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    fingerprint=f"oob_rce:{sorted_new[0]}",
                    metadata={
                        "oob_files": sorted_new,
                        "oob_dir": str(self.oob_dir),
                        "category": "rce_confirmed",
                    },
                )

        # --- HTTP callback SSRF detection ---
        with self._callback_handler.lock:
            n = len(self._callback_handler.callbacks)
            if n > self._last_callback_count:
                new_cbs = self._callback_handler.callbacks[self._last_callback_count:]
                self._last_callback_count = n
                paths = [cb["path"] for cb in new_cbs]
                logger.warning("OOB SSRF detected! HTTP callbacks: %s", paths)
                return Finding(
                    title=f"OOB SSRF: HTTP callback received ({paths[0]})",
                    severity=Severity.HIGH,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    fingerprint=f"oob_ssrf:{paths[0]}",
                    metadata={
                        "callbacks": new_cbs,
                        "category": "ssrf_confirmed",
                    },
                )

        # --- Agent-cov sink signal detection ---
        # file_accessed and network_connected are RCE-equivalent (arbitrary
        # file read/write → credential theft / webshell; network connect →
        # SSRF / lateral movement). Detect these from the response JSON
        # that the bridge merges from agent_cov.json.
        parsed = result.parsed_json()
        if parsed is not None:
            # RCE-equivalent sinks
            for indicator, category, label in (
                ("file_accessed", "file_rw_confirmed", "file read/write"),
                ("network_connected", "network_connect_confirmed", "network connect"),
                ("process_spawned", "rce_confirmed", "process spawn"),
                ("script_exec", "rce_confirmed", "script execution"),
            ):
                if parsed.get(indicator):
                    logger.warning("Agent sink detected: %s", label)
                    return Finding(
                        title=f"OOB sink: {label} detected via agent instrumentation",
                        severity=Severity.CRITICAL,
                        input=inp,
                        result=result,
                        oracle_name=self.name,
                        fingerprint=f"oob_sink:{indicator}",
                        metadata={
                            "sink_indicator": indicator,
                            "category": category,
                            "chain_classes": parsed.get("chain_classes", []),
                            "method_invocations": parsed.get("method_invocations", []),
                        },
                    )

        return None

    def shutdown(self) -> None:
        if self._http_server is not None:
            self._http_server.shutdown()
