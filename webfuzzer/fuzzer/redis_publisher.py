"""Optional Redis Pub/Sub publisher for real-time event streaming.

If Redis is not configured or not reachable, all publish calls silently no-op.
The fuzzer continues to work exactly as before.

Environment variables:
    FUZZER_SESSION_ID  — session ID for Redis channel naming
    FUZZER_REDIS_URL   — Redis connection URL (e.g. redis://localhost:6379/0)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


class RedisPublisher:
    """Publishes fuzzing events to Redis Pub/Sub channels.

    Channel naming: ``fuzzer:{session_id}:{event_type}``

    When Redis is not available but FUZZER_SESSION_ID is set, falls back to
    writing JSON event lines to stderr so the orchestrator can parse them.
    """

    def __init__(self, session_id: str | None = None) -> None:
        self._redis = None
        self._session_id = session_id or os.environ.get("FUZZER_SESSION_ID", "")
        self._enabled = False
        self._stderr_fallback = False
        self._corpus_count = 0  # rate-limit corpus events in stderr mode

        if not self._session_id:
            return

        redis_url = os.environ.get("FUZZER_REDIS_URL", "")
        if not redis_url:
            # No Redis, but session ID is set → use stderr fallback for events
            self._stderr_fallback = True
            return

        try:
            import redis
            self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
            self._redis.ping()
            self._enabled = True
            logger.info("Redis publisher connected: session=%s", self._session_id)
        except Exception as exc:
            logger.warning("Redis connection failed, using stderr fallback: %s", exc)
            self._redis = None
            self._stderr_fallback = True

    @property
    def enabled(self) -> bool:
        return self._enabled or self._stderr_fallback

    def _channel(self, event_type: str) -> str:
        return f"fuzzer:{self._session_id}:{event_type}"

    def _publish(self, event_type: str, data: dict[str, Any]) -> None:
        if self._enabled:
            try:
                self._redis.publish(self._channel(event_type), json.dumps(data, default=str))  # type: ignore[union-attr]
            except Exception:
                pass  # never crash the fuzzer
        elif self._stderr_fallback:
            # Write JSON event to stderr for orchestrator to parse
            import sys
            try:
                line = json.dumps({"event": event_type, "data": data}, default=str)
                print(f"@@EVENT@@{line}", file=sys.stderr, flush=True)
            except Exception:
                pass

    # ── Typed publish helpers ──────────────────────────────────────

    def publish_stats(
        self,
        elapsed_seconds: float,
        total_execs: int,
        execs_per_sec: float,
        corpus_size: int,
        total_edges: int,
        unique_findings: int,
    ) -> None:
        self._publish("stats", {
            "elapsed_seconds": round(elapsed_seconds, 1),
            "total_execs": total_execs,
            "execs_per_sec": round(execs_per_sec, 1),
            "corpus_size": corpus_size,
            "total_edges": total_edges,
            "unique_findings": unique_findings,
        })

    def publish_finding(
        self,
        title: str,
        severity: str,
        oracle_name: str,
        fingerprint: str,
        input_data: bytes,
        exit_code: int,
        duration_ms: float,
        metadata: dict,
    ) -> None:
        try:
            input_preview = input_data[:256].decode("utf-8", errors="replace")
        except Exception:
            input_preview = "<binary>"

        self._publish("finding", {
            "title": title,
            "severity": severity,
            "oracle_name": oracle_name,
            "fingerprint": fingerprint,
            "input_preview": input_preview,
            "exit_code": exit_code,
            "duration_ms": round(duration_ms, 2),
            "metadata": metadata,
        })

    def publish_coverage(
        self,
        edge_count: int,
        elapsed_sec: float,
        exec_count: int = 0,
        corpus_size: int = 0,
    ) -> None:
        # Skip in stderr mode — status line has edge count, reduces pipe pressure
        if self._stderr_fallback and not self._enabled:
            return
        self._publish("coverage", {
            "edge_count": edge_count,
            "elapsed_sec": round(elapsed_sec, 1),
            "exec_count": exec_count,
            "corpus_size": corpus_size,
        })

    def publish_corpus(
        self,
        seed_id: int,
        input_data: bytes,
        parent_id: int | None,
        depth: int,
        energy: float,
        metadata: dict,
    ) -> None:
        self._corpus_count += 1
        # In stderr fallback mode, skip corpus events entirely to avoid
        # flooding the pipe buffer (causes deadlock at high exec rates).
        # Stats line already tracks corpus size; data imported from disk post-session.
        if self._stderr_fallback and not self._enabled:
            return
        self._publish("corpus", {
            "seed_id": seed_id,
            "size_bytes": len(input_data),
            "input_hex": input_data.hex(),
            "parent_id": parent_id,
            "depth": depth,
            "energy": energy,
            "metadata": metadata,
        })

    def publish_log(self, line: str) -> None:
        self._publish("log", {"line": line})

    def publish_status(self, status: str) -> None:
        self._publish("status", {"status": status})

    def publish_priority_update(self, seed_id: int, boost: float) -> None:
        self._publish("priority_update", {
            "seed_id": seed_id,
            "boost": round(boost, 4),
        })

    def close(self) -> None:
        if self._redis:
            try:
                self._redis.close()
            except Exception:
                pass
