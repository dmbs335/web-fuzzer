"""SAML per-target acceptance rate tracker.

Tracks how often each target reports signature_valid=True to identify
"always-accepting" targets whose bypass findings are likely noise.

Usage:
    tracker = SamlAcceptanceTracker(target_count=9)
    tracker.record(0, parsed.get("signature_valid"))
    if tracker.is_always_accepting(0):
        # downgrade finding severity
"""

from __future__ import annotations

import logging

_log = logging.getLogger(__name__)

# Minimum executions before making is_always_accepting judgement
_MIN_SAMPLES = 50


class SamlAcceptanceTracker:
    """Track per-target SAML signature acceptance rates during fuzzing."""

    def __init__(self, target_count: int, threshold: float = 0.95) -> None:
        self._accepted = [0] * target_count
        self._total = [0] * target_count
        self._threshold = threshold
        self._warned: set[int] = set()

    def record(self, target_idx: int, sig_valid: bool | None) -> None:
        """Record a single execution result."""
        if target_idx < 0 or target_idx >= len(self._total):
            return
        self._total[target_idx] += 1
        if sig_valid is True:
            self._accepted[target_idx] += 1

        # Log warning once when a target crosses the always-accepting threshold
        if (
            target_idx not in self._warned
            and self._total[target_idx] == _MIN_SAMPLES
            and self.is_always_accepting(target_idx)
        ):
            self._warned.add(target_idx)
            _log.warning(
                "Target[%d] acceptance rate %.1f%% after %d samples "
                "(>%.0f%% threshold) — bypass findings may be noisy",
                target_idx,
                self.rate(target_idx) * 100,
                _MIN_SAMPLES,
                self._threshold * 100,
            )

    def rate(self, target_idx: int) -> float:
        """Return current acceptance rate for a target (0.0-1.0)."""
        if self._total[target_idx] == 0:
            return 0.0
        return self._accepted[target_idx] / self._total[target_idx]

    def is_always_accepting(self, target_idx: int) -> bool:
        """Return True if target accepts signatures too often (likely lenient)."""
        return (
            self._total[target_idx] >= _MIN_SAMPLES
            and self.rate(target_idx) > self._threshold
        )

    def summary(self) -> dict[int, dict]:
        """Return summary of all targets for logging/stats."""
        return {
            i: {
                "accepted": self._accepted[i],
                "total": self._total[i],
                "rate": round(self.rate(i), 3),
                "always_accepting": self.is_always_accepting(i),
            }
            for i in range(len(self._total))
            if self._total[i] > 0
        }
