"""Coverage-based crash deduplication.

Fingerprints findings by hashing the coverage edge set,
exit code, and error signature.
"""

from __future__ import annotations

import hashlib

from ..protocols import Finding


class CoverageDeduplicator:
    """Deduplicates findings using coverage profile + exit signature."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def fingerprint(self, finding: Finding) -> str:
        h = hashlib.sha256()

        # Oracle identity
        h.update(finding.oracle_name.encode())

        # Exit signature
        h.update(str(finding.result.exit_code).encode())

        # First 512 bytes of stderr (error message signature)
        h.update(finding.result.stderr[:512])

        # Coverage edges if available
        if finding.result.coverage_data and isinstance(
            finding.result.coverage_data, (bytes, bytearray)
        ):
            edge_sig = bytes(
                1 if b else 0
                for b in finding.result.coverage_data[:65536]
            )
            h.update(edge_sig)

        return h.hexdigest()[:16]

    def is_duplicate(self, finding: Finding) -> bool:
        return finding.fingerprint in self._seen

    def register(self, finding: Finding) -> None:
        self._seen.add(finding.fingerprint)
