"""Structural fingerprinting deduplication.

Combines input structure + response error pattern for fingerprinting.
Grammar-aware: uses DerivationTree skeleton when available.
"""

from __future__ import annotations

import hashlib
import re

from ..protocols import Finding


class StructuralDeduplicator:
    """Deduplicates findings using structural fingerprints."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def fingerprint(self, finding: Finding) -> str:
        h = hashlib.sha256()

        # 1. Oracle identity
        h.update(finding.oracle_name.encode())

        # 2. Severity
        h.update(finding.severity.value.encode())

        # 3. Error signature (normalized)
        error_sig = self._extract_error_sig(finding)
        h.update(error_sig.encode())

        # 4. Input structural skeleton
        skeleton = self._input_skeleton(finding)
        h.update(skeleton.encode())

        return h.hexdigest()[:16]

    def is_duplicate(self, finding: Finding) -> bool:
        return finding.fingerprint in self._seen

    def register(self, finding: Finding) -> None:
        self._seen.add(finding.fingerprint)

    @staticmethod
    def _extract_error_sig(finding: Finding) -> str:
        """Extract a normalized error signature from the result."""
        stderr = finding.result.stderr
        if not stderr:
            return str(finding.result.exit_code)

        # Take first line, strip variable content (numbers, paths)
        try:
            first_line = stderr.split(b"\n")[0].decode("utf-8", errors="replace")
        except Exception:
            first_line = str(stderr[:100])

        # Normalize: remove file paths, line numbers, memory addresses
        normalized = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", first_line)
        normalized = re.sub(r"line \d+", "line N", normalized)
        normalized = re.sub(r"/[\w/.-]+", "/PATH", normalized)
        normalized = re.sub(r"\d+", "N", normalized)

        return normalized[:128]

    @staticmethod
    def _input_skeleton(finding: Finding) -> str:
        """Extract structural skeleton of the input."""
        tree = finding.input.metadata.get("tree")
        if tree is not None:
            # Grammar-aware: use rule expansion path
            return _tree_skeleton(tree.root)

        # Byte-level: skeleton by character class transitions
        data = finding.input.data[:256]
        skeleton = []
        prev_class = ""
        for b in data:
            if 65 <= b <= 90 or 97 <= b <= 122:
                cls = "A"
            elif 48 <= b <= 57:
                cls = "0"
            elif b in (32, 9, 10, 13):
                cls = "S"
            else:
                cls = chr(b) if 33 <= b <= 126 else "X"
            if cls != prev_class:
                skeleton.append(cls)
                prev_class = cls
        return "".join(skeleton)[:64]


def _tree_skeleton(node, depth: int = 0) -> str:
    """Extract the structural skeleton of a DerivationTree."""
    if depth > 10:
        return "..."
    if not node.children:
        kind = node.symbol.kind
        if kind == "literal":
            return "L"
        if kind == "builtin":
            return f"B({node.symbol.name})"
        return "?"
    rule = node.rule_name or "?"
    children = "".join(_tree_skeleton(c, depth + 1) for c in node.children[:8])
    return f"{rule}[{children}]"
