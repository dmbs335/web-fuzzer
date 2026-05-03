"""Structural fingerprinting deduplication.

Combines input structure + response error pattern for fingerprinting.
Grammar-aware: uses DerivationTree skeleton when available.
"""

from __future__ import annotations

import hashlib
import re

from ..diff_fields import get_diff_fields
from ..protocols import Finding


class StructuralDeduplicator:
    """Deduplicates findings using structural fingerprints.

    When an atoms list is loaded via :meth:`set_atoms`, the fingerprint for
    differential findings switches from the oracle-level ``diff_pattern_hash``
    (which encodes strategy/category identity) to a Birkhoff bitvector
    ``frozenset(diff_fields ∩ atoms)``.  Two findings that touch the same
    subset of concept-lattice atoms are treated as the same equivalence class
    regardless of which mutator strategy produced them.  Without an atoms list
    the behaviour is byte-identical to the pre-Phase-2 implementation.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()
        # Birkhoff atom set loaded from e4_fca/summary.json["atoms"].
        # None = bitvector path disabled (backward-compatible default).
        self._atoms: frozenset[str] | None = None

    def set_atoms(self, atoms: list[str]) -> None:
        """Load the meet-irreducible atom list from the E4 FCA summary.

        Once set, ``fingerprint()`` will use the bitvector path for any
        finding whose ``diff_fields`` intersect the atom set.  Findings
        whose diff_fields are entirely outside the atom set fall back to
        the original ``diff_pattern_hash`` path so no coverage is lost.
        """
        self._atoms = frozenset(atoms)

    def fingerprint(self, finding: Finding) -> str:
        h = hashlib.sha256()
        components: dict[str, object] = {
            "oracle_name": finding.oracle_name,
            "severity": finding.severity.value,
        }

        # 1. Oracle identity
        h.update(finding.oracle_name.encode())

        # 2. Severity
        h.update(finding.severity.value.encode())

        # 3a. Bitvector path (Phase 2A): when atoms are loaded, fingerprint on
        #     the intersection of diff_fields with the Birkhoff atom set.  This
        #     makes the key invariant to strategy/category identity and collapses
        #     findings that cover the same lattice concept into one bucket.
        if self._atoms is not None:
            diff_fields = get_diff_fields(finding.metadata)
            bv = tuple(sorted(f for f in diff_fields if f in self._atoms))
            if bv:
                components.update(
                    {
                        "mode": "birkhoff_bitvector",
                        "diff_fields": sorted(diff_fields),
                        "bitvector_atoms": list(bv),
                        "category": finding.metadata.get("category", ""),
                        "strategy": finding.metadata.get("strategy", ""),
                        "accepting_side": finding.metadata.get("accepting_side", ""),
                    },
                )
                finding.metadata["fingerprint_components"] = components
                finding.metadata["fine_fingerprint"] = self._fine_fingerprint(
                    finding,
                    components,
                )
                h.update(("bv:" + "|".join(bv)).encode())
                return h.hexdigest()[:16]
            # bv empty means no known atoms hit — fall through to path 3b so
            # non-atom findings still get deduplicated by the original hash.

        # 3b. Oracle-level diff_pattern_hash (high-resolution behavioral fingerprint)
        diff_hash = finding.metadata.get("diff_pattern_hash", "")
        if diff_hash:
            components.update(
                {
                    "mode": "diff_pattern_hash",
                    "diff_pattern_hash": diff_hash,
                    "diff_fields": sorted(get_diff_fields(finding.metadata)),
                    "category": finding.metadata.get("category", ""),
                    "strategy": finding.metadata.get("strategy", ""),
                    "accepting_side": finding.metadata.get("accepting_side", ""),
                },
            )
            h.update(diff_hash.encode())
        else:
            # Fallback: error signature + input skeleton (non-differential oracles)
            error_sig = self._extract_error_sig(finding)
            h.update(error_sig.encode())
            skeleton = self._input_skeleton(finding)
            h.update(skeleton.encode())
            components.update(
                {
                    "mode": "fallback_error_skeleton",
                    "error_signature": error_sig,
                    "input_skeleton": skeleton,
                },
            )

        finding.metadata["fingerprint_components"] = components
        finding.metadata["fine_fingerprint"] = self._fine_fingerprint(
            finding,
            components,
        )

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

    @staticmethod
    def _fine_fingerprint(finding: Finding, components: dict[str, object]) -> str:
        """Return a higher-resolution fingerprint for within-bucket analysis.

        The coarse fingerprint intentionally collapses some semantic variation
        for operational dedup.  ``fine_fingerprint`` preserves more of the
        oracle-side identity so we can later audit diversity inside one coarse
        bucket without changing the dedup decision itself.
        """
        h = hashlib.sha256()
        metadata = finding.metadata
        detail_parts = [
            finding.oracle_name,
            finding.severity.value,
            str(components.get("mode", "")),
            str(components.get("diff_pattern_hash", metadata.get("diff_pattern_hash", ""))),
            str(components.get("error_signature", "")),
            str(components.get("input_skeleton", "")),
            str(metadata.get("category", "")),
            str(metadata.get("strategy", "")),
            str(metadata.get("accepting_side", "")),
            "|".join(sorted(str(v) for v in get_diff_fields(metadata))),
            "|".join(str(v) for v in components.get("bitvector_atoms", []) or []),
        ]
        h.update("\x1f".join(detail_parts).encode("utf-8", errors="replace"))
        return h.hexdigest()[:16]


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
