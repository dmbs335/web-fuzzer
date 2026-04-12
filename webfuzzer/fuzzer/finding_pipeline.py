"""Finding processing pipeline for oracle results."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .orbit_canonical import canonical_key
from .protocols import Finding, Input, Oracle, ExecutionResult, Severity

logger = logging.getLogger(__name__)

# Severities that are allowed to be downgraded when a new finding lands in
# an already-seen input-space orbit. CRITICAL/HIGH are never touched so a
# real bug that happens to share a canonical form with a noisy neighbour is
# still surfaced at full severity.
_ORBIT_DOWNGRADE_ALLOWED: frozenset[Severity] = frozenset(
    {Severity.INFO, Severity.LOW, Severity.MEDIUM},
)


def extract_lib_name(target) -> str:
    """Extract a library name from a target command string."""
    import re as _re

    cmd = (
        getattr(target, "original_cmd", None)
        or getattr(target, "command_template", None)
        or getattr(target, "command", "")
    )
    m = _re.search(r"targets/(\w+)", cmd)
    if m:
        script = m.group(1)
        for prefix in (
            "saml_",
            "jwt_",
            "oauth_",
            "cookie_",
            "sanitizer_",
            "markdown_",
            "graphql_",
            "deser_",
            "dpop_",
            "jwt_node_",
            "jwt_python_",
        ):
            if script.startswith(prefix):
                script = script[len(prefix):]
                break
        for suffix in ("_module", "_diff", "_mxss", "_exec"):
            if script.endswith(suffix):
                script = script[: -len(suffix)]
        return script

    parts = cmd.replace("\\", "/").split()
    for part in parts:
        if "target" in part.lower():
            return part.rsplit("/", 1)[-1].split(".")[0]
    return cmd[:30]


@dataclass
class FindingCheckResult:
    """Summary of one oracle evaluation pass."""

    found: bool
    metadata: list[dict]


def make_jsonl_violation_sink(path: Path) -> Callable[[Finding], None]:
    """Return a callable that appends a Finding as a JSON line to ``path``.

    Called by the engine when ``output_dir`` is set so that
    :class:`~webfuzzer.fuzzer.oracles.implication_oracle.ImplicationSoftOracle`
    violations are written to ``output_dir/violations.jsonl``.  The file is
    opened in append mode so campaigns that resume do not lose prior entries.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    def _sink(finding: Finding) -> None:
        try:
            record = {
                "title": finding.title,
                "severity": finding.severity.value,
                "oracle_name": finding.oracle_name,
                "fingerprint": finding.fingerprint,
                "metadata": finding.metadata,
            }
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except Exception as exc:
            logger.debug("violation_sink write failed: %s", exc)

    return _sink


class FindingProcessor:
    """Normalizes, deduplicates, enriches, and records findings."""

    def __init__(
        self,
        *,
        oracles: list[Oracle],
        deduplicator,
        publisher,
        stats,
        guidance_hooks,
        all_targets: list,
        target_lib_names: list[str],
        violation_sink: Callable[[Finding], None] | None = None,
    ) -> None:
        self.oracles = oracles
        self.deduplicator = deduplicator
        self.publisher = publisher
        self.stats = stats
        self.guidance_hooks = guidance_hooks
        self.all_targets = all_targets
        self.target_lib_names = target_lib_names
        # Optional sink for ImplicationSoftOracle violation findings.
        # When set, any oracle that exposes drain_violations() will have its
        # buffer drained after each check() and each violation forwarded here.
        self._violation_sink = violation_sink
        self.deser_oracle_positive = 0
        # E6 Stage A runtime hook: per-campaign set of already-observed
        # input-space orbits. Second and later findings hitting an orbit
        # we've already reported get their severity pinned to INFO so the
        # operator only sees one high-severity report per bug family.
        self._seen_orbits: set[str] = set()

    def check(
        self,
        inp: Input,
        result: ExecutionResult,
        *,
        mutator_name: str = "",
        ref_results: list[ExecutionResult] | None = None,
        rotation_idx: int = 0,
    ) -> FindingCheckResult:
        """Run all oracles and record any unique findings."""
        found = False
        finding_metadata: list[dict] = []
        primary_idx = (rotation_idx - 1) % len(self.all_targets)

        for oracle in self.oracles:
            if ref_results is not None and hasattr(oracle, "check_with_refs"):
                findings_or_one = oracle.check_with_refs(inp, result, ref_results)
            else:
                findings_or_one = oracle.check(inp, result)

            # Phase 2C: drain ImplicationSoftOracle violation buffer.
            # Called unconditionally when a violation_sink is registered so
            # that violations are written even when the primary check returns
            # None (no main finding). The drain is O(0) in the common case
            # (oracle has no drain_violations method or buffer is empty).
            if self._violation_sink is not None and hasattr(oracle, "drain_violations"):
                for viol in oracle.drain_violations():
                    self._violation_sink(viol)

            findings = self._normalize_findings(findings_or_one)
            for finding in findings:
                if mutator_name:
                    finding.metadata["mutator"] = mutator_name
                # Preserve the mutator-level sub-strategy breadcrumb so E4
                # apply_lattice_atoms and E2/E6 downstream can see which
                # SamlMutator sub-strategies actually produced the finding.
                # The oracle's own metadata["strategy"] (singular) is the
                # oracle-level name; this is the list of composed mutator
                # operators, set by e.g. SamlMutator.mutate at its return.
                inp_strategies = inp.metadata.get("strategies") if inp.metadata else None
                if inp_strategies:
                    finding.metadata.setdefault("strategies", list(inp_strategies))
                finding.metadata["primary_idx"] = primary_idx
                self._normalize_ref_index(finding, primary_idx)
                self._annotate_library_names(finding, primary_idx)

                finding.fingerprint = self.deduplicator.fingerprint(finding)
                if finding.oracle_name == "deser":
                    self.deser_oracle_positive += 1
                if self.deduplicator.is_duplicate(finding):
                    continue

                self.deduplicator.register(finding)
                self._annotate_orbit(finding)
                self.publisher.publish_finding(
                    title=finding.title,
                    severity=finding.severity.value,
                    oracle_name=finding.oracle_name,
                    fingerprint=finding.fingerprint,
                    input_data=finding.input.data,
                    exit_code=finding.result.exit_code,
                    duration_ms=finding.result.duration_ms,
                    metadata=finding.metadata,
                )
                if self.guidance_hooks and self.guidance_hooks.active:
                    finding.metadata = self.guidance_hooks.on_finding(
                        finding.metadata,
                    )
                logger.info(
                    "Finding: [%s] %s (oracle=%s)",
                    finding.severity.value,
                    finding.title,
                    finding.oracle_name,
                )
                self.stats.record_finding(finding, mutator_name)
                finding_metadata.append(
                    {
                        "category": finding.metadata.get("category", ""),
                        "ref_index": finding.metadata.get("ref_index", 0),
                        "severity": finding.severity.value,
                        "strategy": finding.metadata.get("strategy", ""),
                    },
                )
                found = True

        return FindingCheckResult(found=found, metadata=finding_metadata)

    def _annotate_orbit(self, finding: Finding) -> None:
        """Compute E6 orbit-canonical key and downgrade orbit-duplicates.

        Two findings whose inputs lie in the same ``G``-orbit (differing
        only by whitespace, attribute order, xmlns prefix aliasing, …)
        collapse to the same ``canonical_key``. The first finding in each
        orbit is emitted at its oracle-assigned severity; subsequent ones
        are flagged ``duplicate_downgraded`` and pinned to ``INFO`` if
        their current severity is in the allow-list. CRITICAL/HIGH are
        never downgraded so a genuinely new bug that happens to share a
        canonical form with an earlier low-severity observation still
        gets the operator's attention.

        The key is always written to metadata regardless of severity so
        downstream consumers (dashboards, the offline E6 pipeline) can
        group reports by orbit even when no downgrade is applied.
        """
        try:
            orbit_key = canonical_key(finding.input.data)
        except Exception:  # pragma: no cover — canonical_key is total
            logger.debug("orbit_canonical_key failed", exc_info=True)
            return

        metadata = finding.metadata
        metadata["orbit_canonical_key"] = orbit_key

        if orbit_key in self._seen_orbits:
            metadata["orbit_status"] = "duplicate_downgraded"
            if finding.severity in _ORBIT_DOWNGRADE_ALLOWED:
                metadata["orbit_original_severity"] = finding.severity.value
                finding.severity = Severity.INFO
        else:
            metadata["orbit_status"] = "first"
            self._seen_orbits.add(orbit_key)

    @staticmethod
    def _normalize_findings(findings_or_one) -> list[Finding]:
        if findings_or_one is None:
            return []
        if isinstance(findings_or_one, list):
            return findings_or_one
        return [findings_or_one]

    def _normalize_ref_index(self, finding: Finding, primary_idx: int) -> None:
        rel_ref_index = finding.metadata.get("ref_index")
        if rel_ref_index is None or len(self.all_targets) <= 1:
            return

        abs_indices = [
            idx for idx in range(len(self.all_targets)) if idx != primary_idx
        ]
        if rel_ref_index < len(abs_indices):
            finding.metadata["ref_index"] = abs_indices[rel_ref_index]

    def _annotate_library_names(self, finding: Finding, primary_idx: int) -> None:
        if not self.target_lib_names or len(self.all_targets) <= 1:
            return

        metadata = finding.metadata
        p_idx = metadata.get("primary_idx", primary_idx)
        r_idx = metadata.get("ref_index")
        p_name = (
            self.target_lib_names[p_idx]
            if p_idx < len(self.target_lib_names)
            else ""
        )
        r_name = (
            self.target_lib_names[r_idx]
            if r_idx is not None and r_idx < len(self.target_lib_names)
            else ""
        )

        accepting_side = metadata.get("accepting_side")
        if accepting_side and r_idx is not None:
            if accepting_side == "primary":
                metadata["accepting_libraries"] = [p_name]
                metadata["rejecting_libraries"] = [r_name]
            else:
                metadata["accepting_libraries"] = [r_name]
                metadata["rejecting_libraries"] = [p_name]
            return

        if r_idx is None:
            return

        primary_valid = metadata.get("primary_valid")
        ref_valid = metadata.get("ref_valid")
        if primary_valid is True and ref_valid is False:
            metadata["accepting_libraries"] = [p_name]
            metadata["rejecting_libraries"] = [r_name]
        elif ref_valid is True and primary_valid is False:
            metadata["accepting_libraries"] = [r_name]
            metadata["rejecting_libraries"] = [p_name]
