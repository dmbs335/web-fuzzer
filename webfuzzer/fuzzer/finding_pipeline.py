"""Finding processing pipeline for oracle results."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .protocols import Finding, Input, Oracle, ExecutionResult

logger = logging.getLogger(__name__)


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
    ) -> None:
        self.oracles = oracles
        self.deduplicator = deduplicator
        self.publisher = publisher
        self.stats = stats
        self.guidance_hooks = guidance_hooks
        self.all_targets = all_targets
        self.target_lib_names = target_lib_names
        self.deser_oracle_positive = 0

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

            findings = self._normalize_findings(findings_or_one)
            for finding in findings:
                if mutator_name:
                    finding.metadata["mutator"] = mutator_name
                finding.metadata["primary_idx"] = primary_idx
                self._normalize_ref_index(finding, primary_idx)
                self._annotate_library_names(finding, primary_idx)

                finding.fingerprint = self.deduplicator.fingerprint(finding)
                if finding.oracle_name == "deser":
                    self.deser_oracle_positive += 1
                if self.deduplicator.is_duplicate(finding):
                    continue

                self.deduplicator.register(finding)
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
