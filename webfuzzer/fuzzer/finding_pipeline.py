"""Finding processing pipeline for oracle results."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .orbit_canonical import canonical_key
from .protocols import Finding, Input, Oracle, ExecutionResult, Severity
from .heuristic_policy import (
    SelectionEvidence,
    choose_selection_branch,
    selection_branch_contract,
)

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


def make_jsonl_selection_drop_sink(path: Path) -> Callable[[dict[str, object]], None]:
    """Return a callable that appends selection-drop records as JSON lines."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def _sink(record: dict[str, object]) -> None:
        try:
            with path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except Exception as exc:
            logger.debug("selection_drop_sink write failed: %s", exc)

    return _sink


def _selection_bucket_state() -> dict[str, set[str]]:
    return {
        "fine_fingerprints": set(),
        "strategies": set(),
        "oracle_names": set(),
        "orbit_keys": set(),
        "session_keys": set(),
        "witness_families": set(),
    }


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
        selection_drop_sink: Callable[[dict[str, object]], None] | None = None,
        selection_shadow_sink: Callable[[dict[str, object]], None] | None = None,
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
        self._selection_drop_sink = selection_drop_sink
        self._selection_shadow_sink = selection_shadow_sink
        self.deser_oracle_positive = 0
        # E6 Stage A runtime hook: per-campaign set of already-observed
        # input-space orbits. Second and later findings hitting an orbit can
        # either be downgraded (same semantic pattern) or preserved as orbit
        # variants (different pattern / oracle) so we do not over-collapse
        # meaningfully distinct findings inside the same input-space class.
        self._seen_orbits: set[str] = set()
        self._orbit_seen_counts: dict[str, int] = {}
        self._seen_orbit_signatures: dict[str, set[tuple[str, str, str, str]]] = {}
        # Track within-bucket diversity so we can react when one coarse
        # fingerprint collapses semantically different findings. This is the
        # runtime counterpart to the post-run hotspot analysis.
        self._selection_buckets: dict[str, dict[str, set[str]]] = {}

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
                self.stats.record_observed_finding(finding)
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
                self._annotate_session_context(finding)

                finding.fingerprint = self.deduplicator.fingerprint(finding)
                self._annotate_raw_view(finding)
                if finding.oracle_name == "deser":
                    self.deser_oracle_positive += 1
                if self.deduplicator.is_duplicate(finding):
                    if self._maybe_preserve_duplicate_via_hotspot_branch(finding):
                        self._annotate_published_views(finding)
                        self._annotate_orbit(finding)
                        self._update_selection_bucket(finding)
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
                            "Finding: [%s] %s (oracle=%s, branch=%s)",
                            finding.severity.value,
                            finding.title,
                            finding.oracle_name,
                            finding.metadata.get("selection_branch", ""),
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
                        continue
                    drop_reason = self._duplicate_drop_reason(finding)
                    recommended_branch = self._selection_branch_for_duplicate(finding)
                    self._annotate_dropped_views(
                        finding,
                        drop_reason=drop_reason,
                        recommended_branch=recommended_branch,
                    )
                    self.stats.record_selection_drop(drop_reason)
                    self._record_selection_drop(
                        finding,
                        drop_stage="dedup",
                        drop_reason=drop_reason,
                        recommended_branch=recommended_branch,
                    )
                    self._update_selection_bucket(finding)
                    self._record_selection_shadow(finding, recommended_branch)
                    continue

                self.deduplicator.register(finding)
                self._annotate_published_views(finding)
                self._annotate_orbit(finding)
                self._update_selection_bucket(finding)
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
        orbit_seen_count = self._orbit_seen_counts.get(orbit_key, 0) + 1
        self._orbit_seen_counts[orbit_key] = orbit_seen_count
        metadata["orbit_seen_count"] = orbit_seen_count

        signature = self._orbit_signature(finding)
        metadata["orbit_signature"] = {
            "oracle_name": signature[0],
            "diff_pattern_hash": signature[1],
            "strategy": signature[2],
            "category": signature[3],
        }
        seen_signatures = self._seen_orbit_signatures.setdefault(orbit_key, set())

        if orbit_key in self._seen_orbits:
            prior_same_oracle = any(sig[0] == signature[0] for sig in seen_signatures)
            prior_same_pattern = signature in seen_signatures

            if prior_same_pattern:
                metadata["orbit_status"] = "duplicate_downgraded"
                metadata["orbit_downgraded"] = finding.severity in _ORBIT_DOWNGRADE_ALLOWED
                metadata["orbit_downgrade_reason"] = "same_orbit_same_pattern"
                if finding.severity in _ORBIT_DOWNGRADE_ALLOWED:
                    self.stats.record_orbit_downgrade("same_orbit_same_pattern")
                    metadata["orbit_original_severity"] = finding.severity.value
                    finding.severity = Severity.INFO
            else:
                metadata["orbit_status"] = "variant_preserved"
                metadata["orbit_downgraded"] = False
                if prior_same_oracle:
                    metadata["orbit_downgrade_reason"] = "same_orbit_diff_pattern"
                else:
                    metadata["orbit_downgrade_reason"] = "same_orbit_diff_oracle"
        else:
            metadata["orbit_status"] = "first"
            metadata["orbit_downgraded"] = False
            metadata["orbit_downgrade_reason"] = ""
            self._seen_orbits.add(orbit_key)
        seen_signatures.add(signature)

    @staticmethod
    def _orbit_signature(finding: Finding) -> tuple[str, str, str, str]:
        metadata = finding.metadata
        return (
            finding.oracle_name,
            str(metadata.get("diff_pattern_hash", "") or ""),
            str(metadata.get("strategy", "") or ""),
            str(metadata.get("category", "") or ""),
        )

    @staticmethod
    def _normalize_findings(findings_or_one) -> list[Finding]:
        if findings_or_one is None:
            return []
        if isinstance(findings_or_one, list):
            return findings_or_one
        return [findings_or_one]

    def _record_selection_drop(
        self,
        finding: Finding,
        *,
        drop_stage: str,
        drop_reason: str,
        recommended_branch: str = "",
    ) -> None:
        if self._selection_drop_sink is None:
            return

        record = {
            "title": finding.title,
            "oracle_name": finding.oracle_name,
            "severity": finding.severity.value,
            "fingerprint": finding.fingerprint,
            "drop_stage": drop_stage,
            "drop_reason": drop_reason,
            "recommended_branch": recommended_branch,
            "metadata": {
                "category": finding.metadata.get("category", ""),
                "strategy": finding.metadata.get("strategy", ""),
                "strategies": list(finding.metadata.get("strategies", []) or []),
                "diff_fields": sorted(finding.metadata.get("diff_fields", []) or []),
                "all_diff_fields": sorted(
                    finding.metadata.get("all_diff_fields", []) or [],
                ),
                "diff_pattern_hash": finding.metadata.get("diff_pattern_hash", ""),
                "accepting_side": finding.metadata.get("accepting_side", ""),
                "waf_witness_family": finding.metadata.get("waf_witness_family", ""),
                "fine_fingerprint": finding.metadata.get("fine_fingerprint", ""),
                "fingerprint_components": finding.metadata.get("fingerprint_components", {}),
                "selection_policy": finding.metadata.get("selection_policy", {}),
                "orbit_canonical_key": finding.metadata.get("orbit_canonical_key", ""),
                "session_key": finding.metadata.get("session_key", ""),
                "prefix_depth": finding.metadata.get("prefix_depth"),
                "replay_context": finding.metadata.get("replay_context"),
                "raw_view": finding.metadata.get("raw_view", {}),
                "publish_view": finding.metadata.get("publish_view", {}),
                "historical_view": finding.metadata.get("historical_view", {}),
            },
        }
        self._selection_drop_sink(record)

    def _record_selection_shadow(
        self,
        finding: Finding,
        recommended_branch: str,
    ) -> None:
        if self._selection_shadow_sink is None:
            return
        if recommended_branch != "shadow_queue_review":
            return
        record = {
            "title": finding.title,
            "oracle_name": finding.oracle_name,
            "severity": finding.severity.value,
            "fingerprint": finding.fingerprint,
            "shadow_reason": recommended_branch,
            # Keep the raw candidate around in a replay-friendly encoding so
            # post-run triage can materialize an actual seed corpus instead of
            # stopping at a summary-only diagnostic artifact.
            "input_b64": base64.b64encode(finding.input.data).decode("ascii"),
            "metadata": {
                "category": finding.metadata.get("category", ""),
                "strategy": finding.metadata.get("strategy", ""),
                "waf_witness_family": finding.metadata.get("waf_witness_family", ""),
                "fine_fingerprint": finding.metadata.get("fine_fingerprint", ""),
                "fingerprint_components": finding.metadata.get("fingerprint_components", {}),
                "selection_policy": finding.metadata.get("selection_policy", {}),
                "session_key": finding.metadata.get("session_key", ""),
                "prefix_depth": finding.metadata.get("prefix_depth"),
                "replay_context": finding.metadata.get("replay_context"),
                "raw_view": finding.metadata.get("raw_view", {}),
                "publish_view": finding.metadata.get("publish_view", {}),
                "historical_view": finding.metadata.get("historical_view", {}),
            },
        }
        self._selection_shadow_sink(record)

    @staticmethod
    def _duplicate_drop_reason(finding: Finding) -> str:
        components = finding.metadata.get("fingerprint_components", {}) or {}
        mode = str(components.get("mode") or "unknown")
        if mode == "birkhoff_bitvector":
            return "duplicate_coarse_bv"
        if mode == "diff_pattern_hash":
            return "duplicate_exact_pattern"
        if mode == "fallback_error_skeleton":
            return "duplicate_fallback_signature"
        return "duplicate_fingerprint"

    def _selection_branch_for_duplicate(self, finding: Finding) -> str:
        coarse_fingerprint = finding.fingerprint
        bucket = self._selection_buckets.setdefault(coarse_fingerprint, _selection_bucket_state())
        fine_fingerprints = set(bucket["fine_fingerprints"])
        strategies = set(bucket["strategies"])
        oracle_names = set(bucket["oracle_names"])
        orbit_keys = set(bucket["orbit_keys"])
        session_keys = set(bucket["session_keys"])
        witness_families = set(bucket["witness_families"])

        fine_fingerprint = str(finding.metadata.get("fine_fingerprint", "") or "")
        strategy = str(finding.metadata.get("strategy", "") or "")
        orbit_key = self._selection_orbit_key(finding)
        session_key = self._selection_session_key(finding)
        witness_family = str(finding.metadata.get("waf_witness_family", "") or "")
        if fine_fingerprint:
            fine_fingerprints.add(fine_fingerprint)
        if strategy:
            strategies.add(strategy)
        if finding.oracle_name:
            oracle_names.add(finding.oracle_name)
        if orbit_key:
            orbit_keys.add(orbit_key)
        if session_key:
            session_keys.add(session_key)
        if witness_family:
            witness_families.add(witness_family)

        evidence = SelectionEvidence.from_values(
            drop_reason=self._duplicate_drop_reason(finding),
            fingerprint_mode=self._fingerprint_mode(finding),
            unique_fine_fingerprints=len(fine_fingerprints),
            strategy_count=len(strategies),
            oracle_count=len(oracle_names),
            orbit_count=len(orbit_keys),
            session_count=len(session_keys),
            witness_families=witness_families,
        )
        branch = choose_selection_branch(evidence)
        finding.metadata["selection_policy"] = {
            "branch": branch.value,
            "evidence": evidence.to_metadata(),
            "contract_ok": selection_branch_contract(branch, evidence),
        }
        return branch.value

    def _maybe_preserve_duplicate_via_hotspot_branch(self, finding: Finding) -> bool:
        branch = self._selection_branch_for_duplicate(finding)
        if branch != "fine_preserve_bucket":
            return False

        coarse_fingerprint = finding.fingerprint
        fine_fingerprint = str(finding.metadata.get("fine_fingerprint", "") or "")
        if not fine_fingerprint:
            return False

        bucket = self._selection_buckets.setdefault(coarse_fingerprint, _selection_bucket_state())
        if fine_fingerprint in bucket["fine_fingerprints"]:
            return False

        # Keep one representative per unseen fine fingerprint inside a coarse
        # bucket. This lets us preserve semantic diversity without completely
        # disabling coarse dedup for noisy buckets.
        finding.metadata["selection_branch"] = branch
        finding.metadata["selection_preserved_from_duplicate"] = True
        finding.metadata["coarse_fingerprint"] = coarse_fingerprint
        finding.fingerprint = self._promoted_fine_fingerprint(
            coarse_fingerprint=coarse_fingerprint,
            fine_fingerprint=fine_fingerprint,
        )

        if self.deduplicator.is_duplicate(finding):
            return False

        self.deduplicator.register(finding)
        return True

    @staticmethod
    def _promoted_fine_fingerprint(
        *,
        coarse_fingerprint: str,
        fine_fingerprint: str,
    ) -> str:
        h = hashlib.sha256()
        h.update(f"{coarse_fingerprint}\x1f{fine_fingerprint}".encode("utf-8"))
        return h.hexdigest()[:16]

    @staticmethod
    def _fingerprint_mode(finding: Finding) -> str:
        components = finding.metadata.get("fingerprint_components", {}) or {}
        return str(components.get("mode") or "unknown")

    def _selection_orbit_key(self, finding: Finding) -> str:
        orbit_key = str(finding.metadata.get("orbit_canonical_key", "") or "")
        if orbit_key:
            return orbit_key
        try:
            return canonical_key(finding.input.data)
        except Exception:  # pragma: no cover - canonical_key is intended total
            logger.debug("selection orbit key failed", exc_info=True)
            return ""

    def _update_selection_bucket(self, finding: Finding) -> None:
        coarse_fingerprint = str(finding.metadata.get("coarse_fingerprint", "") or finding.fingerprint)
        bucket = self._selection_buckets.setdefault(coarse_fingerprint, _selection_bucket_state())
        fine_fingerprint = str(finding.metadata.get("fine_fingerprint", "") or "")
        strategy = str(finding.metadata.get("strategy", "") or "")
        orbit_key = str(finding.metadata.get("orbit_canonical_key", "") or "")
        session_key = self._selection_session_key(finding)
        witness_family = str(finding.metadata.get("waf_witness_family", "") or "")
        if fine_fingerprint:
            bucket["fine_fingerprints"].add(fine_fingerprint)
        if strategy:
            bucket["strategies"].add(strategy)
        if finding.oracle_name:
            bucket["oracle_names"].add(finding.oracle_name)
        if orbit_key:
            bucket["orbit_keys"].add(orbit_key)
        if session_key:
            bucket["session_keys"].add(session_key)
        if witness_family:
            bucket["witness_families"].add(witness_family)

    def _annotate_session_context(self, finding: Finding) -> None:
        """Normalize session-scoped metadata onto ``finding.metadata``.

        The follow-up theory distinguishes a raw differential witness from a
        session-level survivor: the same byte-level diff can appear under
        different prefixes or replay contexts and therefore have different
        persistence behaviour.  We normalize those fields here so downstream
        dedup/drop code can record that distinction without each producer
        needing to agree on one exact metadata location.
        """
        metadata = finding.metadata

        session_key = self._first_session_value(finding, "session_key")
        if session_key is not None:
            metadata.setdefault("session_key", session_key)

        prefix_depth = self._first_session_value(finding, "prefix_depth")
        if prefix_depth is not None:
            metadata.setdefault("prefix_depth", prefix_depth)

        replay_context = self._first_session_value(finding, "replay_context")
        if replay_context is not None:
            metadata.setdefault("replay_context", replay_context)

    @staticmethod
    def _annotate_raw_view(finding: Finding) -> None:
        """Capture the pre-selection view of a candidate finding.

        This is the richest local view we have before dedup or publish policy
        compresses anything.  It lets later analysis ask "what did the oracle
        actually see?" even if the candidate is eventually shadowed or dropped.
        """
        metadata = finding.metadata
        metadata["raw_view"] = {
            "state": "observed_candidate",
            "fingerprint": finding.fingerprint,
            "oracle_name": finding.oracle_name,
            "severity": finding.severity.value,
            "diff_pattern_hash": metadata.get("diff_pattern_hash", ""),
            "fine_fingerprint": metadata.get("fine_fingerprint", ""),
            "session_key": metadata.get("session_key", ""),
            "prefix_depth": metadata.get("prefix_depth"),
            "replay_context": metadata.get("replay_context"),
        }

    @staticmethod
    def _annotate_published_views(finding: Finding) -> None:
        """Mark that a candidate survived the publish/persistence pipeline."""
        metadata = finding.metadata
        metadata["publish_view"] = {
            "state": "published",
            "selection_branch": metadata.get("selection_branch", ""),
            "fingerprint": finding.fingerprint,
            "coarse_fingerprint": metadata.get("coarse_fingerprint", ""),
        }
        metadata["historical_view"] = {
            "state": "persisted_finding",
            "persisted": True,
        }

    @staticmethod
    def _annotate_dropped_views(
        finding: Finding,
        *,
        drop_reason: str,
        recommended_branch: str,
    ) -> None:
        """Mark how a raw candidate looked after selection/persistence policy."""
        metadata = finding.metadata
        publish_state = (
            "shadow_queue"
            if recommended_branch == "shadow_queue_review"
            else "selection_drop"
        )
        historical_state = (
            "shadow_only"
            if recommended_branch == "shadow_queue_review"
            else "not_persisted"
        )
        metadata["publish_view"] = {
            "state": publish_state,
            "drop_reason": drop_reason,
            "recommended_branch": recommended_branch,
            "fingerprint": finding.fingerprint,
        }
        metadata["historical_view"] = {
            "state": historical_state,
            "persisted": False,
        }

    @staticmethod
    def _first_session_value(finding: Finding, key: str):
        for source in (
            finding.metadata,
            finding.input.metadata,
            finding.result.metadata,
        ):
            if key not in source:
                continue
            value = source.get(key)
            if value is None:
                continue
            if isinstance(value, str) and not value:
                continue
            return value
        return None

    def _selection_session_key(self, finding: Finding) -> str:
        """Return a stable session signature for bucket-level diagnostics.

        ``session_key`` is preferred when a caller provides one explicitly.
        Otherwise we fall back to the pieces most likely to explain why a raw
        diff survived in one run but not another: prefix depth and replay
        context.  The result is only used for diagnostics and hotspot routing,
        not for the main operational fingerprint.
        """
        session_key = str(finding.metadata.get("session_key", "") or "")
        if session_key:
            return session_key

        parts: list[str] = []
        prefix_depth = finding.metadata.get("prefix_depth")
        if prefix_depth is not None and prefix_depth != "":
            parts.append(f"prefix={prefix_depth}")

        replay_context = finding.metadata.get("replay_context")
        if replay_context not in (None, "", {}):
            if isinstance(replay_context, str):
                parts.append(f"replay={replay_context}")
            else:
                parts.append(
                    "replay="
                    + json.dumps(
                        replay_context,
                        sort_keys=True,
                        default=str,
                    ),
                )

        return "|".join(parts)

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
