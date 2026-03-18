"""Class pollution differential strategies.

Compares merge implementations to find pollution acceptance divergence:
  1. MergeAcceptRejectStrategy: one allows dunder traversal, another blocks
  2. PollutionDepthStrategy: different chain depths reached
  3. GlobalsReachabilityStrategy: one reaches __globals__, another doesn't
  4. DunderFilterStrategy: which dunders each implementation filters
"""
from __future__ import annotations

import json
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse(result: ExecutionResult) -> dict | None:
    parsed = result.parsed_json()
    if parsed and isinstance(parsed, dict) and "merged" in parsed:
        return parsed
    if not result.stdout:
        return None
    try:
        data = json.loads(result.stdout.strip())
        if isinstance(data, dict) and "merged" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


class MergeAcceptRejectStrategy:
    """Detect when one merge impl allows dunder traversal and another blocks it."""

    name = "merge_accept_reject"

    def analyze(
        self,
        inp: Input,
        results: list[ExecutionResult],
        target_names: list[str],
    ) -> Finding | None:
        parsed_results = [_parse(r) for r in results]
        valid = [(i, p) for i, p in enumerate(parsed_results) if p is not None]
        if len(valid) < 2:
            return None

        # Check for divergence in dunder_traversed
        traversed_sets = []
        for i, p in valid:
            dunders = p.get("dunder_traversed", [])
            traversed_sets.append((i, set(dunders), p))

        # Find pairs where one has dunders and other doesn't
        for ai in range(len(traversed_sets)):
            for bi in range(ai + 1, len(traversed_sets)):
                idx_a, set_a, pa = traversed_sets[ai]
                idx_b, set_b, pb = traversed_sets[bi]

                if set_a and not set_b:
                    accepting = idx_a
                    blocking = idx_b
                elif set_b and not set_a:
                    accepting = idx_b
                    blocking = idx_a
                else:
                    continue

                pa_data = parsed_results[accepting]
                pb_data = parsed_results[blocking]
                a_impl = pa_data.get("merge_impl", "unknown")
                b_impl = pb_data.get("merge_impl", "unknown")
                a_dunders = pa_data.get("dunder_traversed", [])

                severity = Severity.HIGH
                if "__globals__" in a_dunders or "__init__" in a_dunders:
                    severity = Severity.CRITICAL

                return Finding(
                    title=f"Merge accept/reject split: {a_impl} traverses dunders, {b_impl} blocks",
                    severity=severity,
                    input=inp,
                    result=results[accepting],
                    oracle_name="class_pollution_diff",
                    fingerprint=f"cp_diff:accept_reject:{a_impl}:{b_impl}:{sorted(a_dunders)[0] if a_dunders else 'none'}",
                    metadata={
                        "category": "merge_accept_reject",
                        "strategy": self.name,
                        "accepting_impl": a_impl,
                        "blocking_impl": b_impl,
                        "accepting_idx": accepting,
                        "blocking_idx": blocking,
                        "dunder_traversed": a_dunders,
                    },
                )

        return None


class PollutionDepthStrategy:
    """Detect when implementations reach different chain depths."""

    name = "pollution_depth"

    def analyze(
        self,
        inp: Input,
        results: list[ExecutionResult],
        target_names: list[str],
    ) -> Finding | None:
        parsed_results = [_parse(r) for r in results]
        valid = [(i, p) for i, p in enumerate(parsed_results) if p is not None]
        if len(valid) < 2:
            return None

        depths = [(i, p.get("chain_depth", 0), p) for i, p in valid]
        depths.sort(key=lambda x: x[1], reverse=True)

        deepest_idx, deepest_depth, deepest_p = depths[0]
        shallowest_idx, shallowest_depth, shallowest_p = depths[-1]

        if deepest_depth > shallowest_depth and deepest_depth >= 2:
            diff = deepest_depth - shallowest_depth
            severity = Severity.HIGH if deepest_depth >= 3 else Severity.MEDIUM
            d_impl = deepest_p.get("merge_impl", "unknown")
            s_impl = shallowest_p.get("merge_impl", "unknown")

            return Finding(
                title=f"Chain depth divergence: {d_impl} depth={deepest_depth} vs {s_impl} depth={shallowest_depth}",
                severity=severity,
                input=inp,
                result=results[deepest_idx],
                oracle_name="class_pollution_diff",
                fingerprint=f"cp_diff:depth:{d_impl}:{s_impl}:{deepest_depth}",
                metadata={
                    "category": "chain_depth_divergence",
                    "strategy": self.name,
                    "deeper_impl": d_impl,
                    "shallower_impl": s_impl,
                    "deeper_idx": deepest_idx,
                    "deeper_depth": deepest_depth,
                    "shallower_depth": shallowest_depth,
                },
            )

        return None


class GlobalsReachabilityStrategy:
    """Detect when one implementation reaches __globals__ and another doesn't."""

    name = "globals_reachability"

    def analyze(
        self,
        inp: Input,
        results: list[ExecutionResult],
        target_names: list[str],
    ) -> Finding | None:
        parsed_results = [_parse(r) for r in results]
        valid = [(i, p) for i, p in enumerate(parsed_results) if p is not None]
        if len(valid) < 2:
            return None

        has_globals = []
        no_globals = []
        for i, p in valid:
            polluted = p.get("globals_polluted", [])
            if polluted:
                has_globals.append((i, p))
            else:
                no_globals.append((i, p))

        if has_globals and no_globals:
            gi, gp = has_globals[0]
            ni, np = no_globals[0]
            g_impl = gp.get("merge_impl", "unknown")
            n_impl = np.get("merge_impl", "unknown")
            polluted = gp.get("globals_polluted", [])

            return Finding(
                title=f"Globals reachability split: {g_impl} writes globals, {n_impl} doesn't",
                severity=Severity.CRITICAL,
                input=inp,
                result=results[gi],
                oracle_name="class_pollution_diff",
                fingerprint=f"cp_diff:globals_reach:{g_impl}:{n_impl}:{sorted(polluted)[0] if polluted else 'none'}",
                metadata={
                    "category": "globals_reachability",
                    "strategy": self.name,
                    "polluting_impl": g_impl,
                    "safe_impl": n_impl,
                    "polluting_idx": gi,
                    "globals_polluted": polluted,
                },
            )

        return None


class DunderFilterStrategy:
    """Detect differences in which dunder attributes each implementation filters."""

    name = "dunder_filter"

    def analyze(
        self,
        inp: Input,
        results: list[ExecutionResult],
        target_names: list[str],
    ) -> Finding | None:
        parsed_results = [_parse(r) for r in results]
        valid = [(i, p) for i, p in enumerate(parsed_results) if p is not None]
        if len(valid) < 2:
            return None

        # Compare dunder traversal sets
        traversals = [(i, set(p.get("dunder_traversed", [])), p) for i, p in valid]

        for ai in range(len(traversals)):
            for bi in range(ai + 1, len(traversals)):
                idx_a, set_a, pa = traversals[ai]
                idx_b, set_b, pb = traversals[bi]

                # Only interesting if both traverse some dunders but differently
                if not set_a and not set_b:
                    continue
                extra_a = set_a - set_b
                extra_b = set_b - set_a

                if not extra_a and not extra_b:
                    continue

                # Determine which side is weaker (allows more dunders)
                if len(set_a) >= len(set_b):
                    weaker_idx, weaker_p, weaker_set = idx_a, pa, set_a
                    stronger_idx, stronger_p, stronger_set = idx_b, pb, set_b
                else:
                    weaker_idx, weaker_p, weaker_set = idx_b, pb, set_b
                    stronger_idx, stronger_p, stronger_set = idx_a, pa, set_a

                w_impl = weaker_p.get("merge_impl", "unknown")
                s_impl = stronger_p.get("merge_impl", "unknown")
                unfiltered = weaker_set - stronger_set

                if not unfiltered:
                    continue

                severity = Severity.HIGH
                if "__globals__" in unfiltered or "__init__" in unfiltered:
                    severity = Severity.CRITICAL

                return Finding(
                    title=f"Dunder filter gap: {w_impl} allows {sorted(unfiltered)}, {s_impl} blocks them",
                    severity=severity,
                    input=inp,
                    result=results[weaker_idx],
                    oracle_name="class_pollution_diff",
                    fingerprint=f"cp_diff:filter:{w_impl}:{s_impl}:{sorted(unfiltered)[0]}",
                    metadata={
                        "category": "filter_bypass",
                        "strategy": self.name,
                        "weaker_impl": w_impl,
                        "stronger_impl": s_impl,
                        "unfiltered_dunders": sorted(unfiltered),
                        "weaker_idx": weaker_idx,
                    },
                )

        return None


def get_class_pollution_strategies() -> list:
    """Return all class pollution differential strategies."""
    return [
        MergeAcceptRejectStrategy(),
        GlobalsReachabilityStrategy(),
        PollutionDepthStrategy(),
        DunderFilterStrategy(),
    ]
