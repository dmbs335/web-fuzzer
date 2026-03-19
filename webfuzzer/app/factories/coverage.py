"""Coverage factory helpers."""

from __future__ import annotations


def build_coverage(
    args,
    *,
    is_diff_mode: bool,
    reference_targets: list,
    has_sanitizer_diff: bool = False,
):
    """Build the coverage collector for the current fuzzing mode."""
    if is_diff_mode:
        if getattr(args, "adaptive_coverage", False):
            from ...fuzzer.coverage.adaptive_coverage import (
                AdaptiveConfig,
                AdaptiveDiffCoverage,
                RefinementLevel,
            )

            if has_sanitizer_diff:
                adaptive_config = AdaptiveConfig(
                    initial_level=RefinementLevel.L2_COMPONENT,
                    stagnation_window=5000,
                    check_interval=getattr(args, "adaptive_check_interval", 5000),
                    upper_corpus_pct=getattr(args, "adaptive_upper_pct", 5.0),
                )
            else:
                adaptive_config = AdaptiveConfig(
                    initial_level=RefinementLevel(
                        getattr(args, "adaptive_level", 1),
                    ),
                    check_interval=getattr(args, "adaptive_check_interval", 5000),
                    upper_corpus_pct=getattr(args, "adaptive_upper_pct", 5.0),
                )
            return AdaptiveDiffCoverage(
                reference_targets=reference_targets,
                config=adaptive_config,
            )

        from ...fuzzer.coverage.diff_coverage import DiffCoverageCollector

        return DiffCoverageCollector(reference_targets=reference_targets)

    from ...fuzzer.coverage.response_coverage import ResponseCoverageCollector

    return ResponseCoverageCollector()
