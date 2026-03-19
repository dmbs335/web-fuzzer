"""Target assembly helpers for CLI runtime wiring."""

from __future__ import annotations

from dataclasses import dataclass

from ...fuzzer.targets.process_target import ProcessTarget


@dataclass
class TargetAssembly:
    """Primary/reference target configuration for a fuzzing run."""

    target: object
    reference_targets: list
    use_persistent: bool


def _build_target_from_cmd(
    cmd: str,
    *,
    grammar: str,
    requested_oracle_names: set[str],
    use_persistent: bool,
    use_target_cov: bool,
    whitebox_lines_only: bool,
    to_persistent_cmd,
    persistent_timeout_for_cmd,
    is_reference: bool = False,
):
    """Build a target instance from a command line."""
    if use_persistent:
        from ...fuzzer.targets.persistent_target import PersistentTarget

        timeout = persistent_timeout_for_cmd(
            cmd,
            grammar,
            requested_oracle_names,
            is_reference=is_reference,
        )
        persistent_cmd = to_persistent_cmd(
            cmd,
            target_coverage=use_target_cov,
            lines_only=whitebox_lines_only,
        )
        if persistent_cmd is not None:
            target = PersistentTarget(persistent_cmd, timeout_seconds=timeout)
        else:
            target = ProcessTarget(cmd)
    else:
        target = ProcessTarget(cmd)

    target.original_cmd = cmd
    return target


def build_targets(
    args,
    *,
    requested_oracle_names: set[str],
    to_persistent_cmd,
    persistent_timeout_for_cmd,
) -> TargetAssembly:
    """Build the primary target and any differential reference targets."""
    diff_cmds: list[str] = getattr(args, "diff_cmd", [])
    use_persistent = getattr(args, "persistent", False)
    whitebox_lines_only = (
        getattr(args, "concolic", False)
        and getattr(args, "concolic_mode", "") == "whitebox"
    )
    use_target_cov = getattr(args, "target_coverage", False)

    if not use_persistent:
        all_cmds = [args.target_cmd] + diff_cmds
        if any(to_persistent_cmd(cmd) is not None for cmd in all_cmds):
            use_persistent = True

    target = _build_target_from_cmd(
        args.target_cmd,
        grammar=args.grammar,
        requested_oracle_names=requested_oracle_names,
        use_persistent=use_persistent,
        use_target_cov=use_target_cov,
        whitebox_lines_only=whitebox_lines_only,
        to_persistent_cmd=to_persistent_cmd,
        persistent_timeout_for_cmd=persistent_timeout_for_cmd,
        is_reference=False,
    )
    reference_targets = [
        _build_target_from_cmd(
            cmd,
            grammar=args.grammar,
            requested_oracle_names=requested_oracle_names,
            use_persistent=use_persistent,
            use_target_cov=use_target_cov,
            whitebox_lines_only=whitebox_lines_only,
            to_persistent_cmd=to_persistent_cmd,
            persistent_timeout_for_cmd=persistent_timeout_for_cmd,
            is_reference=True,
        )
        for cmd in diff_cmds
    ]
    return TargetAssembly(
        target=target,
        reference_targets=reference_targets,
        use_persistent=use_persistent,
    )
