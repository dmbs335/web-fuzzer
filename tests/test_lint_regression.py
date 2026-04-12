"""Phase 2D: Lint regression guard.

Asserts that the stored diffspace-geometry lint outputs for the two stable
run_ids have zero FAIL entries.  This is a static test (reads pre-computed
JSON, no re-running experiments) and runs in < 0.5s.

If either file is absent the test is skipped — the guard only fires when
the lint artefacts are present, so CI on a fresh clone without the
experiment outputs does not fail.

Run_ids covered:
  - waf_v61_20260407: 18h WAF hybrid campaign (baseline)
  - saml_stageb_merged: merged SAML stage-B campaign (baseline)
  - waf_feedback_test: short WAF feedback run (Phase 1 validation output)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

_OUTPUTS_ROOT = Path("experiments/diffspace_geometry/outputs")

_LINT_FILES: list[tuple[str, str]] = [
    ("waf_v61_20260407",   "lint_baseline.json"),
    ("waf_feedback_test",  "lint_after.json"),
]


def _load_lint(run_id: str, filename: str) -> dict | None:
    p = _OUTPUTS_ROOT / run_id / filename
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.mark.parametrize("run_id,filename", _LINT_FILES)
def test_lint_no_fail(run_id: str, filename: str) -> None:
    """No FAIL in stored lint output for run_id."""
    data = _load_lint(run_id, filename)
    if data is None:
        pytest.skip(f"lint artefact not present: {run_id}/{filename}")

    summary = data.get("summary", {})
    fail_count = summary.get("fail", 0)
    assert fail_count == 0, (
        f"{run_id}/{filename}: summary.fail={fail_count} (expected 0)"
    )

    checks = data.get("checks", [])
    failed_checks = [c for c in checks if c.get("status") == "FAIL"]
    assert not failed_checks, (
        f"{run_id}/{filename}: FAIL checks: "
        + ", ".join(f"{c['id']}: {c.get('message','')}" for c in failed_checks)
    )


@pytest.mark.parametrize("run_id,filename", _LINT_FILES)
def test_lint_all_checks_present(run_id: str, filename: str) -> None:
    """All 19 DG checks (DG001–DG019) are present in the stored output."""
    data = _load_lint(run_id, filename)
    if data is None:
        pytest.skip(f"lint artefact not present: {run_id}/{filename}")

    checks = data.get("checks", [])
    ids_present = {c["id"] for c in checks}
    expected = {f"DG{i:03d}" for i in range(1, 20)}
    missing = expected - ids_present
    assert not missing, (
        f"{run_id}/{filename}: missing check IDs: {sorted(missing)}"
    )
