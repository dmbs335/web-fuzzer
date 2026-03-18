"""Apache Confusion differential strategies for cross-config comparison.

Detects exploitable confusion between Apache module interactions:
  1. AccessBypass   (CRITICAL) — one config allows, another denies same URL
  2. PhaseConfusion (HIGH)     — phase fields change after access check
  3. CrossConfig    (MEDIUM)   — phase traces diverge across configs

FP filters applied:
  - Proxy URL cosmetic normalization (port 80 implicit vs explicit)
  - Empty phase trace (403/error responses with no X-FuzzTrace)
  - Handler set from empty to content-type (normal fixup behaviour)

References:
  - Orange Tsai, "Confusion Attacks" (Black Hat USA 2024)
  - Apache httpd request processing phases
"""

from __future__ import annotations

import json
import re
from typing import Any

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_output(stdout: bytes) -> dict | None:
    """Parse JSON output from an Apache confusion target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "status_code" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _is_success(status: int) -> bool:
    return 200 <= status < 400


def _is_denied(status: int) -> bool:
    return status in (401, 403)


def _input_preview(inp: Input) -> str:
    return inp.data[:200].decode("utf-8", errors="replace")


# ── FP filters ───────────────────────────────────────────────────

# Regex: proxy URL with explicit :80 (HTTP default port)
_PROXY_PORT80_RE = re.compile(r"(https?://[^/:]+):80(/|$)")


def _normalize_proxy_url(url: str) -> str:
    """Strip explicit :80 from proxy URLs for comparison.

    proxy:http://127.0.0.1:80/path → proxy:http://127.0.0.1/path
    This is cosmetic normalization, NOT a confusion.
    """
    return _PROXY_PORT80_RE.sub(r"\1\2", url)


def _is_cosmetic_filename_diff(fn_a: str, fn_b: str) -> bool:
    """Check if two filenames differ only in cosmetic proxy normalization."""
    if not fn_a or not fn_b:
        return False
    return _normalize_proxy_url(fn_a) == _normalize_proxy_url(fn_b)


def _is_handler_fixup_only(h_ac: str, h_handler: str) -> bool:
    """Check if handler change is just the normal fixup → content-type assignment.

    Empty handler at access_check → content-type at handler is normal Apache
    behaviour (mod_mime assigns handler in type_checker phase after access_check).
    """
    return (not h_ac or h_ac == "") and h_handler != ""


def _has_valid_trace(d: dict) -> bool:
    """Check if the parsed output has meaningful phase trace data (not just error)."""
    return d.get("uri_at_access_check", "") != "" or d.get("filename_at_access_check", "") != ""


# ── Mechanism classification ─────────────────────────────────────


def _confusion_mechanism(p: dict, r: dict, inp: Input | None = None) -> str:
    """Classify the confusion mechanism from phase trace data and input."""
    # Use input URL for pattern detection
    inp_str = ""
    if inp is not None:
        inp_str = inp.data.decode("utf-8", errors="replace")
    if not inp_str:
        inp_str = p.get("uri_at_access_check", "") or p.get("uri_at_handler", "")

    p_fn_ac = p.get("filename_at_access_check", "")
    p_fn_h = p.get("filename_at_handler", "")

    # Proxy URL confusion: filename starts with proxy: scheme
    if p_fn_ac.startswith("proxy:") or p_fn_h.startswith("proxy:"):
        if _is_cosmetic_filename_diff(p_fn_ac, p_fn_h):
            return "proxy_cosmetic_normalization"
        return "proxy_filename_confusion"

    # Input-pattern based classification
    if "..;" in inp_str:
        return "path_param_traversal"
    if "%2e%2e" in inp_str.lower() or "%252e" in inp_str.lower():
        return "encoded_traversal"
    if ".." in inp_str:
        return "traversal"
    if ";jsessionid=" in inp_str.lower() or ";%3b" in inp_str.lower():
        return "path_param_jsessionid"
    if ";" in inp_str or "%3b" in inp_str.lower():
        return "path_param_confusion"
    if "%2f" in inp_str.lower() or "%5c" in inp_str.lower():
        return "encoded_separator"
    if "//" in inp_str:
        return "slash_merging"
    if "%00" in inp_str:
        return "null_byte"
    if "%2e" in inp_str.lower():
        return "encoded_dot"

    # Trace-based classification
    if p_fn_ac and p_fn_h and p_fn_ac != p_fn_h:
        return "filename_mutation"
    if p.get("handler_at_access_check") != p.get("handler_at_handler"):
        handler_ac = p.get("handler_at_access_check", "")
        handler_h = p.get("handler_at_handler", "")
        if not handler_ac and handler_h:
            return "handler_late_assignment"
        return "handler_mutation"
    return "unknown"


# ── Strategy 1: Access Bypass (CRITICAL) ─────────────────────────


class AccessBypassStrategy:
    """Detects when one Apache config denies a URL that another allows.

    FP filter: requires BOTH sides to have valid phase traces.
    A 403 with no trace (error response) compared against a 200 with
    full trace is only meaningful if we can see WHY the denial happened.
    """

    name = "access_bypass"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_output(primary.stdout)
        r = _parse_output(reference.stdout)
        if not p or not r:
            return None

        p_status = p.get("status_code", 0)
        r_status = r.get("status_code", 0)

        # One allows, the other denies
        if _is_success(p_status) and _is_denied(r_status):
            accepting_side = "primary"
        elif _is_denied(p_status) and _is_success(r_status):
            accepting_side = "ref"
        else:
            return None

        # Body content heuristic: if the accepting side served protected
        # content markers, this is a confirmed content leak regardless of
        # phase confusion signals.
        accepting = p if accepting_side == "primary" else r
        content_leaked = accepting.get("served_protected_content", False)
        body_marker = accepting.get("body_marker", "")

        if content_leaked:
            mechanism = _confusion_mechanism(p, r, inp)
            return Finding(
                title=(
                    f"CONTENT LEAK: protected content served ({body_marker!r}) "
                    f"via {accepting_side} (status={accepting.get('status_code')}), "
                    f"ref[{ref_index}] denies"
                ),
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "content_leak",
                    "mechanism": mechanism,
                    "accepting_side": accepting_side,
                    "primary_status": p_status,
                    "ref_status": r_status,
                    "ref_index": ref_index,
                    "body_marker": body_marker,
                    "input_preview": _input_preview(inp),
                    "confirmed_leak": True,
                },
            )

        # FP filter: require the accepting side to have phase confusion
        # indicators. A simple status code diff between Location-authz and
        # Directory-authz configs is expected — only report if the
        # accepting side also shows intra-phase confusion.
        if _has_valid_trace(accepting):
            fn_confused = accepting.get("filename_changed_post_access", False)
            uri_confused = accepting.get("uri_changed_post_access", False)
            if not fn_confused and not uri_confused:
                mechanism = _confusion_mechanism(p, r, inp)
                return Finding(
                    title=(
                        f"Config access divergence: {p_status} vs "
                        f"ref[{ref_index}]={r_status} (no phase confusion)"
                    ),
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": "access_bypass",
                        "mechanism": mechanism,
                        "accepting_side": accepting_side,
                        "primary_status": p_status,
                        "ref_status": r_status,
                        "ref_index": ref_index,
                        "input_preview": _input_preview(inp),
                        "downgraded": True,
                    },
                )

        mechanism = _confusion_mechanism(p, r, inp)

        return Finding(
            title=(
                f"Access bypass: config accepts ({p_status}) "
                f"vs ref[{ref_index}] denies ({r_status}) with phase confusion"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "access_bypass",
                "mechanism": mechanism,
                "accepting_side": accepting_side,
                "primary_status": p_status,
                "ref_status": r_status,
                "ref_index": ref_index,
                "input_preview": _input_preview(inp),
            },
        )


# ── Strategy 2: Phase Confusion (HIGH) ──────────────────────────


class PhaseConfusionStrategy:
    """Detects when request_rec fields change between access_check and handler.

    FP filters:
      - Proxy cosmetic normalization (port 80)
      - Handler assignment from empty (normal fixup)
      - Empty trace data (no X-FuzzTrace on error responses)
    """

    name = "phase_confusion"

    _PHASE_PAIRS = (
        ("uri_at_access_check", "uri_at_handler", "uri", "path_confusion"),
        ("filename_at_access_check", "filename_at_handler", "filename", "filename_confusion"),
        ("handler_at_access_check", "handler_at_handler", "handler", "handler_confusion"),
    )

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> list[Finding] | None:
        p = _parse_output(primary.stdout)
        r = _parse_output(reference.stdout)
        if not p or not r:
            return None

        # FP filter: skip if either side has no valid phase trace
        # (403/error with no X-FuzzTrace means we can't meaningfully compare)
        if not _has_valid_trace(p) or not _has_valid_trace(r):
            return None

        findings = []
        for ac_key, h_key, field_name, category in self._PHASE_PAIRS:
            p_ac = p.get(ac_key, "")
            p_h = p.get(h_key, "")
            r_ac = r.get(ac_key, "")
            r_h = r.get(h_key, "")

            p_confused = p_ac and p_h and p_ac != p_h
            r_confused = r_ac and r_h and r_ac != r_h

            # FP filter: handler empty→assigned is normal fixup
            if field_name == "handler":
                if _is_handler_fixup_only(p_ac, p_h):
                    p_confused = False
                if _is_handler_fixup_only(r_ac, r_h):
                    r_confused = False

            # FP filter: proxy URL cosmetic normalization
            if field_name == "filename":
                if p_confused and _is_cosmetic_filename_diff(p_ac, p_h):
                    p_confused = False
                if r_confused and _is_cosmetic_filename_diff(r_ac, r_h):
                    r_confused = False

            if p_confused == r_confused:
                continue

            confused_side = "primary" if p_confused else "ref"
            mechanism = _confusion_mechanism(p, r, inp)

            # Severity: filename confusion after filtering cosmetic = CRITICAL
            severity = Severity.HIGH
            if field_name == "filename":
                severity = Severity.CRITICAL

            findings.append(Finding(
                title=(
                    f"Phase confusion ({field_name}): "
                    f"{confused_side} has {ac_key} != {h_key} "
                    f"(ref[{ref_index}])"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": category,
                    "mechanism": mechanism,
                    "field": field_name,
                    "confused_side": confused_side,
                    "primary_ac": p_ac,
                    "primary_handler": p_h,
                    "ref_ac": r_ac,
                    "ref_handler": r_h,
                    "ref_index": ref_index,
                },
            ))

        return findings if findings else None


# ── Strategy 3: Cross-Config Divergence (MEDIUM) ────────────────


class CrossConfigConfusionStrategy:
    """Detects when the same URL produces different phase traces across configs.

    FP filter: skips cosmetic proxy normalization differences.
    """

    name = "cross_config"

    _TRACE_KEYS = (
        "uri_at_handler", "filename_at_handler",
        "handler_at_handler", "final_handler",
    )

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_output(primary.stdout)
        r = _parse_output(reference.stdout)
        if not p or not r:
            return None

        p_status = p.get("status_code", 0)
        r_status = r.get("status_code", 0)

        # Skip if both denied or both errored
        if _is_denied(p_status) and _is_denied(r_status):
            return None
        if p_status >= 500 and r_status >= 500:
            return None

        # Find diverging trace fields (with cosmetic normalization)
        diff_fields = []
        for key in self._TRACE_KEYS:
            pv = str(p.get(key, ""))
            rv = str(r.get(key, ""))
            if pv == rv or (not pv and not rv):
                continue
            # FP filter: normalize proxy URLs before comparison
            if "filename" in key:
                if _normalize_proxy_url(pv) == _normalize_proxy_url(rv):
                    continue
            # FP filter: handler empty vs content-type is normal
            if "handler" in key:
                if (not pv and rv) or (pv and not rv):
                    continue
            diff_fields.append(key)

        if not diff_fields:
            return None

        # Determine category from highest-priority differing field
        category = "phase_desync"
        if "filename_at_handler" in diff_fields:
            category = "filename_confusion"
        elif "handler_at_handler" in diff_fields:
            category = "handler_confusion"
        elif "final_handler" in diff_fields:
            category = "backend_confusion"

        mechanism = _confusion_mechanism(p, r, inp)

        return Finding(
            title=(
                f"Cross-config divergence: {','.join(diff_fields)} "
                f"differ (ref[{ref_index}])"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": category,
                "mechanism": mechanism,
                "diff_fields": diff_fields,
                "primary_status": p_status,
                "ref_status": r_status,
                "ref_index": ref_index,
            },
        )


# ── Factory ──────────────────────────────────────────────────────


def get_apache_confusion_strategies() -> list:
    """Return all Apache confusion diff strategies."""
    return [
        AccessBypassStrategy(),
        PhaseConfusionStrategy(),
        CrossConfigConfusionStrategy(),
    ]
