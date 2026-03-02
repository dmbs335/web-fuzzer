"""Cookie differential strategies for cross-library comparison.

Detects exploitable divergences between cookie parser implementations:
  1. Accept/Reject Divergence (HIGH) — one accepts, another rejects
  2. Name Confusion (CRITICAL) — both accept but extract different names
  3. Value Confusion (HIGH) — same name, different value extracted
  4. Domain Scope Confusion (CRITICAL) — different domain scope
  5. Flag Divergence (HIGH) — different security flag interpretation
  6. Attribute Parsing Divergence (MEDIUM) — different attribute values

Architecture mirrors SamlDiffStrategy — pluggable DiffStrategy
for composition with DiffOracle.

References:
  - Cookie Crumbles (USENIX Security 2023) — 12 CVEs across 13 frameworks
  - PortSwigger "Cookie Chaos" (2025) — $Version parsing differentials
  - CVE-2024-47764 (npm cookie) — out-of-bounds character injection
  - CVE-2023-46218 (curl) — PSL case-sensitivity bypass
"""

from __future__ import annotations

import json
import logging

from ..protocols import ExecutionResult, Finding, Input, Severity

logger = logging.getLogger(__name__)


def _parse_cookie_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a cookie target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "name" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


# ── Primary strategy: Accept/Reject + Name/Value Confusion ───────


class CookieDiffStrategy:
    """Primary cookie differential strategy.

    Detects accept/reject divergence and name/value confusion between
    two cookie parser implementations.  These findings indicate parsing
    differentials that could be exploited for session hijacking, cookie
    injection, or WAF bypass.
    """

    name = "cookie_parsing"

    _trace_counter = 0
    _trace_interval = 500

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_cookie_output(primary.stdout)
        r = _parse_cookie_output(reference.stdout)

        CookieDiffStrategy._trace_counter += 1
        do_trace = (CookieDiffStrategy._trace_counter
                    % CookieDiffStrategy._trace_interval == 1)
        if do_trace:
            logger.warning(
                "TRACE[%d] ref[%d]: p=%s r=%s",
                CookieDiffStrategy._trace_counter, ref_index,
                "parsed" if p else "None",
                "parsed" if r else "None",
            )

        # Both failed — no interesting divergence
        if p is None and r is None:
            return None

        # ── HIGH: One-sided accept/reject ──
        if (p is None) != (r is None):
            parsed_side = "primary" if p is not None else f"ref[{ref_index}]"
            parsed = p if p is not None else r
            return Finding(
                title=(
                    f"Cookie Accept/Reject: {parsed_side} accepts "
                    f"(name={parsed.get('name')}) but the other rejects"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "accept_reject_divergence",
                    "accepting_side": parsed_side,
                    "ref_index": ref_index,
                    "parsed_name": parsed.get("name"),
                    "input_preview": _input_preview(inp),
                },
            )

        # Both parsed successfully
        p_name = (p.get("name") or "").strip()
        r_name = (r.get("name") or "").strip()
        p_value = (p.get("value") or "").strip()
        r_value = (r.get("value") or "").strip()

        # ── CRITICAL: Name confusion ──
        if p_name and r_name and p_name != r_name:
            return Finding(
                title=(
                    f"Cookie Name Confusion: "
                    f"primary='{p_name}' vs ref[{ref_index}]='{r_name}'"
                ),
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "name_confusion",
                    "primary_name": p_name,
                    "ref_name": r_name,
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        # ── HIGH: Value confusion ──
        if p_name == r_name and p_value != r_value:
            return Finding(
                title=(
                    f"Cookie Value Confusion: name='{p_name}' "
                    f"primary_value='{p_value[:50]}' vs "
                    f"ref[{ref_index}]_value='{r_value[:50]}'"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "value_confusion",
                    "cookie_name": p_name,
                    "primary_value": p_value[:200],
                    "ref_value": r_value[:200],
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            )

        return None


# ── Domain scope confusion ────────────────────────────────────────


class CookieDomainScopeStrategy:
    """Detect domain/path scope interpretation differences.

    Different domain scope means the cookie would be sent to different
    origins — exploitable for session hijacking and cookie tossing.
    """

    name = "cookie_scope"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_cookie_output(primary.stdout)
        r = _parse_cookie_output(reference.stdout)
        if p is None or r is None:
            return None

        # Domain confusion
        p_domain = (p.get("domain") or "").strip().lower()
        r_domain = (r.get("domain") or "").strip().lower()
        if p_domain != r_domain and (p_domain or r_domain):
            return Finding(
                title=(
                    f"Cookie Domain Confusion: "
                    f"primary='{p_domain}' vs ref[{ref_index}]='{r_domain}'"
                ),
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "domain_confusion",
                    "primary_domain": p_domain,
                    "ref_domain": r_domain,
                    "ref_index": ref_index,
                },
            )

        # Path confusion
        p_path = (p.get("path") or "").strip()
        r_path = (r.get("path") or "").strip()
        if p_path != r_path and (p_path or r_path):
            return Finding(
                title=(
                    f"Cookie Path Confusion: "
                    f"primary='{p_path}' vs ref[{ref_index}]='{r_path}'"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "path_confusion",
                    "primary_path": p_path,
                    "ref_path": r_path,
                    "ref_index": ref_index,
                },
            )

        return None


# ── Security flag divergence ──────────────────────────────────────


class CookieFlagDivergenceStrategy:
    """Detect security flag interpretation differences.

    If parsers disagree on Secure, HttpOnly, or SameSite flags,
    the cookie's security properties are ambiguous — one system
    may enforce protections while another doesn't.
    """

    name = "cookie_flags"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_cookie_output(primary.stdout)
        r = _parse_cookie_output(reference.stdout)
        if p is None or r is None:
            return None

        # Secure flag divergence
        p_secure = p.get("secure", False)
        r_secure = r.get("secure", False)
        if p_secure != r_secure:
            return Finding(
                title=(
                    f"Cookie Secure Flag Divergence: "
                    f"primary={p_secure} vs ref[{ref_index}]={r_secure}"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "secure_flag_divergence",
                    "primary_secure": p_secure,
                    "ref_secure": r_secure,
                    "ref_index": ref_index,
                },
            )

        # HttpOnly flag divergence
        p_httponly = p.get("httponly", False)
        r_httponly = r.get("httponly", False)
        if p_httponly != r_httponly:
            return Finding(
                title=(
                    f"Cookie HttpOnly Flag Divergence: "
                    f"primary={p_httponly} vs ref[{ref_index}]={r_httponly}"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "httponly_flag_divergence",
                    "primary_httponly": p_httponly,
                    "ref_httponly": r_httponly,
                    "ref_index": ref_index,
                },
            )

        # SameSite divergence
        p_ss = (p.get("samesite") or "").strip().lower()
        r_ss = (r.get("samesite") or "").strip().lower()
        if p_ss != r_ss and (p_ss or r_ss):
            return Finding(
                title=(
                    f"Cookie SameSite Divergence: "
                    f"primary='{p_ss}' vs ref[{ref_index}]='{r_ss}'"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "samesite_divergence",
                    "primary_samesite": p_ss,
                    "ref_samesite": r_ss,
                    "ref_index": ref_index,
                },
            )

        return None


# ── Expiry interpretation divergence ──────────────────────────────


class CookieExpiryStrategy:
    """Detect Expires/Max-Age interpretation differences.

    Expiry disagreements mean one parser treats the cookie as expired
    (delete) while another keeps it alive — or vice versa.
    """

    name = "cookie_expiry"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_cookie_output(primary.stdout)
        r = _parse_cookie_output(reference.stdout)
        if p is None or r is None:
            return None

        # Max-Age divergence
        p_ma = (p.get("max_age") or "").strip()
        r_ma = (r.get("max_age") or "").strip()
        if p_ma != r_ma and (p_ma or r_ma):
            return Finding(
                title=(
                    f"Cookie Max-Age Divergence: "
                    f"primary='{p_ma}' vs ref[{ref_index}]='{r_ma}'"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "max_age_divergence",
                    "primary_max_age": p_ma,
                    "ref_max_age": r_ma,
                    "ref_index": ref_index,
                },
            )

        # Expires divergence (normalized comparison)
        p_exp = (p.get("expires") or "").strip()
        r_exp = (r.get("expires") or "").strip()
        if p_exp != r_exp and (p_exp or r_exp):
            return Finding(
                title=(
                    f"Cookie Expires Divergence: "
                    f"primary vs ref[{ref_index}] differ"
                ),
                severity=Severity.LOW,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "expires_divergence",
                    "primary_expires": p_exp[:80],
                    "ref_expires": r_exp[:80],
                    "ref_index": ref_index,
                },
            )

        return None


# ── Factory ───────────────────────────────────────────────────────


def get_cookie_strategies() -> list:
    """Return all cookie differential strategies.

    Intended to be composed with DiffOracle's existing strategies.
    """
    return [
        CookieDiffStrategy(),
        CookieDomainScopeStrategy(),
        CookieFlagDivergenceStrategy(),
        CookieExpiryStrategy(),
    ]
