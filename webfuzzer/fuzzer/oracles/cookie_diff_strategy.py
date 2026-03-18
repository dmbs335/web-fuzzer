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


# ── Mechanism classifiers ─────────────────────────────────────────
# Classify the structural pattern of a divergence (the "why"), not
# just the category (the "what").  Used for dedup fingerprinting so
# that different root causes within the same category get separate
# fingerprint slots.  Values are fixed enums — no per-input data.


def _domain_mechanism(p: str, r: str) -> str:
    """Classify why two domain values differ."""
    if not p or not r:
        return "absent_vs_present"
    if '"' in p or '"' in r:
        return "quoted"
    p_dot = p.startswith(".")
    r_dot = r.startswith(".")
    if p_dot != r_dot and p.lstrip(".") == r.lstrip("."):
        return "leading_dot"
    # One is subdomain of the other
    if p.endswith("." + r) or r.endswith("." + p):
        return "subdomain"
    if p.rstrip(".") == r.rstrip("."):
        return "trailing_dot"
    return "unrelated"


def _path_mechanism(p: str, r: str) -> str:
    """Classify why two path values differ."""
    if not p or not r:
        return "absent_vs_present"
    if '"' in p or '"' in r:
        return "quoted"
    if "/.." in p or "/.." in r:
        return "traversal"
    return "value_diff"


def _value_mechanism(p: str, r: str) -> str:
    """Classify why two cookie values differ."""
    if '"' in p or '"' in r:
        # Check if stripping quotes makes them equal
        if p.strip('"') == r.strip('"'):
            return "quoted"
        return "quoted"
    if ";" in p or ";" in r:
        return "absorbed_attr"
    if p and r and (len(p) > 2 * len(r) or len(r) > 2 * len(p)):
        return "length_diff"
    if "%" in p or "%" in r:
        return "encoding"
    return "value_diff"


def _name_mechanism(p: str, r: str) -> str:
    """Classify why two cookie names differ."""
    pl, rl = p.lower(), r.lower()
    if pl.startswith("$version") or rl.startswith("$version"):
        return "version_prefix"
    if (pl.startswith("__host-") or pl.startswith("__secure-") or
            rl.startswith("__host-") or rl.startswith("__secure-")):
        return "prefix_parsing"
    if "," in p or "," in r:
        return "comma_split"
    return "value_diff"


def _flag_mechanism(p_val: bool, r_val: bool) -> str:
    """Classify boolean flag divergence direction."""
    return "true_vs_false" if p_val else "false_vs_true"


def _samesite_mechanism(p: str, r: str) -> str:
    """Classify SameSite divergence."""
    if not p or not r:
        return "absent_vs_present"
    pair = frozenset([p, r])
    if pair <= {"none", "lax"}:
        return "none_vs_lax"
    if pair <= {"none", "strict"}:
        return "none_vs_strict"
    if pair <= {"lax", "strict"}:
        return "lax_vs_strict"
    return "value_diff"


def _expiry_mechanism(p: str, r: str) -> str:
    """Classify expiry value divergence."""
    if not p or not r:
        return "absent_vs_present"
    return "value_diff"


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
    ) -> list[Finding] | None:
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
        # Exclusive: if one side didn't parse, name/value checks can't run.
        if (p is None) != (r is None):
            parsed_side = "primary" if p is not None else f"ref[{ref_index}]"
            parsed = p if p is not None else r
            # Classify rejection reason for better dedup and FP filtering.
            rejecting_result = reference if p is not None else primary
            reject_reason = self._classify_rejection(rejecting_result)
            mechanism = (
                f"{'primary' if p is not None else 'ref'}_accepts_"
                f"{reject_reason}"
            )
            # Downgrade to LOW when rejection is a crash/timeout (not
            # a real semantic disagreement — likely harness artifact).
            severity = Severity.HIGH
            if reject_reason in ("timeout", "crash", "empty_output"):
                severity = Severity.LOW
            return [Finding(
                title=(
                    f"Cookie Accept/Reject: {parsed_side} accepts "
                    f"(name={parsed.get('name')}) but the other rejects"
                ),
                severity=severity,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "accept_reject_divergence",
                    "mechanism": mechanism,
                    "accepting_side": parsed_side,
                    "reject_reason": reject_reason,
                    "ref_index": ref_index,
                    "parsed_name": parsed.get("name"),
                    "input_preview": _input_preview(inp),
                },
            )]

        # Both parsed successfully — collect all divergences
        all_findings: list[Finding] = []

        p_name = (p.get("name") or "").strip()
        r_name = (r.get("name") or "").strip()
        p_value = (p.get("value") or "").strip()
        r_value = (r.get("value") or "").strip()

        # ── CRITICAL: Name confusion ──
        if p_name and r_name and p_name != r_name:
            all_findings.append(Finding(
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
                    "mechanism": _name_mechanism(p_name, r_name),
                    "primary_name": p_name,
                    "ref_name": r_name,
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            ))

        # ── HIGH: Value confusion ──
        if p_name == r_name and p_value != r_value:
            all_findings.append(Finding(
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
                    "mechanism": _value_mechanism(p_value, r_value),
                    "cookie_name": p_name,
                    "primary_value": p_value[:200],
                    "ref_value": r_value[:200],
                    "ref_index": ref_index,
                    "input_preview": _input_preview(inp),
                },
            ))

        return all_findings or None

    @staticmethod
    def _classify_rejection(result: ExecutionResult) -> str:
        """Classify why a target rejected (didn't parse) the input."""
        if result.exit_code < 0:
            return "crash"
        stderr = result.stderr.decode("utf-8", errors="replace").lower()
        if "timeout" in stderr or "timed out" in stderr:
            return "timeout"
        if not result.stdout.strip():
            return "empty_output"
        # Target returned non-JSON or JSON without "name" key = parse failure
        return "parse_failure"


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
    ) -> list[Finding] | None:
        p = _parse_cookie_output(primary.stdout)
        r = _parse_cookie_output(reference.stdout)
        if p is None or r is None:
            return None

        all_findings: list[Finding] = []
        cookie_name = (p.get("name") or "").strip()

        # Domain confusion
        p_domain = (p.get("domain") or "").strip().lower()
        r_domain = (r.get("domain") or "").strip().lower()
        if p_domain != r_domain and (p_domain or r_domain):
            all_findings.append(Finding(
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
                    "mechanism": _domain_mechanism(p_domain, r_domain),
                    "cookie_name": cookie_name,
                    "primary_domain": p_domain,
                    "ref_domain": r_domain,
                    "ref_index": ref_index,
                },
            ))

        # Path confusion
        p_path = (p.get("path") or "").strip()
        r_path = (r.get("path") or "").strip()
        if p_path != r_path and (p_path or r_path):
            all_findings.append(Finding(
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
                    "mechanism": _path_mechanism(p_path, r_path),
                    "cookie_name": cookie_name,
                    "primary_path": p_path,
                    "ref_path": r_path,
                    "ref_index": ref_index,
                },
            ))

        return all_findings or None


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
    ) -> list[Finding] | None:
        p = _parse_cookie_output(primary.stdout)
        r = _parse_cookie_output(reference.stdout)
        if p is None or r is None:
            return None

        all_findings: list[Finding] = []
        cookie_name = (p.get("name") or "").strip()

        # Secure flag divergence
        p_secure = p.get("secure", False)
        r_secure = r.get("secure", False)
        if p_secure != r_secure:
            all_findings.append(Finding(
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
                    "mechanism": _flag_mechanism(p_secure, r_secure),
                    "cookie_name": cookie_name,
                    "primary_secure": p_secure,
                    "ref_secure": r_secure,
                    "ref_index": ref_index,
                },
            ))

        # HttpOnly flag divergence
        p_httponly = p.get("httponly", False)
        r_httponly = r.get("httponly", False)
        if p_httponly != r_httponly:
            all_findings.append(Finding(
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
                    "mechanism": _flag_mechanism(p_httponly, r_httponly),
                    "cookie_name": cookie_name,
                    "primary_httponly": p_httponly,
                    "ref_httponly": r_httponly,
                    "ref_index": ref_index,
                },
            ))

        # SameSite divergence
        p_ss = (p.get("samesite") or "").strip().lower()
        r_ss = (r.get("samesite") or "").strip().lower()
        if p_ss != r_ss and (p_ss or r_ss):
            all_findings.append(Finding(
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
                    "mechanism": _samesite_mechanism(p_ss, r_ss),
                    "cookie_name": cookie_name,
                    "primary_samesite": p_ss,
                    "ref_samesite": r_ss,
                    "ref_index": ref_index,
                },
            ))

        return all_findings or None


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

        cookie_name = (p.get("name") or "").strip()

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
                    "mechanism": _expiry_mechanism(p_ma, r_ma),
                    "cookie_name": cookie_name,
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
                    "mechanism": _expiry_mechanism(p_exp, r_exp),
                    "cookie_name": cookie_name,
                    "primary_expires": p_exp[:80],
                    "ref_expires": r_exp[:80],
                    "ref_index": ref_index,
                },
            )

        return None


# ── Attribute count divergence ────────────────────────────────────


class CookieAttrCountStrategy:
    """Detect divergence in the number of parsed cookie attributes.

    If one parser extracts more non-empty attributes than another,
    it indicates different parsing depths — one may recognize attributes
    the other ignores, leading to different security property enforcement.
    """

    name = "cookie_attr_count"

    _FIELDS = ("name", "value", "domain", "path", "expires", "max_age",
               "secure", "httponly", "samesite")

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

        def _count(d: dict) -> int:
            n = 0
            for f in self._FIELDS:
                v = d.get(f)
                if v is not None and v != "" and v is not False:
                    n += 1
            return n

        p_count = _count(p)
        r_count = _count(r)
        if p_count != r_count and abs(p_count - r_count) >= 2:
            cookie_name = (p.get("name") or "").strip()
            return Finding(
                title=(
                    f"Cookie Attr Count Divergence: "
                    f"primary={p_count} vs ref[{ref_index}]={r_count}"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "attr_count_divergence",
                    "mechanism": "more_primary" if p_count > r_count else "more_ref",
                    "cookie_name": cookie_name,
                    "primary_count": p_count,
                    "ref_count": r_count,
                    "ref_index": ref_index,
                },
            )
        return None


# ── RFC 2109 version divergence ──────────────────────────────────


class CookieVersionStrategy:
    """Detect RFC 2109 $Version interpretation differences.

    Python http.cookies supports the `version` field while most other
    parsers ignore it entirely.  When one parser enters RFC 2109 mode
    and another stays in RFC 6265 mode, parsing behavior diverges
    significantly (quoted values, comma separators, octal escapes).
    """

    name = "cookie_version"

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

        cookie_name = (p.get("name") or "").strip()
        p_ver = (p.get("version") or "").strip()
        r_ver = (r.get("version") or "").strip()
        if p_ver != r_ver and (p_ver or r_ver):
            return Finding(
                title=(
                    f"Cookie Version Divergence: "
                    f"primary='{p_ver}' vs ref[{ref_index}]='{r_ver}'"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "version_divergence",
                    "mechanism": "absent_vs_present" if not p_ver or not r_ver else "version_value_diff",
                    "cookie_name": cookie_name,
                    "primary_version": p_ver,
                    "ref_version": r_ver,
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
        CookieAttrCountStrategy(),
        CookieVersionStrategy(),
    ]
