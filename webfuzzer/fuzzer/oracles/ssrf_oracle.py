"""URL confusion differential strategy for URL parser comparison.

Compares URL parser outputs and detects security-relevant parsing
divergences that could enable SSRF, open redirect, cache poisoning,
auth bypass, path traversal, and other confusion attacks.

Unlike generic OutputStrategy which flags any output difference,
UrlConfusionStrategy performs semantic analysis of parsed URL
components to identify exploitable discrepancies across ALL 7
URL components (scheme, userinfo, host, port, path, query, fragment).

Attack vectors detected:
  - SSRF: internal/external host mismatch
  - Open redirect: different external hosts
  - Scheme confusion: protocol confusion (http vs javascript/file/gopher)
  - Authority confusion: userinfo/@/backslash tricks
  - Port confusion: different port interpretation
  - Path traversal: path normalization differences with ..
  - Path confusion: generic path differences (cache poisoning, WAF bypass)
  - Query confusion: query string interpretation differences
  - Fragment confusion: fragment handling differences (DOM XSS)

Architecture mirrors XssBypassStrategy - pluggable DiffStrategy
for composition with DiffOracle.

References:
  - Orange Tsai, "A New Era of SSRF" (BlackHat 2017)
  - Orange Tsai, "Confusion Attacks" (BlackHat 2024)
  - CVE-2025-0938: Python urllib bracket confusion
  - CVE-2025-0454: AutoGPT SSRF via colon-@ trick
  - CVE-2024-22262: Spring UriComponentsBuilder SSRF
  - WHATWG URL Standard vs RFC 3986 backslash differential
  - URL Confusion Mutation Taxonomy (S1-S9)
"""

from __future__ import annotations

import ipaddress
import json
import re
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

from ..protocols import ExecutionResult, Finding, Input, Severity


# -- Internal IP / host detection ------------------------------------------

# Hostnames considered internal
_INTERNAL_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
})

_INTERNAL_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".home.arpa",
    ".intranet",
    ".corp",
    ".lan",
)

# Cloud metadata endpoints (S3-2, S9)
_CLOUD_METADATA_IPS = frozenset({
    "169.254.169.254",  # AWS, GCP, Azure
    "100.100.100.200",  # Alibaba Cloud
    "169.254.170.2",    # AWS ECS task metadata
})

_CLOUD_METADATA_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.google.com",
})

# Hex/octal/decimal IP patterns for localhost detection (S3-1)
_LOCALHOST_ALTERNATES = frozenset({
    "0x7f000001",
    "0x7f.0x0.0x0.0x1",
    "017700000001",
    "0177.0.0.01",
    "0177.0.0.1",
    "2130706433",
    "127.1",
    "127.0.1",
    "0",
    "0.0.0.0",
})


@lru_cache(maxsize=64)
def _is_internal_host(host: str) -> bool:
    """Check if a hostname/IP resolves to an internal/private address.

    Covers RFC 1918, RFC 4193, loopback, link-local, cloud metadata,
    and common alternative representations (S3-1, S3-2).

    Cached (LRU, 64 entries) — same host strings are checked repeatedly
    across multiple strategies and reference results.
    """
    if not host:
        return False

    host_lower = host.lower().strip().rstrip(".")

    # Direct hostname matches
    if host_lower in _INTERNAL_HOSTNAMES:
        return True

    if host_lower in _CLOUD_METADATA_HOSTS:
        return True

    # Suffix matches
    if any(host_lower.endswith(suffix) for suffix in _INTERNAL_SUFFIXES):
        return True

    # Alternative localhost representations (S3-1)
    if host_lower in _LOCALHOST_ALTERNATES:
        return True

    # Cloud metadata IPs
    if host_lower in _CLOUD_METADATA_IPS:
        return True

    # Try parsing as IP address
    try:
        # Strip brackets for IPv6
        ip_str = host_lower
        if ip_str.startswith("[") and ip_str.endswith("]"):
            ip_str = ip_str[1:-1]
        # Strip zone ID
        if "%" in ip_str:
            ip_str = ip_str.split("%")[0]
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_loopback
            or addr.is_private
            or addr.is_reserved
            or addr.is_link_local
            or addr.is_multicast
        )
    except (ValueError, ipaddress.AddressValueError):
        pass

    # Hex IP (0x7f000001 etc.)
    if host_lower.startswith("0x"):
        try:
            num = int(host_lower, 16)
            if 0 <= num <= 0xFFFFFFFF:
                addr = ipaddress.ip_address(num)
                return addr.is_loopback or addr.is_private or addr.is_reserved
        except (ValueError, OverflowError):
            pass

    # Pure decimal IP (2130706433 etc.)
    if host_lower.isdigit():
        try:
            num = int(host_lower)
            if 0 <= num <= 0xFFFFFFFF:
                addr = ipaddress.ip_address(num)
                return addr.is_loopback or addr.is_private or addr.is_reserved
        except (ValueError, OverflowError):
            pass

    # Octal IP (0177.0.0.01 etc.)
    if re.match(r"^0\d", host_lower):
        try:
            parts = host_lower.split(".")
            decimal_parts = [str(int(p, 8)) for p in parts]
            decimal_ip = ".".join(decimal_parts)
            addr = ipaddress.ip_address(decimal_ip)
            return addr.is_loopback or addr.is_private or addr.is_reserved
        except (ValueError, ipaddress.AddressValueError):
            pass

    return False


@lru_cache(maxsize=16)
def _parse_url_output(stdout: bytes) -> dict[str, str] | None:
    """Parse JSON output from a URL parser target.

    Returns dict with keys: scheme, userinfo, host, port, path, query, fragment.
    Returns None if output is not valid JSON or missing expected keys.

    Cached (LRU, 16 entries) because the same stdout bytes are parsed
    repeatedly by multiple strategies within a single _collect_all() call.
    With 4 refs × 4 strategies, this reduces ~32 JSON parses to ~5.
    """
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "host" in data:
            return {k: str(v) for k, v in data.items()}
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


# -- Dangerous scheme detection (S1-2) -------------------------------------

_DANGEROUS_SCHEMES = frozenset({
    "file", "gopher", "dict", "jar", "netdoc",
    "ldap", "ldaps", "tftp", "glob",
})

_XSS_SCHEMES = frozenset({
    "javascript", "vbscript", "data",
})


# -- Path analysis helpers -------------------------------------------------

# Patterns that indicate path traversal attempts in raw input
_TRAVERSAL_RE = re.compile(
    rb"(?:"
    rb"\.\."           # literal ..
    rb"|%2e%2e"        # percent-encoded ..
    rb"|%252e%252e"    # double-encoded ..
    rb"|%2e\."         # mixed encoding
    rb"|\.%2e"         # mixed encoding
    rb"|%c0%ae"        # overlong UTF-8 encoding of .
    rb"|%c0%2e"        # overlong variant
    rb"|%e0%80%ae"     # 3-byte overlong UTF-8 encoding of .
    rb")",
    re.IGNORECASE,
)

# Backslash in URL - WHATWG treats as path separator, RFC 3986 doesn't
_BACKSLASH_RE = re.compile(rb"\\")


def _has_traversal_indicators(raw_input: bytes) -> bool:
    """Check if raw input contains path traversal patterns."""
    return bool(_TRAVERSAL_RE.search(raw_input))


def _has_backslash(raw_input: bytes) -> bool:
    """Check if raw input contains backslash characters."""
    return bool(_BACKSLASH_RE.search(raw_input))


def _is_traversal_path_diff(p_path: str, r_path: str) -> bool:
    """Check if path difference involves traversal normalization.

    Returns True when one parser resolved .. segments and the other didn't,
    or when paths differ in ways that suggest directory traversal.
    """
    # One path has .. and the other doesn't
    if (".." in p_path) != (".." in r_path):
        return True

    # Try percent-decoding and check again
    try:
        p_decoded = unquote(p_path)
        r_decoded = unquote(r_path)
        if (".." in p_decoded) != (".." in r_decoded):
            return True
    except Exception:
        pass

    # One path is shorter (resolved) while the other keeps traversal
    # e.g., "/admin/../secret" vs "/secret"
    p_segments = [s for s in p_path.split("/") if s]
    r_segments = [s for s in r_path.split("/") if s]
    if abs(len(p_segments) - len(r_segments)) >= 2:
        if ".." in p_path or ".." in r_path:
            return True

    return False


def _is_trivial_path_diff(a: str, b: str) -> bool:
    """Check if path difference is trivial (trailing slash, encoding only)."""
    # Trailing slash difference
    if a.rstrip("/") == b.rstrip("/"):
        return True
    # Case-only difference
    if a.lower() == b.lower():
        return True
    # Percent-encoding normalization difference
    try:
        if unquote(a) == unquote(b):
            return True
    except Exception:
        pass
    return False


def _is_trivial_query_diff(a: str, b: str) -> bool:
    """Check if query string difference is trivial."""
    # Leading ? difference
    a_clean = a.lstrip("?")
    b_clean = b.lstrip("?")
    if a_clean == b_clean:
        return True
    # Encoding normalization
    try:
        if unquote(a_clean) == unquote(b_clean):
            return True
    except Exception:
        pass
    return False


def _is_trivial_fragment_diff(a: str, b: str) -> bool:
    """Check if fragment difference is trivial."""
    # Leading # difference
    a_clean = a.lstrip("#")
    b_clean = b.lstrip("#")
    if a_clean == b_clean:
        return True
    # Encoding normalization
    try:
        if unquote(a_clean) == unquote(b_clean):
            return True
    except Exception:
        pass
    return False


# -- UrlConfusionStrategy --------------------------------------------------

class UrlConfusionStrategy:
    """Differential strategy: detect URL confusion attack vectors.

    Parses JSON output from URL parser targets and compares all 7
    parsed components to find exploitable discrepancies.

    Reports findings for (priority order):
      1. ssrf_host_confusion (CRITICAL) - internal/external host mismatch
      2. open_redirect (HIGH) - different external hosts
      3. scheme_confusion (HIGH/MEDIUM) - protocol confusion
      4. authority_confusion (HIGH) - userinfo mismatch
      5. path_traversal (HIGH) - path normalization with .. patterns
      6. port_confusion (MEDIUM) - port mismatch
      7. path_confusion (MEDIUM) - generic path differences
      8. query_confusion (MEDIUM) - query string differences
      9. fragment_confusion (MEDIUM/LOW) - fragment differences

    Taxonomy references: S1 (Scheme), S2 (Authority), S3 (Host),
    S4 (Port), S5 (Path), S6 (Query), S7 (Fragment),
    S8 (Encoding Differentials).
    """

    name = "url_confusion"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        # Need at least one successful parse to compare
        if primary.exit_code != 0 and reference.exit_code != 0:
            return None

        primary_parsed = _parse_url_output(primary.stdout)
        ref_parsed = _parse_url_output(reference.stdout)

        # If only one side parsed, check for interesting one-sided cases
        if primary_parsed is None or ref_parsed is None:
            return self._check_one_sided(
                inp, primary, reference, ref_index,
                primary_parsed, ref_parsed,
            )

        # Both parsed - compare all 7 components
        p_scheme = primary_parsed.get("scheme", "").lower().strip()
        r_scheme = ref_parsed.get("scheme", "").lower().strip()
        p_userinfo = primary_parsed.get("userinfo", "").strip()
        r_userinfo = ref_parsed.get("userinfo", "").strip()
        p_host = primary_parsed.get("host", "").lower().strip()
        r_host = ref_parsed.get("host", "").lower().strip()
        p_port = primary_parsed.get("port", "").strip()
        r_port = ref_parsed.get("port", "").strip()
        p_path = primary_parsed.get("path", "").strip()
        r_path = ref_parsed.get("path", "").strip()
        p_query = primary_parsed.get("query", "").strip()
        r_query = ref_parsed.get("query", "").strip()
        p_fragment = primary_parsed.get("fragment", "").strip()
        r_fragment = ref_parsed.get("fragment", "").strip()

        # Compute which fields differ - used for dedup fingerprinting
        diff_fields: list[str] = []
        if p_scheme != r_scheme and (p_scheme or r_scheme):
            diff_fields.append("scheme")
        if p_userinfo != r_userinfo:
            diff_fields.append("userinfo")
        if p_host != r_host and (p_host or r_host):
            diff_fields.append("host")
        if p_port != r_port and (p_port or r_port):
            diff_fields.append("port")
        if p_path != r_path and (p_path or r_path):
            diff_fields.append("path")
        if p_query != r_query and (p_query or r_query):
            diff_fields.append("query")
        if p_fragment != r_fragment and (p_fragment or r_fragment):
            diff_fields.append("fragment")

        # Check for backslash in raw input (enriches metadata)
        raw_input = inp.data
        has_backslash = _has_backslash(raw_input)
        has_traversal = _has_traversal_indicators(raw_input)

        # -- S3 + S2-1: Host confusion (most critical) --
        if p_host and r_host and p_host != r_host:
            p_internal = _is_internal_host(p_host)
            r_internal = _is_internal_host(r_host)

            # CRITICAL: one sees internal, other sees external
            if p_internal != r_internal:
                internal_side = "primary" if p_internal else "reference"
                external_side = "reference" if p_internal else "primary"
                return self._make_finding(
                    inp=inp,
                    result=primary,
                    ref_index=ref_index,
                    category="ssrf_host_confusion",
                    severity=Severity.CRITICAL,
                    title=(
                        f"SSRF: {internal_side} resolves to internal "
                        f"({p_host if p_internal else r_host}) but "
                        f"{external_side} sees external "
                        f"({r_host if p_internal else p_host}) "
                        f"(ref[{ref_index}])"
                    ),
                    details={
                        "primary_host": p_host,
                        "ref_host": r_host,
                        "primary_internal": p_internal,
                        "ref_internal": r_internal,
                        "has_backslash": has_backslash,
                    },
                    primary_parsed=primary_parsed,
                    ref_parsed=ref_parsed,
                    diff_fields=diff_fields,
                )

            # HIGH: different external hosts - open redirect / CORS bypass
            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                category="open_redirect",
                severity=Severity.HIGH,
                title=(
                    f"Open redirect: parsers disagree on host "
                    f"(primary={p_host} vs ref[{ref_index}]={r_host})"
                ),
                details={
                    "primary_host": p_host,
                    "ref_host": r_host,
                    "attack_vectors": [
                        "open_redirect",
                        "cors_bypass",
                        "oauth_redirect_uri_bypass",
                    ],
                    "has_backslash": has_backslash,
                },
                primary_parsed=primary_parsed,
                ref_parsed=ref_parsed,
                diff_fields=diff_fields,
            )

        # -- S1: Scheme confusion --
        if p_scheme and r_scheme and p_scheme != r_scheme:
            p_dangerous = p_scheme in _DANGEROUS_SCHEMES | _XSS_SCHEMES
            r_dangerous = r_scheme in _DANGEROUS_SCHEMES | _XSS_SCHEMES
            if p_dangerous != r_dangerous:
                severity = Severity.HIGH
            elif p_scheme in _DANGEROUS_SCHEMES or r_scheme in _DANGEROUS_SCHEMES:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            attack_vectors = []
            if p_scheme in _DANGEROUS_SCHEMES or r_scheme in _DANGEROUS_SCHEMES:
                attack_vectors.append("ssrf_via_scheme")
            if p_scheme in _XSS_SCHEMES or r_scheme in _XSS_SCHEMES:
                attack_vectors.append("xss_via_scheme")
            if not attack_vectors:
                attack_vectors.append("protocol_confusion")

            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                category="scheme_confusion",
                severity=severity,
                title=(
                    f"Scheme confusion: primary={p_scheme} vs "
                    f"ref[{ref_index}]={r_scheme}"
                ),
                details={
                    "primary_scheme": p_scheme,
                    "ref_scheme": r_scheme,
                    "attack_vectors": attack_vectors,
                },
                primary_parsed=primary_parsed,
                ref_parsed=ref_parsed,
                diff_fields=diff_fields,
            )

        # -- S2-1: Userinfo/authority confusion --
        if p_userinfo != r_userinfo:
            if bool(p_userinfo) != bool(r_userinfo):
                return self._make_finding(
                    inp=inp,
                    result=primary,
                    ref_index=ref_index,
                    category="authority_confusion",
                    severity=Severity.HIGH,
                    title=(
                        f"Authority confusion: userinfo mismatch "
                        f"({p_userinfo!r} vs {r_userinfo!r}) "
                        f"(ref[{ref_index}])"
                    ),
                    details={
                        "primary_userinfo": p_userinfo,
                        "ref_userinfo": r_userinfo,
                        "primary_host": p_host,
                        "ref_host": r_host,
                        "attack_vectors": [
                            "credential_confusion",
                            "auth_bypass",
                        ],
                        "has_backslash": has_backslash,
                    },
                    primary_parsed=primary_parsed,
                    ref_parsed=ref_parsed,
                    diff_fields=diff_fields,
                )

        # -- S5: Path traversal (HIGH - subset of path confusion) --
        if p_path != r_path and (p_path or r_path):
            if not _is_trivial_path_diff(p_path, r_path):
                if has_traversal or _is_traversal_path_diff(p_path, r_path):
                    return self._make_finding(
                        inp=inp,
                        result=primary,
                        ref_index=ref_index,
                        category="path_traversal",
                        severity=Severity.HIGH,
                        title=(
                            f"Path traversal: parsers disagree on .. "
                            f"normalization "
                            f"(primary={p_path[:60]} vs "
                            f"ref[{ref_index}]={r_path[:60]})"
                        ),
                        details={
                            "primary_path": p_path,
                            "ref_path": r_path,
                            "attack_vectors": [
                                "directory_traversal",
                                "acl_bypass",
                                "path_normalization_bypass",
                            ],
                            "has_backslash": has_backslash,
                        },
                        primary_parsed=primary_parsed,
                        ref_parsed=ref_parsed,
                        diff_fields=diff_fields,
                    )

        # -- S4: Port confusion --
        if p_port != r_port and (p_port or r_port):
            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                category="port_confusion",
                severity=Severity.MEDIUM,
                title=(
                    f"Port confusion: primary={p_port or 'default'} vs "
                    f"ref[{ref_index}]={r_port or 'default'}"
                ),
                details={
                    "primary_port": p_port,
                    "ref_port": r_port,
                    "attack_vectors": ["port_based_access_control_bypass"],
                },
                primary_parsed=primary_parsed,
                ref_parsed=ref_parsed,
                diff_fields=diff_fields,
            )

        # -- S5: Generic path confusion (MEDIUM) --
        if p_path != r_path and p_path and r_path:
            if not _is_trivial_path_diff(p_path, r_path):
                attack_vectors = ["cache_poisoning", "waf_bypass"]
                if has_backslash:
                    attack_vectors.append("backslash_path_confusion")

                return self._make_finding(
                    inp=inp,
                    result=primary,
                    ref_index=ref_index,
                    category="path_confusion",
                    severity=Severity.MEDIUM,
                    title=(
                        f"Path confusion: primary={p_path[:60]} vs "
                        f"ref[{ref_index}]={r_path[:60]}"
                    ),
                    details={
                        "primary_path": p_path,
                        "ref_path": r_path,
                        "attack_vectors": attack_vectors,
                        "has_backslash": has_backslash,
                    },
                    primary_parsed=primary_parsed,
                    ref_parsed=ref_parsed,
                    diff_fields=diff_fields,
                )

        # -- S6: Query confusion --
        if p_query != r_query and (p_query or r_query):
            if not _is_trivial_query_diff(p_query, r_query):
                return self._make_finding(
                    inp=inp,
                    result=primary,
                    ref_index=ref_index,
                    category="query_confusion",
                    severity=Severity.MEDIUM,
                    title=(
                        f"Query confusion: primary={p_query[:60]!r} vs "
                        f"ref[{ref_index}]={r_query[:60]!r}"
                    ),
                    details={
                        "primary_query": p_query,
                        "ref_query": r_query,
                        "attack_vectors": [
                            "parameter_injection",
                            "waf_bypass",
                            "cache_key_confusion",
                        ],
                    },
                    primary_parsed=primary_parsed,
                    ref_parsed=ref_parsed,
                    diff_fields=diff_fields,
                )

        # -- S7: Fragment confusion --
        if p_fragment != r_fragment and (p_fragment or r_fragment):
            if not _is_trivial_fragment_diff(p_fragment, r_fragment):
                # Higher severity when one parser sees fragment and other doesn't
                # (can affect server-side routing in some frameworks)
                if bool(p_fragment) != bool(r_fragment):
                    severity = Severity.MEDIUM
                    attack_vectors = [
                        "fragment_injection",
                        "dom_xss",
                        "client_side_routing_bypass",
                    ]
                else:
                    severity = Severity.LOW
                    attack_vectors = ["dom_xss", "fragment_value_confusion"]

                return self._make_finding(
                    inp=inp,
                    result=primary,
                    ref_index=ref_index,
                    category="fragment_confusion",
                    severity=severity,
                    title=(
                        f"Fragment confusion: primary={p_fragment[:40]!r} vs "
                        f"ref[{ref_index}]={r_fragment[:40]!r}"
                    ),
                    details={
                        "primary_fragment": p_fragment,
                        "ref_fragment": r_fragment,
                        "attack_vectors": attack_vectors,
                    },
                    primary_parsed=primary_parsed,
                    ref_parsed=ref_parsed,
                    diff_fields=diff_fields,
                )

        return None

    def _check_one_sided(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
        primary_parsed: dict[str, str] | None,
        ref_parsed: dict[str, str] | None,
    ) -> Finding | None:
        """Check when only one side parsed successfully.

        If the accepting side parsed an internal host or dangerous scheme,
        that's interesting even without comparison.
        """
        parsed = primary_parsed or ref_parsed
        if parsed is None:
            return None

        side = "primary" if primary_parsed else f"ref[{ref_index}]"
        host = parsed.get("host", "").lower().strip()
        scheme = parsed.get("scheme", "").lower().strip()

        # One side accepts URL pointing to internal host
        if host and _is_internal_host(host):
            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                category="ssrf_accept_reject",
                severity=Severity.HIGH,
                title=(
                    f"SSRF: {side} accepts URL to internal host "
                    f"({host}) but other side rejects"
                ),
                details={
                    "accepting_side": side,
                    "host": host,
                    "scheme": scheme,
                },
                primary_parsed=primary_parsed or {},
                ref_parsed=ref_parsed or {},
            )

        # One side accepts dangerous scheme URL
        if scheme in _DANGEROUS_SCHEMES:
            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                category="scheme_accept_reject",
                severity=Severity.HIGH,
                title=(
                    f"Scheme bypass: {side} accepts {scheme}:// URL "
                    f"but other side rejects"
                ),
                details={
                    "accepting_side": side,
                    "scheme": scheme,
                    "host": host,
                },
                primary_parsed=primary_parsed or {},
                ref_parsed=ref_parsed or {},
            )

        # One side accepts XSS scheme URL
        if scheme in _XSS_SCHEMES:
            return self._make_finding(
                inp=inp,
                result=primary,
                ref_index=ref_index,
                category="xss_scheme_accept_reject",
                severity=Severity.HIGH,
                title=(
                    f"XSS scheme bypass: {side} accepts {scheme}: URL "
                    f"but other side rejects"
                ),
                details={
                    "accepting_side": side,
                    "scheme": scheme,
                    "host": host,
                    "attack_vectors": ["xss_via_scheme"],
                },
                primary_parsed=primary_parsed or {},
                ref_parsed=ref_parsed or {},
            )

        return None

    @staticmethod
    def _make_finding(
        *,
        inp: Input,
        result: ExecutionResult,
        ref_index: int,
        category: str,
        severity: Severity,
        title: str,
        details: dict[str, Any],
        primary_parsed: dict[str, str] | dict,
        ref_parsed: dict[str, str] | dict,
        diff_fields: list[str] | None = None,
    ) -> Finding:
        return Finding(
            title=title,
            severity=severity,
            input=inp,
            result=result,
            oracle_name="differential",
            metadata={
                "strategy": "url_confusion",
                "category": category,
                "ref_index": ref_index,
                "primary_parsed": dict(primary_parsed),
                "ref_parsed": dict(ref_parsed),
                **({"diff_fields": diff_fields} if diff_fields else {}),
                **details,
            },
        )


# Backward compatibility alias
SsrfStrategy = UrlConfusionStrategy


# -- Component-specific strategies (run independently of UrlConfusionStrategy) --

class PortConfusionStrategy:
    """Detect port parsing differences regardless of host/scheme differences.

    Runs independently so port confusion is reported even when
    UrlConfusionStrategy returns a higher-priority host finding.
    """

    name = "port_confusion"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        if primary.exit_code != 0 and reference.exit_code != 0:
            return None
        p = _parse_url_output(primary.stdout)
        r = _parse_url_output(reference.stdout)
        if p is None or r is None:
            return None
        p_port = p.get("port", "").strip()
        r_port = r.get("port", "").strip()
        if not p_port and not r_port:
            return None
        if p_port == r_port:
            return None
        return Finding(
            title=(
                f"Port confusion: primary={p_port or 'default'} vs "
                f"ref[{ref_index}]={r_port or 'default'}"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": "port_confusion",
                "category": "port_confusion",
                "ref_index": ref_index,
                "primary_port": p_port,
                "ref_port": r_port,
            },
        )


class QueryConfusionStrategy:
    """Detect query string parsing differences independently."""

    name = "query_confusion"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        if primary.exit_code != 0 and reference.exit_code != 0:
            return None
        p = _parse_url_output(primary.stdout)
        r = _parse_url_output(reference.stdout)
        if p is None or r is None:
            return None
        p_query = p.get("query", "").strip()
        r_query = r.get("query", "").strip()
        if not p_query and not r_query:
            return None
        if p_query == r_query:
            return None
        if _is_trivial_query_diff(p_query, r_query):
            return None
        return Finding(
            title=(
                f"Query confusion: primary={p_query[:60]!r} vs "
                f"ref[{ref_index}]={r_query[:60]!r}"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": "query_confusion",
                "category": "query_confusion",
                "ref_index": ref_index,
                "primary_query": p_query,
                "ref_query": r_query,
            },
        )


class FragmentConfusionStrategy:
    """Detect fragment parsing differences independently."""

    name = "fragment_confusion"

    def compare(
        self, inp: Input, primary: ExecutionResult,
        reference: ExecutionResult, ref_index: int,
    ) -> Finding | None:
        if primary.exit_code != 0 and reference.exit_code != 0:
            return None
        p = _parse_url_output(primary.stdout)
        r = _parse_url_output(reference.stdout)
        if p is None or r is None:
            return None
        p_frag = p.get("fragment", "").strip()
        r_frag = r.get("fragment", "").strip()
        if not p_frag and not r_frag:
            return None
        if p_frag == r_frag:
            return None
        if _is_trivial_fragment_diff(p_frag, r_frag):
            return None
        if bool(p_frag) != bool(r_frag):
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        return Finding(
            title=(
                f"Fragment confusion: primary={p_frag[:40]!r} vs "
                f"ref[{ref_index}]={r_frag[:40]!r}"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": "fragment_confusion",
                "category": "fragment_confusion",
                "ref_index": ref_index,
                "primary_fragment": p_frag,
                "ref_fragment": r_frag,
            },
        )


# -- Standalone SsrfOracle -------------------------------------------------

class SsrfOracle:
    """Standalone SSRF oracle - checks single target output.

    Detects when a URL parser accepts a URL pointing to internal
    hosts or using dangerous schemes. Works without differential
    comparison (single target mode).
    """

    name = "ssrf"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0:
            return None

        parsed = _parse_url_output(result.stdout)
        if parsed is None:
            return None

        host = parsed.get("host", "").lower().strip()
        scheme = parsed.get("scheme", "").lower().strip()

        # Check for internal host acceptance
        if host and _is_internal_host(host):
            return Finding(
                title=f"SSRF: URL resolves to internal host ({host})",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name="ssrf",
                metadata={
                    "host": host,
                    "scheme": scheme,
                    "parsed": dict(parsed),
                },
            )

        # Check for dangerous scheme
        if scheme in _DANGEROUS_SCHEMES:
            return Finding(
                title=f"Dangerous scheme accepted: {scheme}://",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name="ssrf",
                metadata={
                    "scheme": scheme,
                    "host": host,
                    "parsed": dict(parsed),
                },
            )

        return None


# -- Strategy composition --------------------------------------------------

def get_ssrf_strategies():
    """Return default diff strategies + URL confusion strategies.

    Includes main UrlConfusionStrategy (host/scheme/authority priority)
    plus independent component strategies for port/query/fragment that
    fire regardless of host differences.
    """
    from .diff_oracle import DEFAULT_STRATEGIES
    return list(DEFAULT_STRATEGIES) + [
        UrlConfusionStrategy(),
        PortConfusionStrategy(),
        QueryConfusionStrategy(),
        FragmentConfusionStrategy(),
    ]


# Preferred name
get_url_confusion_strategies = get_ssrf_strategies
