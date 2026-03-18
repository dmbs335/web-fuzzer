"""OAuth differential strategies for cross-library comparison.

Detects divergences in redirect_uri validation and scope parsing
across different OAuth/OIDC library implementations.

Strategy architecture:
- OAuthRedirectMatchStrategy: redirect_match divergence (Open Redirect / AuthZ Bypass)
- OAuthRedirectNormStrategy: candidate_normalized divergence (URL parsing differential)
- OAuthRedirectComponentStrategy: individual URL component divergence
- OAuthScopeMatchStrategy: scope_match divergence (Scope Expansion)
- OAuthScopeParsingStrategy: scope_count/empty_elements divergence
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _oauth_uri_mechanism(p_val: str, r_val: str) -> str:
    if not p_val or not r_val:
        return "absent_vs_present"
    if "%" in p_val or "%" in r_val:
        return "encoding"
    if p_val.lower() == r_val.lower():
        return "case_normalization"
    return "value_diff"


def _oauth_accept_mechanism(accepting: str) -> str:
    return "primary_accepts" if "primary" in accepting.lower() else "ref_accepts"


def _oauth_redirect_mechanism(candidate: str, inp_data: bytes) -> str:
    """Classify redirect_uri bypass mechanism from input/candidate structure."""
    raw = inp_data.decode("utf-8", errors="replace")
    c = str(candidate)
    if "\\" in raw:
        return "backslash"
    if "@" in c:
        return "userinfo_confusion"
    if ".." in c or "%2e" in c.lower():
        return "path_traversal"
    if "%" in c:
        return "encoding"
    if c.lower() != raw.lower() and c.lower().split("//")[-1:] != raw.lower().split("//")[-1:]:
        return "subdomain_confusion"
    if "#" in raw or "%23" in raw:
        return "fragment_injection"
    if ":" in c.split("//", 1)[-1].split("/", 1)[0]:
        return "port_confusion"
    return "value_diff"


def _parse_oauth_output(stdout: bytes) -> dict | None:
    """Parse JSON output from an OAuth target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and "input_type" in data:
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


def _input_preview(inp: Input) -> str:
    return inp.data[:300].decode("utf-8", errors="replace")


# ---------- redirect_uri strategies ----------


class OAuthRedirectMatchStrategy:
    """Detect redirect_match divergence: one library accepts, other rejects.

    This is the highest-signal finding — a redirect_uri accepted by one
    implementation but rejected by another may indicate an Open Redirect
    or Authorization Bypass vulnerability.
    """

    name = "oauth_redirect_match"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "redirect_uri" or r.get("input_type") != "redirect_uri":
            return None

        p_match = p.get("redirect_match")
        r_match = r.get("redirect_match")

        if p_match is None or r_match is None:
            return None
        if p_match == r_match:
            return None

        accepting = "primary" if p_match else f"ref[{ref_index}]"
        rejecting = f"ref[{ref_index}]" if p_match else "primary"
        accepting_data = p if p_match else r

        severity = Severity.CRITICAL
        title = (
            f"OAuth redirect_uri match divergence: "
            f"{accepting} accepts, {rejecting} rejects"
        )

        # Higher confidence if the candidate has attack characteristics
        candidate = accepting_data.get("candidate_normalized", "")
        attack_indicators = ["@", "..", "%00", "#", "\\", "javascript:", "data:"]
        has_attack = any(ind in str(candidate) for ind in attack_indicators)

        return Finding(
            title=title,
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "redirect_uri_bypass",
                "ref_index": ref_index,
                "accepting": accepting,
                "candidate": str(candidate)[:200],
                "has_attack_indicator": has_attack,
                "mechanism": _oauth_redirect_mechanism(str(candidate), inp.data),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthRedirectNormStrategy:
    """Detect candidate_normalized divergence: same URI parsed differently.

    Even when both libraries reach the same match/reject decision,
    different normalization reveals URL parsing differentials that
    could be exploited in more complex scenarios.
    """

    name = "oauth_redirect_norm"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "redirect_uri" or r.get("input_type") != "redirect_uri":
            return None

        p_norm = p.get("candidate_normalized")
        r_norm = r.get("candidate_normalized")
        if p_norm is None or r_norm is None:
            return None
        if p_norm == r_norm:
            return None

        return Finding(
            title=(
                f"OAuth redirect_uri normalization divergence: "
                f"primary={p_norm!r:.80} vs ref[{ref_index}]={r_norm!r:.80}"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "redirect_uri_normalization",
                "ref_index": ref_index,
                "primary_normalized": str(p_norm)[:200],
                "ref_normalized": str(r_norm)[:200],
                "mechanism": _oauth_uri_mechanism(p_norm, r_norm),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthRedirectComponentStrategy:
    """Detect individual URL component divergence (host, port, path, scheme).

    Checks whether specific URL components are parsed differently,
    which indicates the underlying URL parser has different behavior.
    """

    name = "oauth_redirect_component"

    _COMPONENT_FIELDS = [
        ("candidate_host", "redirect_host_confusion", Severity.CRITICAL),
        ("candidate_scheme", "redirect_scheme_confusion", Severity.HIGH),
        ("candidate_port", "redirect_port_confusion", Severity.MEDIUM),
        ("candidate_path", "redirect_path_confusion", Severity.HIGH),
    ]

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "redirect_uri" or r.get("input_type") != "redirect_uri":
            return None

        # Check components in priority order, return first divergence
        for field, category, severity in self._COMPONENT_FIELDS:
            p_val = p.get(field)
            r_val = r.get(field)
            if p_val is not None and r_val is not None and p_val != r_val:
                return Finding(
                    title=(
                        f"OAuth {field} divergence: "
                        f"primary={p_val!r} vs ref[{ref_index}]={r_val!r}"
                    ),
                    severity=severity,
                    input=inp,
                    result=primary,
                    oracle_name="differential",
                    metadata={
                        "strategy": self.name,
                        "category": category,
                        "field": field,
                        "ref_index": ref_index,
                        "primary_value": str(p_val)[:200],
                        "ref_value": str(r_val)[:200],
                        "mechanism": "absent_vs_present" if not p_val or not r_val else "value_diff",
                        "input_preview": _input_preview(inp),
                    },
                )

        return None


class OAuthFragmentDivergenceStrategy:
    """Detect fragment handling divergence.

    RFC 6749 §3.1.2 says redirect_uri MUST NOT include fragment component.
    Libraries differ on whether they reject, strip, or ignore fragments.
    """

    name = "oauth_fragment"

    _GATE_BYTES = [b"#"]

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "redirect_uri" or r.get("input_type") != "redirect_uri":
            return None

        p_frag = p.get("fragment_present")
        r_frag = r.get("fragment_present")
        p_match = p.get("redirect_match")
        r_match = r.get("redirect_match")

        # Interesting: one accepts with fragment, other rejects
        if p_frag and r_frag and p_match != r_match:
            return Finding(
                title=(
                    f"OAuth fragment handling divergence: "
                    f"redirect with fragment {'accepted' if p_match else 'rejected'} by primary, "
                    f"{'accepted' if r_match else 'rejected'} by ref[{ref_index}]"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "fragment_handling_divergence",
                    "ref_index": ref_index,
                    "mechanism": "presence" if bool(p_frag) != bool(r_frag) else "value_diff",
                    "input_preview": _input_preview(inp),
                },
            )
        return None


# ---------- scope strategies ----------


class OAuthScopeMatchStrategy:
    """Detect scope_match divergence: one library grants, other denies.

    This indicates a scope expansion vulnerability where different
    implementations disagree on whether a requested scope is covered
    by the granted scopes.
    """

    name = "oauth_scope_match"

    _GATE_BYTES = [b'"scope"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "scope" or r.get("input_type") != "scope":
            return None

        p_match = p.get("scope_match")
        r_match = r.get("scope_match")
        if p_match is None or r_match is None:
            return None
        if p_match == r_match:
            return None

        granting = "primary" if p_match else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"OAuth scope match divergence: "
                f"{granting} grants access, other denies"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "scope_expansion",
                "ref_index": ref_index,
                "primary_granted": p.get("scope_parsed_granted"),
                "ref_granted": r.get("scope_parsed_granted"),
                "mechanism": "scope_expansion",
                "input_preview": _input_preview(inp),
            },
        )


class OAuthScopeParsingStrategy:
    """Detect scope parsing divergence: different count or empty elements.

    Different whitespace handling (single space vs any whitespace)
    produces different parsed scope lists.
    """

    name = "oauth_scope_parsing"

    _GATE_BYTES = [b'"scope"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "scope" or r.get("input_type") != "scope":
            return None

        p_count = p.get("scope_count_granted")
        r_count = r.get("scope_count_granted")
        p_empty = p.get("scope_empty_elements")
        r_empty = r.get("scope_empty_elements")

        if (
            p_count is not None
            and r_count is not None
            and p_count != r_count
        ):
            return Finding(
                title=(
                    f"OAuth scope count divergence: "
                    f"primary={p_count} vs ref[{ref_index}]={r_count}"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "scope_parsing_divergence",
                    "ref_index": ref_index,
                    "primary_count": p_count,
                    "ref_count": r_count,
                    "primary_empty_elements": p_empty,
                    "ref_empty_elements": r_empty,
                    "mechanism": "count_diff",
                    "input_preview": _input_preview(inp),
                },
            )

        if (
            p_empty is not None
            and r_empty is not None
            and p_empty != r_empty
        ):
            return Finding(
                title=(
                    f"OAuth scope empty element divergence: "
                    f"primary={p_empty} vs ref[{ref_index}]={r_empty}"
                ),
                severity=Severity.LOW,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "scope_parsing_divergence",
                    "ref_index": ref_index,
                    "primary_empty": p_empty,
                    "ref_empty": r_empty,
                    "mechanism": "empty_elements",
                    "input_preview": _input_preview(inp),
                },
            )

        return None


class OAuthLoopbackDivergenceStrategy:
    """Detect loopback handling divergence between libraries.

    RFC 8252 allows native apps to use different ports on loopback.
    Libraries differ on which addresses count as loopback and whether
    port-agnostic matching is applied.
    """

    name = "oauth_loopback"

    _GATE_BYTES = [b"127.0.0.1", b"::1", b"localhost"]

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "redirect_uri" or r.get("input_type") != "redirect_uri":
            return None

        p_loop = p.get("loopback_detected")
        r_loop = r.get("loopback_detected")

        if p_loop != r_loop and (p_loop is not None and r_loop is not None):
            return Finding(
                title=(
                    f"OAuth loopback detection divergence: "
                    f"primary={'detected' if p_loop else 'not detected'} vs "
                    f"ref[{ref_index}]={'detected' if r_loop else 'not detected'}"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "loopback_divergence",
                    "ref_index": ref_index,
                    "mechanism": "loopback_detection",
                    "input_preview": _input_preview(inp),
                },
            )

        return None


# ---------- PKCE strategies (RFC 7636) ----------


class OAuthPKCEMatchStrategy:
    """Detect challenge_match divergence: one library accepts PKCE, other rejects.

    This is the highest-signal PKCE finding — if one library validates a
    code_challenge/code_verifier pair as correct while another rejects it,
    it indicates a potential authorization bypass.
    """

    name = "oauth_pkce_match"

    _GATE_BYTES = [b'"pkce"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "pkce" or r.get("input_type") != "pkce":
            return None

        p_match = p.get("challenge_match")
        r_match = r.get("challenge_match")
        if p_match is None or r_match is None:
            return None
        if p_match == r_match:
            return None

        accepting = "primary" if p_match else f"ref[{ref_index}]"
        rejecting = f"ref[{ref_index}]" if p_match else "primary"

        return Finding(
            title=(
                f"OAuth PKCE challenge_match divergence: "
                f"{accepting} accepts, {rejecting} rejects"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "pkce_match_divergence",
                "ref_index": ref_index,
                "accepting": accepting,
                "primary_computed": p.get("challenge_computed"),
                "ref_computed": r.get("challenge_computed"),
                "method": p.get("method"),
                "mechanism": p.get("method", "unknown"),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthPKCEPaddingStrategy:
    """Detect challenge_computed divergence: different base64url padding.

    authlib and oauthlib may differ on whether base64url output includes
    '=' padding. This causes challenge verification to fail across libraries.
    """

    name = "oauth_pkce_padding"

    _GATE_BYTES = [b'"pkce"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "pkce" or r.get("input_type") != "pkce":
            return None

        p_computed = p.get("challenge_computed")
        r_computed = r.get("challenge_computed")
        if p_computed is None or r_computed is None:
            return None
        if p_computed == r_computed:
            return None

        p_pad = p.get("challenge_has_padding", False)
        r_pad = r.get("challenge_has_padding", False)

        return Finding(
            title=(
                f"OAuth PKCE challenge_computed divergence: "
                f"primary={p_computed!r:.60} vs ref[{ref_index}]={r_computed!r:.60}"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "pkce_padding_divergence",
                "ref_index": ref_index,
                "primary_computed": str(p_computed)[:100],
                "ref_computed": str(r_computed)[:100],
                "primary_has_padding": p_pad,
                "ref_has_padding": r_pad,
                "method": p.get("method"),
                "mechanism": p.get("method", "unknown"),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthPKCEVerifierStrategy:
    """Detect verifier_valid divergence: validation strictness differs.

    Libraries may differ on verifier length bounds (43-128) or allowed
    character set ([A-Za-z0-9\\-._~]).
    """

    name = "oauth_pkce_verifier"

    _GATE_BYTES = [b'"pkce"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "pkce" or r.get("input_type") != "pkce":
            return None

        p_valid = p.get("verifier_valid")
        r_valid = r.get("verifier_valid")
        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        accepting = "primary" if p_valid else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"OAuth PKCE verifier_valid divergence: "
                f"{accepting} accepts verifier, other rejects"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "pkce_verifier_divergence",
                "ref_index": ref_index,
                "accepting": accepting,
                "verifier_length": p.get("verifier_length"),
                "mechanism": "format",
                "input_preview": _input_preview(inp),
            },
        )


# ---------- token_request strategies ----------


class OAuthTokenRequestValidityStrategy:
    """Detect overall_valid divergence in token request parameter validation.

    The highest-signal token request finding: one library accepts the
    request parameters while another rejects them entirely.
    """

    name = "oauth_token_request_validity"

    _GATE_BYTES = [b'"token_request"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "token_request" or r.get("input_type") != "token_request":
            return None

        p_valid = p.get("overall_valid")
        r_valid = r.get("overall_valid")
        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        accepting = "primary" if p_valid else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"OAuth token_request validity divergence: "
                f"{accepting} accepts, other rejects"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "token_request_validity_divergence",
                "ref_index": ref_index,
                "accepting": accepting,
                "p_reason": p.get("rejection_reason"),
                "r_reason": r.get("rejection_reason"),
                "mechanism": _oauth_accept_mechanism(accepting),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthGrantTypeStrategy:
    """Detect grant_type_valid or grant_type_normalized divergence.

    Exploits: authlib .lower() normalizes (case-insensitive) vs oauthlib/Node
    exact match (case-sensitive).
    """

    name = "oauth_grant_type"

    _GATE_BYTES = [b'"token_request"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "token_request" or r.get("input_type") != "token_request":
            return None

        p_valid = p.get("grant_type_valid")
        r_valid = r.get("grant_type_valid")
        p_norm = p.get("grant_type_normalized")
        r_norm = r.get("grant_type_normalized")

        if p_valid is None or r_valid is None:
            return None

        # Check valid divergence first, then normalization
        if p_valid != r_valid:
            accepting = "primary" if p_valid else f"ref[{ref_index}]"
            return Finding(
                title=(
                    f"OAuth grant_type confusion: "
                    f"{accepting} accepts '{p_norm or r_norm}'"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "grant_type_confusion",
                    "ref_index": ref_index,
                    "p_normalized": p_norm,
                    "r_normalized": r_norm,
                    "mechanism": "normalization",
                    "input_preview": _input_preview(inp),
                },
            )
        elif p_norm != r_norm and p_norm is not None and r_norm is not None:
            return Finding(
                title=(
                    f"OAuth grant_type normalization divergence: "
                    f"'{p_norm}' vs '{r_norm}'"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "grant_type_confusion",
                    "ref_index": ref_index,
                    "p_normalized": p_norm,
                    "r_normalized": r_norm,
                    "mechanism": "normalization",
                    "input_preview": _input_preview(inp),
                },
            )
        return None


class OAuthCodeFormatStrategy:
    """Detect code_format_valid divergence: authorization code validation strictness.

    Targets: null bytes, Unicode, overlength codes, URL-encoded chars.
    """

    name = "oauth_code_format"

    _GATE_BYTES = [b'"token_request"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "token_request" or r.get("input_type") != "token_request":
            return None

        p_valid = p.get("code_format_valid")
        r_valid = r.get("code_format_valid")
        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        accepting = "primary" if p_valid else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"OAuth code format divergence: "
                f"{accepting} accepts code, other rejects"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "code_format_divergence",
                "ref_index": ref_index,
                "accepting": accepting,
                "p_code_length": p.get("code_length"),
                "r_code_length": r.get("code_length"),
                "mechanism": _oauth_accept_mechanism(accepting),
                "input_preview": _input_preview(inp),
            },
        )


# ---------- token_response strategies ----------


class OAuthTokenTypeStrategy:
    """Detect token_type_valid or token_type_normalized divergence.

    Exploits: case handling (Bearer vs BEARER vs bearer), unknown types,
    whitespace in token_type value.
    """

    name = "oauth_token_type"

    _GATE_BYTES = [b'"token_response"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "token_response" or r.get("input_type") != "token_response":
            return None

        p_valid = p.get("token_type_valid")
        r_valid = r.get("token_type_valid")

        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        accepting = "primary" if p_valid else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"OAuth token_type confusion: "
                f"{accepting} accepts '{p.get('token_type_raw', '')}'"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "token_type_confusion",
                "ref_index": ref_index,
                "accepting": accepting,
                "p_raw": p.get("token_type_raw"),
                "r_raw": r.get("token_type_raw"),
                "mechanism": _oauth_accept_mechanism(accepting),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthExpiresInStrategy:
    """Detect expires_in handling divergence.

    Key difference: authlib int("3600") succeeds, oauthlib rejects string,
    Node parseInt("3600") succeeds. Float, negative, huge values.
    """

    name = "oauth_expires_in"

    _GATE_BYTES = [b'"token_response"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "token_response" or r.get("input_type") != "token_response":
            return None

        p_valid = p.get("expires_in_valid")
        r_valid = r.get("expires_in_valid")

        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        accepting = "primary" if p_valid else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"OAuth expires_in confusion: "
                f"{accepting} accepts ({p.get('expires_in_raw_type')}) "
                f"vs ref[{ref_index}] ({r.get('expires_in_raw_type')})"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "expires_in_confusion",
                "ref_index": ref_index,
                "accepting": accepting,
                "p_raw_type": p.get("expires_in_raw_type"),
                "r_raw_type": r.get("expires_in_raw_type"),
                "p_value": p.get("expires_in_value"),
                "r_value": r.get("expires_in_value"),
                "mechanism": _oauth_accept_mechanism(accepting),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthScopeDowngradeStrategy:
    """Detect scope_subset_of_requested divergence.

    Different libraries may disagree on whether a response scope is a
    valid subset of the requested scope (due to parsing differences).
    """

    name = "oauth_scope_downgrade"

    _GATE_BYTES = [b'"token_response"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "token_response" or r.get("input_type") != "token_response":
            return None

        p_subset = p.get("scope_subset_of_requested")
        r_subset = r.get("scope_subset_of_requested")
        p_changed = p.get("scope_changed")
        r_changed = r.get("scope_changed")

        # Check subset divergence
        if p_subset is not None and r_subset is not None and p_subset != r_subset:
            return Finding(
                title=(
                    f"OAuth scope downgrade divergence: "
                    f"subset={p_subset} vs ref[{ref_index}] subset={r_subset}"
                ),
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "scope_downgrade_divergence",
                    "ref_index": ref_index,
                    "p_returned": p.get("scope_returned"),
                    "r_returned": r.get("scope_returned"),
                    "p_requested": p.get("scope_requested"),
                    "mechanism": "subset",
                    "input_preview": _input_preview(inp),
                },
            )

        # Check scope_changed divergence
        if p_changed is not None and r_changed is not None and p_changed != r_changed:
            return Finding(
                title=(
                    f"OAuth scope change divergence: "
                    f"changed={p_changed} vs ref[{ref_index}] changed={r_changed}"
                ),
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="differential",
                metadata={
                    "strategy": self.name,
                    "category": "scope_downgrade_divergence",
                    "ref_index": ref_index,
                    "p_returned": p.get("scope_returned"),
                    "r_returned": r.get("scope_returned"),
                    "mechanism": "changed",
                    "input_preview": _input_preview(inp),
                },
            )

        return None


class OAuthErrorHandlingStrategy:
    """Detect is_error_response divergence.

    Targets: 200+error body (confused deputy), 400+token body,
    inconsistent error detection.
    """

    name = "oauth_error_handling"

    _GATE_BYTES = [b'"token_response"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None
        if p.get("input_type") != "token_response" or r.get("input_type") != "token_response":
            return None

        p_error = p.get("is_error_response")
        r_error = r.get("is_error_response")

        if p_error is None or r_error is None:
            return None
        if p_error == r_error:
            return None

        error_side = "primary" if p_error else f"ref[{ref_index}]"

        return Finding(
            title=(
                f"OAuth error handling divergence: "
                f"{error_side} sees error, other sees success"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "error_handling_divergence",
                "ref_index": ref_index,
                "error_side": error_side,
                "p_error_code": p.get("error_code"),
                "r_error_code": r.get("error_code"),
                "mechanism": "error_presence" if not p.get("error_code") or not r.get("error_code") else "error_code_diff",
                "input_preview": _input_preview(inp),
            },
        )


# ---------- PKCE downgrade/presence strategies (RFC 7636 §4.2) ----------


class OAuthPKCEDowngradeStrategy:
    """Detect PKCE method downgrade: one lib resolves S256, another plain.

    RFC 7636 §4.2 says default is "plain" when method is "not present", but
    implementations differ on what "not present" means (CVE-2024-23647,
    CVE-2025-4144).
    """

    name = "oauth_pkce_downgrade"

    _GATE_BYTES = [b'"pkce"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_method = p.get("method_resolved", "")
        r_method = r.get("method_resolved", "")
        if not p_method or not r_method:
            return None

        # Normalize for comparison
        p_norm = p_method.strip().lower()
        r_norm = r_method.strip().lower()

        if p_norm == r_norm:
            return None

        # One is S256, other is plain → CRITICAL downgrade
        methods = {p_norm, r_norm}
        if methods == {"s256", "plain"}:
            severity = Severity.CRITICAL
            category = "pkce_downgrade"
        else:
            severity = Severity.HIGH
            category = "pkce_method_divergence"

        return Finding(
            title=(
                f"OAuth PKCE method divergence: primary={p_method}, "
                f"ref[{ref_index}]={r_method}"
            ),
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": category,
                "ref_index": ref_index,
                "p_method": p_method,
                "r_method": r_method,
                "mechanism": "s256_to_plain" if methods == {"s256", "plain"} else "method_diff",
                "input_preview": _input_preview(inp),
            },
        )


class OAuthPKCEPresenceStrategy:
    """Detect PKCE bypass when challenge or verifier key is absent.

    If challenge key is missing from input but a library reports
    challenge_match=True, it may indicate CVE-2025-4144 pattern
    (skipping PKCE check entirely).
    """

    name = "oauth_pkce_presence"

    _GATE_BYTES = [b'"pkce"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        # Check if challenge or verifier was absent in input
        p_ch_absent = p.get("challenge_was_absent", False)
        r_ch_absent = r.get("challenge_was_absent", False)
        p_ver_absent = p.get("verifier_was_absent", False)
        r_ver_absent = r.get("verifier_was_absent", False)

        if not (p_ch_absent or r_ch_absent or p_ver_absent or r_ver_absent):
            return None

        p_match = p.get("challenge_match")
        r_match = r.get("challenge_match")

        if p_match is None or r_match is None:
            return None
        if p_match == r_match:
            return None

        # Divergence on challenge_match when fields are absent → bypass
        absent_field = "challenge" if (p_ch_absent or r_ch_absent) else "verifier"
        return Finding(
            title=(
                f"OAuth PKCE {absent_field} absent but match diverges: "
                f"primary={p_match}, ref[{ref_index}]={r_match}"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "pkce_presence_bypass",
                "ref_index": ref_index,
                "absent_field": absent_field,
                "p_match": p_match,
                "r_match": r_match,
                "mechanism": "challenge_absent" if (p_ch_absent or r_ch_absent) else "verifier_absent",
                "input_preview": _input_preview(inp),
            },
        )


# ---------- Token exchange redirect_uri strategies (RFC 6749 §4.1.3) ----------


class OAuthTokenExchangeMatchStrategy:
    """Detect token_match divergence in token exchange.

    RFC 6749 §4.1.3 requires redirect_uri at token endpoint to match
    the authorization request value. Libraries differ on "identical" —
    byte-level vs normalized comparison.
    """

    name = "oauth_token_exchange_match"

    _GATE_BYTES = [b'"token_exchange"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_match = p.get("token_match")
        r_match = r.get("token_match")

        if p_match is None or r_match is None:
            return None
        if p_match == r_match:
            return None

        accept_side = "primary" if p_match else f"ref[{ref_index}]"
        return Finding(
            title=(
                f"OAuth token exchange redirect_uri bypass: "
                f"{accept_side} accepts mismatched redirect_uri"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "token_exchange_redirect_bypass",
                "ref_index": ref_index,
                "accept_side": accept_side,
                "p_token_match": p_match,
                "r_token_match": r_match,
                "p_auth_norm": p.get("auth_normalized"),
                "p_token_norm": p.get("token_normalized"),
                "mechanism": _oauth_accept_mechanism(accept_side),
                "input_preview": _input_preview(inp),
            },
        )


class OAuthTokenExchangeIdenticalStrategy:
    """Detect uri_identical divergence in token exchange.

    When libraries disagree on whether auth and token redirect_uri
    are "identical", it reveals normalization differences.
    """

    name = "oauth_token_exchange_identical"

    _GATE_BYTES = [b'"token_exchange"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_identical = p.get("uri_identical")
        r_identical = r.get("uri_identical")

        if p_identical is None or r_identical is None:
            return None
        if p_identical == r_identical:
            return None

        return Finding(
            title=(
                f"OAuth token exchange URI identity divergence: "
                f"primary={p_identical}, ref[{ref_index}]={r_identical}"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "token_exchange_identical_divergence",
                "ref_index": ref_index,
                "p_auth_norm": p.get("auth_normalized"),
                "p_token_norm": p.get("token_normalized"),
                "r_auth_norm": r.get("auth_normalized"),
                "r_token_norm": r.get("token_normalized"),
                "mechanism": _oauth_uri_mechanism(p.get("auth_normalized", ""), r.get("auth_normalized", "")),
                "input_preview": _input_preview(inp),
            },
        )


# ---------- DPoP strategies (RFC 9449) ----------


class DPoPProofValidStrategy:
    """Detect proof_valid divergence: one library accepts DPoP proof, other rejects."""

    name = "dpop_proof_valid"

    _GATE_BYTES = [b'"dpop_proof"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_valid = p.get("proof_valid")
        r_valid = r.get("proof_valid")

        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        accept_side = "primary" if p_valid else f"ref[{ref_index}]"
        return Finding(
            title=(
                f"DPoP proof validation bypass: {accept_side} accepts proof"
            ),
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "dpop_proof_bypass",
                "ref_index": ref_index,
                "accept_side": accept_side,
                "p_alg": p.get("header_alg"),
                "r_alg": r.get("header_alg"),
                "p_parse_error": p.get("jwt_parse_error"),
                "r_parse_error": r.get("jwt_parse_error"),
                "mechanism": _oauth_accept_mechanism(accept_side),
                "input_preview": _input_preview(inp),
            },
        )


class DPoPHTUMatchStrategy:
    """Detect htu_matches divergence: URI normalization differences for DPoP."""

    name = "dpop_htu_match"

    _GATE_BYTES = [b'"dpop_proof"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_match = p.get("htu_matches")
        r_match = r.get("htu_matches")

        if p_match is None or r_match is None:
            return None
        if p_match == r_match:
            return None

        return Finding(
            title=(
                f"DPoP htu URI matching divergence: "
                f"primary={p_match}, ref[{ref_index}]={r_match}"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "dpop_htu_divergence",
                "ref_index": ref_index,
                "p_htu_norm": p.get("htu_normalized"),
                "r_htu_norm": r.get("htu_normalized"),
                "mechanism": _oauth_uri_mechanism(p.get("htu_normalized", ""), r.get("htu_normalized", "")),
                "input_preview": _input_preview(inp),
            },
        )


class DPoPATHBindingStrategy:
    """Detect ath_valid divergence: access token hash binding differences."""

    name = "dpop_ath_binding"

    _GATE_BYTES = [b'"dpop_proof"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_valid = p.get("ath_valid")
        r_valid = r.get("ath_valid")

        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        return Finding(
            title=(
                f"DPoP ath binding divergence: "
                f"primary={p_valid}, ref[{ref_index}]={r_valid}"
            ),
            severity=Severity.HIGH,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "dpop_ath_divergence",
                "ref_index": ref_index,
                "p_ath_padding": p.get("ath_has_padding"),
                "r_ath_padding": r.get("ath_has_padding"),
                "mechanism": "padding" if p.get("ath_has_padding") != r.get("ath_has_padding") else "value_diff",
                "input_preview": _input_preview(inp),
            },
        )


class DPoPHTMMatchStrategy:
    """Detect htm_matches divergence: HTTP method case sensitivity differences."""

    name = "dpop_htm_match"

    _GATE_BYTES = [b'"dpop_proof"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_match = p.get("htm_matches")
        r_match = r.get("htm_matches")

        if p_match is None or r_match is None:
            return None
        if p_match == r_match:
            return None

        return Finding(
            title=(
                f"DPoP htm method matching divergence: "
                f"primary={p_match}, ref[{ref_index}]={r_match}"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "dpop_htm_divergence",
                "ref_index": ref_index,
                "p_htm": p.get("htm_value"),
                "r_htm": r.get("htm_value"),
                "mechanism": "value_diff",
                "input_preview": _input_preview(inp),
            },
        )


class DPoPNonceStrategy:
    """Detect nonce_valid divergence: server nonce handling differences."""

    name = "dpop_nonce"

    _GATE_BYTES = [b'"dpop_proof"']

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        if not any(g in inp.data for g in self._GATE_BYTES):
            return None

        p = _parse_oauth_output(primary.stdout)
        r = _parse_oauth_output(reference.stdout)
        if p is None or r is None:
            return None

        p_valid = p.get("nonce_valid")
        r_valid = r.get("nonce_valid")

        if p_valid is None or r_valid is None:
            return None
        if p_valid == r_valid:
            return None

        return Finding(
            title=(
                f"DPoP nonce validation divergence: "
                f"primary={p_valid}, ref[{ref_index}]={r_valid}"
            ),
            severity=Severity.MEDIUM,
            input=inp,
            result=primary,
            oracle_name="differential",
            metadata={
                "strategy": self.name,
                "category": "dpop_nonce_divergence",
                "ref_index": ref_index,
                "p_nonce": p.get("nonce_value"),
                "r_nonce": r.get("nonce_value"),
                "mechanism": "value_diff",
                "input_preview": _input_preview(inp),
            },
        )


def get_oauth_strategies() -> list:
    """Return OAuth-focused differential strategies plus default non-output checks.

    Architecture:
    - OAuthRedirectMatchStrategy: ungated, detects accept/reject divergence
    - OAuthRedirectNormStrategy: ungated, detects normalization difference
    - OAuthRedirectComponentStrategy: ungated, detects component-level parsing
    - OAuthFragmentDivergenceStrategy: input-gated on '#' bytes
    - OAuthScopeMatchStrategy: input-gated on "scope" bytes
    - OAuthScopeParsingStrategy: input-gated on "scope" bytes
    - OAuthLoopbackDivergenceStrategy: input-gated on loopback addresses
    - OAuthPKCEMatchStrategy: input-gated on "pkce", challenge_match divergence
    - OAuthPKCEPaddingStrategy: input-gated on "pkce", challenge_computed divergence
    - OAuthPKCEVerifierStrategy: input-gated on "pkce", verifier_valid divergence
    - OAuthPKCEDowngradeStrategy: input-gated on "pkce", method_resolved divergence
    - OAuthPKCEPresenceStrategy: input-gated on "pkce", absence-based bypass
    - OAuthTokenRequestValidityStrategy: token_request overall_valid divergence
    - OAuthGrantTypeStrategy: grant_type case/normalization divergence
    - OAuthCodeFormatStrategy: code format validation divergence
    - OAuthTokenTypeStrategy: token_type case/valid divergence
    - OAuthExpiresInStrategy: expires_in type coercion divergence
    - OAuthScopeDowngradeStrategy: scope subset/change divergence
    - OAuthErrorHandlingStrategy: error/success detection divergence
    - OAuthTokenExchangeMatchStrategy: token_exchange redirect_uri bypass
    - OAuthTokenExchangeIdenticalStrategy: token_exchange URI identity divergence
    - DPoPProofValidStrategy: dpop_proof overall validation bypass
    - DPoPHTUMatchStrategy: dpop htu URI normalization divergence
    - DPoPATHBindingStrategy: dpop ath hash binding divergence
    - DPoPHTMMatchStrategy: dpop htm method case divergence
    - DPoPNonceStrategy: dpop nonce handling divergence
    """
    from .diff_oracle import DEFAULT_STRATEGIES

    # Exclude noisy default strategies: output (redundant), accept_reject
    # (JSON parse errors from havoc), and timing (not security-relevant).
    _EXCLUDE = {"output", "exit_code", "timing"}
    base = [s for s in DEFAULT_STRATEGIES if getattr(s, "name", "") not in _EXCLUDE]
    return base + [
        OAuthRedirectMatchStrategy(),
        OAuthRedirectNormStrategy(),
        OAuthRedirectComponentStrategy(),
        OAuthFragmentDivergenceStrategy(),
        OAuthScopeMatchStrategy(),
        OAuthScopeParsingStrategy(),
        OAuthLoopbackDivergenceStrategy(),
        OAuthPKCEMatchStrategy(),
        OAuthPKCEPaddingStrategy(),
        OAuthPKCEVerifierStrategy(),
        OAuthPKCEDowngradeStrategy(),
        OAuthPKCEPresenceStrategy(),
        # Token exchange strategies
        OAuthTokenRequestValidityStrategy(),
        OAuthGrantTypeStrategy(),
        OAuthCodeFormatStrategy(),
        OAuthTokenTypeStrategy(),
        OAuthExpiresInStrategy(),
        OAuthScopeDowngradeStrategy(),
        OAuthErrorHandlingStrategy(),
        # Token exchange redirect_uri strategies
        OAuthTokenExchangeMatchStrategy(),
        OAuthTokenExchangeIdenticalStrategy(),
        # DPoP strategies
        DPoPProofValidStrategy(),
        DPoPHTUMatchStrategy(),
        DPoPATHBindingStrategy(),
        DPoPHTMMatchStrategy(),
        DPoPNonceStrategy(),
    ]
