"""WAF bypass differential strategies."""

from __future__ import annotations

import hashlib

from ..protocols import ExecutionResult, Finding, Input, Severity


def _extract_header(data: bytes, header: bytes) -> str:
    """Extract a single HTTP header value from raw request bytes.

    Returns the first matching header value (stripped), or empty string.
    Stops at the header/body boundary (blank line).
    """
    prefix = header.lower() + b":"
    for line in data.split(b"\r\n"):
        if not line:
            break  # end of headers
        if line.lower().startswith(prefix):
            val = line[len(prefix):].strip()
            # Guard against newline-injected header values
            return val.split(b"\n")[0].decode("ascii", errors="replace").strip()
    return ""


_RESPONSE_KEYS = (
    "response_status",
    "waf_blocked",
    "waf_block_reason",
    "waf_score",
    "backend_reached",
    "backend_status",
)

_REFLECTION_KEYS = (
    "payload_reflected",
    "canary_in_body",
    "canary_in_headers",
)

_ENCODING_KEYS = (
    "content_type_sent",
    "content_type_parsed",
    "encoding_applied",
    "encoding_depth",
    "charset_sent",
    "charset_detected",
    "charset_declared",
)

_MULTIPART_KEYS = (
    "boundary_used",
    "boundary_parsed",
    "part_count",
    "nested_multipart",
)

_TECHNIQUE_KEYS = (
    "payload_type",
    "technique_family",
    "mutation_lane",
    "encoding_chain",
)


# ── Helper functions ────────────────────────────────────────────


def _parse_result(result: ExecutionResult) -> dict | None:
    data = result.parsed_json()
    if not isinstance(data, dict):
        return None
    if "response_status" not in data and "waf_blocked" not in data:
        return None
    return data


def _is_error_or_timeout(data: dict | None) -> bool:
    """Return True when the result represents a timeout or parse error."""
    if not data:
        return False
    return bool(data.get("timeout")) or bool(data.get("parse_error"))


# Families whose payloads sit in multipart preamble/epilogue —
# regions that real backends discard per RFC 2046 §5.1.1.
_PREAMBLE_FAMILIES = frozenset({"mp_preamble_payload", "mp_epilogue_payload"})


def _is_preamble_family(data: dict | None, inp: Input) -> bool:
    """Return True when the technique places payloads in multipart
    preamble/epilogue which real backends ignore per RFC 2046."""
    family = None
    if data:
        family = data.get("technique_family")
    # Fall back to input metadata if data has no meaningful family.
    if not family or family == "unknown":
        family = inp.metadata.get("technique_family", "")
    if not family:
        return False
    # Strip newline artifacts from header-injection mutations.
    return str(family).split("\n")[0].strip() in _PREAMBLE_FAMILIES


def _has_no_behavioral_divergence(p: dict | None, r: dict | None) -> bool:
    """Return True when primary and reference show identical behavioral
    outcome (status, blocking, reflection), meaning the WAF did not
    change the observable result.

    NOTE: This helper is intentionally NOT used in strategy compare()
    methods.  In WAF bypass fuzzing, identical primary/reference
    behavior IS the finding — it means the WAF was transparent to the
    attack.  Each strategy has its own per-field checks that are
    sufficient.  Kept only for external callers (tests, analysis).
    """
    if p is None or r is None:
        return False
    return (
        p.get("response_status") == r.get("response_status")
        and bool(p.get("waf_blocked")) == bool(r.get("waf_blocked"))
        and bool(p.get("payload_reflected")) == bool(r.get("payload_reflected"))
        and bool(p.get("canary_in_body")) == bool(r.get("canary_in_body"))
    )


def _is_waf_block(data: dict | None) -> bool:
    """Return True when the WAF actively blocked the request."""
    if not data:
        return False
    if data.get("waf_blocked") is True:
        return True
    status = data.get("response_status")
    if isinstance(status, int) and status in {403, 406, 418, 429, 493}:
        return True
    return False


def _is_payload_reflected(data: dict | None) -> bool:
    """Return True when the payload or canary appeared in the response body."""
    if not data:
        return False
    return bool(data.get("payload_reflected")) or bool(data.get("canary_in_body"))


def _waf_interpretation(data: dict | None) -> str:
    """Classify WAF behavior into a coarse category."""
    if not data:
        return "no_output"
    if data.get("parse_error") or data.get("timeout"):
        return "error"
    if _is_waf_block(data):
        return "blocked"
    if _is_payload_reflected(data):
        return "passed"
    if data.get("backend_reached"):
        return "partial"
    return "unknown"


def _difference_fields(primary: dict | None, reference: dict | None) -> list[str]:
    keys = (
        *_RESPONSE_KEYS,
        *_REFLECTION_KEYS,
        *_ENCODING_KEYS,
        *_MULTIPART_KEYS,
        *_TECHNIQUE_KEYS,
    )
    diff: list[str] = []
    p = primary or {}
    r = reference or {}
    for key in keys:
        if p.get(key) != r.get(key):
            diff.append(key)
    return sorted(diff)


def _diff_pattern_hash(
    *,
    bypass_type: str,
    payload_type: str,
    technique_family: str,
    waf_response: str,
    backend_response: str,
    ref_index: int,
    diff_fields: list[str],
) -> str:
    # bypass_type (strategy) is intentionally excluded — the behavioral
    # hash should be the same regardless of which strategy fires.  This
    # prevents the 3-5x finding inflation where the same input produces
    # separate findings for waf_bypass_full, waf_bypass_content_type, etc.
    material = {
        "payload_type": payload_type,
        "technique_family": technique_family,
        "waf_response": waf_response,
        "backend_response": backend_response,
        "ref_index": ref_index,
        "diff_fields": tuple(sorted(diff_fields)),
    }
    return hashlib.sha1(repr(material).encode("utf-8", errors="replace")).hexdigest()[:20]


def _summary_label(data: dict | None) -> str:
    if not data:
        return "no-output"
    waf = _waf_interpretation(data)
    status_part = f" status={data.get('response_status')}"
    backend_part = f" backend={data.get('backend_status')}"
    reflected_part = f" reflected={_is_payload_reflected(data)}"
    return f"{waf}{status_part}{backend_part}{reflected_part}"


def _make_finding(
    *,
    title: str,
    severity: Severity,
    category: str,
    mechanism: str,
    inp: Input,
    primary_result: ExecutionResult,
    primary_data: dict | None,
    reference_data: dict | None,
    ref_index: int,
) -> Finding:
    p = primary_data or {}
    r = reference_data or {}
    diff_fields = _difference_fields(primary_data, reference_data)

    payload_type = str(
        p.get("payload_type") or r.get("payload_type")
        or inp.metadata.get("payload_type")
        or _extract_header(inp.data, b"X-WF-Payload-Type")
        or "unknown"
    )
    technique_family = str(
        p.get("technique_family") or r.get("technique_family")
        or inp.metadata.get("technique_family")
        or _extract_header(inp.data, b"X-WF-Family")
        or "unknown"
    )

    diff_hash = _diff_pattern_hash(
        bypass_type=category,
        payload_type=payload_type,
        technique_family=technique_family,
        waf_response=_waf_interpretation(primary_data),
        backend_response=_waf_interpretation(reference_data),
        ref_index=ref_index,
        diff_fields=diff_fields,
    )

    return Finding(
        title=title,
        severity=severity,
        input=inp,
        result=primary_result,
        oracle_name="differential",
        metadata={
            "strategy": category,
            "category": category,
            "mechanism": mechanism,
            "payload_type": payload_type,
            "technique_family": technique_family,
            "mutation_lane": str(
                p.get("mutation_lane") or r.get("mutation_lane")
                or inp.metadata.get("mutation_lane") or ""
            ),
            "encoding_chain": str(
                p.get("encoding_chain") or r.get("encoding_chain")
                or inp.metadata.get("encoding_chain") or ""
            ),
            "primary_interpretation": _waf_interpretation(primary_data),
            "ref_interpretation": _waf_interpretation(reference_data),
            "primary_response": {
                "status": p.get("response_status"),
                "waf_blocked": p.get("waf_blocked"),
                "waf_block_reason": p.get("waf_block_reason"),
                "waf_score": p.get("waf_score"),
                "backend_reached": p.get("backend_reached"),
                "backend_status": p.get("backend_status"),
            },
            "ref_response": {
                "status": r.get("response_status"),
                "waf_blocked": r.get("waf_blocked"),
                "waf_block_reason": r.get("waf_block_reason"),
                "waf_score": r.get("waf_score"),
                "backend_reached": r.get("backend_reached"),
                "backend_status": r.get("backend_status"),
            },
            "primary_reflection": {
                "payload_reflected": p.get("payload_reflected"),
                "canary_in_body": p.get("canary_in_body"),
                "canary_in_headers": p.get("canary_in_headers"),
            },
            "ref_reflection": {
                "payload_reflected": r.get("payload_reflected"),
                "canary_in_body": r.get("canary_in_body"),
                "canary_in_headers": r.get("canary_in_headers"),
            },
            "primary_encoding": {
                "content_type_sent": p.get("content_type_sent"),
                "content_type_parsed": p.get("content_type_parsed"),
                "encoding_applied": p.get("encoding_applied"),
                "encoding_depth": p.get("encoding_depth"),
                "charset_sent": p.get("charset_sent"),
                "charset_detected": p.get("charset_detected"),
            },
            "ref_encoding": {
                "content_type_sent": r.get("content_type_sent"),
                "content_type_parsed": r.get("content_type_parsed"),
                "encoding_applied": r.get("encoding_applied"),
                "encoding_depth": r.get("encoding_depth"),
                "charset_sent": r.get("charset_sent"),
                "charset_detected": r.get("charset_detected"),
            },
            "primary_multipart": {
                "boundary_used": p.get("boundary_used"),
                "boundary_parsed": p.get("boundary_parsed"),
                "part_count": p.get("part_count"),
                "nested_multipart": p.get("nested_multipart"),
            },
            "ref_multipart": {
                "boundary_used": r.get("boundary_used"),
                "boundary_parsed": r.get("boundary_parsed"),
                "part_count": r.get("part_count"),
                "nested_multipart": r.get("nested_multipart"),
            },
            "diff_pattern_hash": diff_hash,
            "diff_fields": diff_fields,
            "difference_fields": diff_fields,
            "explanation": (
                f"primary={_summary_label(primary_data)} | "
                f"ref={_summary_label(reference_data)} | "
                f"diff={','.join(diff_fields) if diff_fields else 'none'}"
            ),
            "ref_index": ref_index,
        },
    )


# ── Strategy classes ────────────────────────────────────────────


class WafBypassStrategy:
    """Confirmed full WAF bypass: WAF passed AND payload reflected.

    The WAF failed to block, the payload reached the backend and was
    reflected in the response.  The reference (direct backend) also
    reflects, confirming the payload is genuinely processed.
    """

    name = "waf_bypass_full"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        if _is_waf_block(p):
            return None
        # Full bypass requires the actual attack payload reflected, not
        # merely the canary.  canary_in_body alone (without
        # payload_reflected) is a partial bypass — the request reached
        # the backend but the payload was sanitized.
        if not p.get("payload_reflected"):
            return None
        # Require the reference WAF to have blocked the same payload.
        # Without this, a benign request that all targets pass generates
        # a spurious finding with no differential signal.
        if not _is_waf_block(r):
            return None
        # Downgrade severity if backend rejected the request (4xx)
        status = p.get("response_status")
        severity = Severity.CRITICAL
        if isinstance(status, int) and 400 <= status < 500:
            severity = Severity.HIGH
        return _make_finding(
            title=f"WAF bypass confirmed: payload reflected through WAF (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_full",
            mechanism="full_bypass",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class WafPartialBypassStrategy:
    """Partial WAF bypass: WAF passed, canary reached body but payload
    was sanitized (canary_in_body=True, payload_reflected=False).
    """

    name = "waf_bypass_partial"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        if _is_waf_block(p):
            return None
        if not p.get("canary_in_body"):
            return None
        if p.get("payload_reflected"):
            return None  # Full bypass — handled by WafBypassStrategy
        if not _is_waf_block(r):
            return None
        # Downgrade severity if backend rejected the request (4xx)
        status = p.get("response_status")
        severity = Severity.HIGH
        if isinstance(status, int) and 400 <= status < 500:
            severity = Severity.MEDIUM
        return _make_finding(
            title=f"WAF partial bypass: canary passed, payload sanitized (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_partial",
            mechanism="partial_sanitization",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class WafEvasionStrategy:
    """WAF evasion via encoding: the encoded payload bypassed the WAF,
    but metadata indicates the base (unencoded) payload was blocked.
    """

    name = "waf_bypass_evasion"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        if _is_waf_block(p):
            return None
        # Check that metadata indicates the base payload was blocked
        meta = inp.metadata
        base_blocked = (
            meta.get("base_payload_blocked") is True
            or str(meta.get("base_waf_result", "")).lower() == "blocked"
        )
        if not base_blocked:
            return None
        if not _is_payload_reflected(p):
            return None
        if not _is_waf_block(r):
            return None
        return _make_finding(
            title=f"WAF evasion: encoded payload bypassed WAF (ref[{ref_index}])",
            severity=Severity.HIGH,
            category="waf_bypass_evasion",
            mechanism="encoding_evasion",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class ContentTypeConfusionStrategy:
    """Content-Type confusion: WAF parsed with a different content type
    than the backend, enabling bypass.
    """

    name = "waf_bypass_content_type"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        ct_sent = p.get("content_type_sent")
        ct_parsed = p.get("content_type_parsed")
        if not ct_sent or not ct_parsed:
            return None
        if str(ct_sent).strip().lower() == str(ct_parsed).strip().lower():
            return None
        if _is_waf_block(p):
            return None
        if not p.get("backend_reached"):
            return None
        return _make_finding(
            title=f"WAF content-type confusion: sent={ct_sent} parsed={ct_parsed} (ref[{ref_index}])",
            severity=Severity.MEDIUM,
            category="waf_bypass_content_type",
            mechanism="content_type_confusion",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class EncodingBypassStrategy:
    """Encoding bypass: multi-layer encoding evaded WAF inspection."""

    name = "waf_bypass_encoding"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        depth = p.get("encoding_depth")
        if not isinstance(depth, (int, float)) or depth <= 0:
            return None
        if _is_waf_block(p):
            return None
        if not _is_payload_reflected(p):
            return None
        return _make_finding(
            title=f"WAF encoding bypass: depth={depth} payload reflected (ref[{ref_index}])",
            severity=Severity.MEDIUM,
            category="waf_bypass_encoding",
            mechanism="encoding_depth",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class MultipartBoundaryStrategy:
    """Multipart boundary confusion: WAF and backend disagree on
    the multipart boundary, enabling smuggling of payload parts.
    """

    name = "waf_bypass_multipart"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        boundary_used = p.get("boundary_used")
        boundary_parsed = p.get("boundary_parsed")
        if not boundary_used or not boundary_parsed:
            return None
        if str(boundary_used).strip() == str(boundary_parsed).strip():
            return None
        if _is_waf_block(p):
            return None
        if not p.get("backend_reached"):
            return None
        return _make_finding(
            title=f"WAF multipart boundary confusion: used={boundary_used} parsed={boundary_parsed} (ref[{ref_index}])",
            severity=Severity.MEDIUM,
            category="waf_bypass_multipart",
            mechanism="multipart_boundary_confusion",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class HeaderNormalizationStrategy:
    """Header normalization bypass: WAF and backend process headers
    differently, enabling the payload to slip through.
    """

    name = "waf_bypass_header_norm"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        if _is_waf_block(p):
            return None

        # Detect header normalization difference between WAF and backend
        p_headers = p.get("headers_normalized")
        r_headers = r.get("headers_normalized")
        p_payload_header = p.get("payload_in_header")
        r_payload_header = r.get("payload_in_header")

        # Divergence: WAF sees normalized headers, backend sees raw (or vice versa)
        header_diff = (
            (p_headers is not None and r_headers is not None and p_headers != r_headers)
            or bool(p.get("canary_in_headers")) != bool(r.get("canary_in_headers"))
            or (p_payload_header is not None and r_payload_header is not None
                and p_payload_header != r_payload_header)
        )
        if not header_diff:
            return None
        if not p.get("backend_reached"):
            return None
        if not _is_waf_block(r):
            return None
        return _make_finding(
            title=f"WAF header normalization bypass (ref[{ref_index}])",
            severity=Severity.MEDIUM,
            category="waf_bypass_header_norm",
            mechanism="header_normalization",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class UrlNormalizationStrategy:
    """URL normalization bypass: WAF and backend normalize the URL
    path differently, enabling payload delivery via path confusion.
    """

    name = "waf_bypass_url_norm"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        if _is_waf_block(p):
            return None

        # Detect URL normalization difference between WAF and backend
        p_path = p.get("path_normalized") or p.get("url_path")
        r_path = r.get("path_normalized") or r.get("url_path")
        p_path_raw = p.get("path_raw") or p.get("url_path_raw")
        r_path_raw = r.get("path_raw") or r.get("url_path_raw")

        # At least one side must report path info
        if p_path is None and r_path is None and p_path_raw is None and r_path_raw is None:
            return None

        path_diff = (
            (p_path is not None and r_path is not None and str(p_path) != str(r_path))
            or (p_path_raw is not None and r_path_raw is not None
                and str(p_path_raw) != str(r_path_raw))
            or (p_path is not None and p_path_raw is not None
                and r_path is not None and r_path_raw is not None
                and (str(p_path) != str(p_path_raw)) != (str(r_path) != str(r_path_raw)))
        )
        if not path_diff:
            return None
        if not p.get("backend_reached"):
            return None
        if not _is_waf_block(r):
            return None
        return _make_finding(
            title=f"WAF URL normalization bypass (ref[{ref_index}])",
            severity=Severity.MEDIUM,
            category="waf_bypass_url_norm",
            mechanism="url_normalization",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class CharsetConfusionStrategy:
    """Charset confusion: the request declares an exotic charset
    (e.g. IBM037, UTF-7, UTF-16) that transforms payload bytes.
    The WAF inspects raw bytes (missing the charset) while the backend
    decodes per the declared charset, revealing the payload.
    """

    name = "waf_bypass_charset"

    # Charsets that transform ASCII payload bytes into non-obvious forms.
    _EXOTIC = frozenset({
        "ibm037", "cp037", "ebcdic", "utf-7", "utf-16", "utf-16le",
        "utf-16be", "utf-32", "utf-32le", "utf-32be", "iso-2022-jp",
        "iso-2022-kr", "shift_jis", "euc-jp", "euc-kr", "gb2312",
        "gbk", "gb18030", "big5",
    })

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None
        if _is_waf_block(p):
            return None

        charset = str(p.get("charset_declared") or "").strip().lower()
        if not charset or charset in ("utf-8", "us-ascii", "ascii", "latin-1",
                                       "iso-8859-1", "windows-1252"):
            return None
        if charset.replace("-", "").replace("_", "") not in {
            c.replace("-", "").replace("_", "") for c in self._EXOTIC
        }:
            return None
        if not p.get("backend_reached"):
            return None
        # Promote to HIGH when payload actually reflected through
        # the exotic charset encoding.
        severity = Severity.HIGH if p.get("payload_reflected") else Severity.MEDIUM
        return _make_finding(
            title=f"WAF charset confusion: charset={charset} (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_charset",
            mechanism="charset_confusion",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class HPPStrategy:
    """HTTP Parameter Pollution: the same parameter name appears in
    both query string and body.  The WAF may inspect the query-string
    value (safe) while the backend uses the body value (payload).
    """

    name = "waf_bypass_hpp"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None
        if _is_waf_block(p):
            return None
        if not p.get("backend_reached"):
            return None

        # Extract query params from request line and body params
        query_params = _extract_query_params(inp.data)
        body_params = _extract_body_params(inp.data)
        if not query_params or not body_params:
            return None

        # Find overlapping parameter names
        overlap = set(query_params) & set(body_params)
        if not overlap:
            return None

        severity = Severity.HIGH if _is_payload_reflected(p) else Severity.MEDIUM
        return _make_finding(
            title=f"WAF HPP bypass: duplicate params={','.join(sorted(overlap)[:3])} (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_hpp",
            mechanism="http_parameter_pollution",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class BodyBoundaryMismatchStrategy:
    """Body-level boundary mismatch: the Content-Type header declares
    one boundary but the body uses a different delimiter.  The WAF
    parses per the header boundary (finding no parts), while the
    backend may parse the body boundary (finding the payload).
    """

    name = "waf_bypass_body_boundary"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None
        if _is_waf_block(p):
            return None
        if not p.get("backend_reached"):
            return None

        header_boundary = str(p.get("boundary_used") or "").strip()
        if not header_boundary:
            return None

        # Extract the actual boundary used in the request body
        body_boundary = _extract_body_boundary(inp.data)
        if not body_boundary:
            return None

        # Compare: header boundary vs body boundary
        if header_boundary == body_boundary:
            return None

        severity = Severity.HIGH if _is_payload_reflected(p) else Severity.MEDIUM
        return _make_finding(
            title=f"WAF body boundary mismatch: header={header_boundary[:30]} body={body_boundary[:30]} (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_body_boundary",
            mechanism="body_boundary_mismatch",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


class XmlContentStrategy:
    """XML content-type bypass: WAFFLED-class bypasses where the body
    is XML (DOCTYPE closure, CDATA hiding, extra fields, attribute
    injection, newline abuse, schema manipulation).  The WAF either
    lacks an XML parser or parses the document loosely while the
    backend processes every element, enabling payload delivery.
    """

    name = "waf_bypass_xml"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None
        if _is_preamble_family(p, inp):
            return None

        body_struct = str(p.get("body_structure") or "")
        xml_variant = str(p.get("xml_variant") or "")
        if body_struct != "xml" or not xml_variant:
            return None
        if _is_waf_block(p):
            return None
        if not p.get("backend_reached"):
            return None
        # Require canary or payload to reach the body — otherwise the XML
        # envelope never surfaced past the WAF's parser.
        if not (p.get("canary_in_body") or p.get("payload_reflected")):
            return None

        severity = Severity.HIGH if p.get("payload_reflected") else Severity.MEDIUM
        return _make_finding(
            title=f"WAF XML content bypass: variant={xml_variant} (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_xml",
            mechanism=f"xml_{xml_variant.split(',')[0]}",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


def _extract_query_params(data: bytes) -> dict[str, str]:
    """Extract query string parameter names from the request line."""
    try:
        first_line = data.split(b"\r\n", 1)[0]
        parts = first_line.split(b" ")
        if len(parts) < 2:
            return {}
        url = parts[1]
        if b"?" not in url:
            return {}
        query = url.split(b"?", 1)[1].split(b" ", 1)[0]  # strip HTTP/1.x
        params: dict[str, str] = {}
        for pair in query.split(b"&"):
            if b"=" in pair:
                k = pair.split(b"=", 1)[0].decode("ascii", errors="replace")
                v = pair.split(b"=", 1)[1].decode("ascii", errors="replace")
                params[k] = v
            elif pair:
                params[pair.decode("ascii", errors="replace")] = ""
        return params
    except Exception:
        return {}


def _extract_body_params(data: bytes) -> dict[str, str]:
    """Extract URL-encoded body parameters from the request."""
    try:
        # Find body after header/body separator
        for sep in (b"\r\n\r\n", b"\n\n"):
            if sep in data:
                body = data.split(sep, 1)[1]
                break
        else:
            return {}
        # Only parse if body looks URL-encoded (no binary, has = signs)
        if b"=" not in body or b"\x00" in body[:256]:
            return {}
        # Take first 2048 bytes of body to avoid huge bodies
        body = body[:2048]
        params: dict[str, str] = {}
        for pair in body.split(b"&"):
            if b"=" in pair:
                k = pair.split(b"=", 1)[0].decode("ascii", errors="replace").strip()
                v = pair.split(b"=", 1)[1].decode("ascii", errors="replace")
                if k and k.isprintable():
                    params[k] = v
        return params
    except Exception:
        return {}


def _extract_body_boundary(data: bytes) -> str:
    """Extract the first multipart boundary delimiter from the request body."""
    try:
        for sep in (b"\r\n\r\n", b"\n\n"):
            if sep in data:
                body = data.split(sep, 1)[1]
                break
        else:
            return ""
        # Multipart boundaries start with -- at beginning of body or after CRLF
        for line in body.split(b"\r\n")[:5]:  # check first 5 lines
            stripped = line.strip()
            if stripped.startswith(b"--") and len(stripped) > 4:
                # Return boundary without the leading --
                return stripped[2:].decode("ascii", errors="replace").strip()
        # Also try LF-only
        for line in body.split(b"\n")[:5]:
            stripped = line.strip()
            if stripped.startswith(b"--") and len(stripped) > 4:
                return stripped[2:].decode("ascii", errors="replace").strip()
        return ""
    except Exception:
        return ""


class H2DowngradeStrategy:
    """H2 → H1 downgrade smuggling: detects WAF bypass via H2c binary framing.

    Fires when the request was sent over H2c Prior Knowledge and a specific
    H2 bypass technique (h2_variant) was used.  If the WAF received the H2
    HEADERS/DATA frames without blocking and the payload/canary reached the
    backend, the H2 → H1 translation created a parse ambiguity that the WAF
    missed.

    Techniques covered:
    - ``header_crlf``        — CRLF in H2 header value → extra H1 header
    - ``cl_zero_body``       — content-length: 0 + non-empty DATA frame
    - ``te_forbidden``       — Transfer-Encoding (RFC 7540 §8.1.2.2 violation)
    - ``path_inject``        — CRLF/whitespace in ``:path`` pseudo-header
    - ``authority_mismatch`` — ``:authority`` ≠ ``host`` header
    - ``scheme_mismatch``    — non-standard ``:scheme`` value
    """

    name = "waf_bypass_h2_downgrade"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None
        if _is_error_or_timeout(p) or _is_error_or_timeout(r):
            return None

        if str(p.get("transport_mode") or "") != "h2c":
            return None
        h2_variant = str(p.get("h2_variant") or "")
        if not h2_variant:
            return None
        if _is_waf_block(p):
            return None
        if not p.get("backend_reached"):
            return None
        if not _is_waf_block(r):
            return None

        severity = Severity.HIGH if p.get("payload_reflected") else Severity.MEDIUM
        return _make_finding(
            title=f"WAF H2 downgrade bypass: variant={h2_variant} (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_h2_downgrade",
            mechanism=f"h2_{h2_variant}",
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


_RFC_QUIRK_FAMILIES: frozenset[str] = frozenset({
    "rfc_vt_ff_separator",
    "rfc_absolute_target",
    "rfc_trailer_inject",
    "rfc_param_continuation",
    "rfc_obs_text_header",
    "rfc_method_case",
    "rfc_host_case",
})


class RfcParserQuirkStrategy:
    """RFC specification parsing ambiguity bypass.

    Fires when the mutated request exploits an RFC-specified parsing ambiguity
    (VT/FF whitespace, absolute-form target, chunked trailers, RFC 2231
    parameter continuation, obs-text, method case, or host case) AND the WAF
    passes the request while a reference target blocks it.
    """

    name = "waf_bypass_rfc_quirk"

    def compare(
        self,
        inp: "Input",
        primary: "ExecutionResult",
        reference: "ExecutionResult",
        ref_index: int,
    ) -> "Finding | None":
        p = _parse_result(primary)
        r = _parse_result(reference)
        if p is None or r is None:
            return None

        # Only fire for rfc_spec_quirks lane techniques
        if inp.metadata.get("technique_family", "") not in _RFC_QUIRK_FAMILIES:
            return None

        if not p.get("backend_reached"):
            return None
        if p.get("waf_blocked"):
            return None
        if not r.get("waf_blocked"):
            return None

        quirk = inp.metadata.get("technique_family", "unknown")
        severity = Severity.HIGH if p.get("payload_reflected") else Severity.MEDIUM
        return _make_finding(
            title=f"WAF RFC parser quirk bypass: technique={quirk} (ref[{ref_index}])",
            severity=severity,
            category="waf_bypass_rfc_quirk",
            mechanism=quirk,
            inp=inp,
            primary_result=primary,
            primary_data=p,
            reference_data=r,
            ref_index=ref_index,
        )


# ── Factory ─────────────────────────────────────────────────────


def get_waf_bypass_strategies() -> list:
    return [
        WafBypassStrategy(),
        WafPartialBypassStrategy(),
        WafEvasionStrategy(),
        ContentTypeConfusionStrategy(),
        EncodingBypassStrategy(),
        MultipartBoundaryStrategy(),
        HeaderNormalizationStrategy(),
        UrlNormalizationStrategy(),
        CharsetConfusionStrategy(),
        HPPStrategy(),
        BodyBoundaryMismatchStrategy(),
        XmlContentStrategy(),
        H2DowngradeStrategy(),
        RfcParserQuirkStrategy(),
    ]
