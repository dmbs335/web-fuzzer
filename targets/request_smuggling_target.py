"""Probe-aware request smuggling differential target."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time
import zlib
from pathlib import Path


_FAMILY_AXIS_FALLBACKS: dict[str, dict[str, str]] = {
    "cl_te": {
        "axis_framing": "CL",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "te_cl": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "te_te": {
        "axis_framing": "TE",
        "axis_leniency": "obs_fold",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "duplicate_cl": {
        "axis_framing": "CL",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "x_original_url",
        "stream_shape": "padding_plus_canary",
    },
    "duplicate_te": {
        "axis_framing": "TE",
        "axis_leniency": "duplicate_resolution",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "x_original_url",
        "stream_shape": "body_plus_canary",
    },
    "cl_0": {
        "axis_framing": "CL",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "x_original_url",
        "stream_shape": "padding_plus_canary",
    },
    "0_cl": {
        "axis_framing": "0",
        "axis_leniency": "whitespace_before_colon",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "padding_plus_canary",
    },
    "te_0": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "chunk_ws": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "size_whitespace",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "chunk_ext": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "chunk_extension",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "chunk_bare_lf": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "bare_lf",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "trailer_merge": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "trailer_override_path",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "x_original_url",
        "stream_shape": "trailers_plus_canary",
    },
    "trailer_header_ambiguity": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "trailer_override_host",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "authority_conflict",
        "stream_shape": "trailers_plus_canary",
    },
    "chunk_terminator": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "terminator_ambiguity",
        "axis_connection": "keepalive",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "pause_prefix": {
        "axis_framing": "CL",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "reuse",
        "axis_timing": "pause_prefix",
        "axis_routing": "host",
        "stream_shape": "split_canary",
    },
    "pause_suffix": {
        "axis_framing": "TE",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "reuse",
        "axis_timing": "pause_suffix",
        "axis_routing": "host",
        "stream_shape": "split_canary",
    },
    "early_response": {
        "axis_framing": "0",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "reuse",
        "axis_timing": "early_response",
        "axis_routing": "rewrite_path",
        "stream_shape": "split_canary",
    },
    "connection_locked": {
        "axis_framing": "CL",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "reuse",
        "axis_timing": "partial_hold",
        "axis_routing": "host",
        "stream_shape": "split_canary",
    },
    "halfclose": {
        "axis_framing": "CL",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "halfclose",
        "axis_timing": "halfclose",
        "axis_routing": "host",
        "stream_shape": "split_canary",
    },
    "h2_cl": {
        "axis_framing": "H2",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "downgrade",
        "axis_timing": "none",
        "axis_routing": "x_original_url",
        "stream_shape": "body_plus_canary",
    },
    "h2_te": {
        "axis_framing": "H2",
        "axis_leniency": "forbidden_retention",
        "axis_chunk": "none",
        "axis_connection": "downgrade",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "h2_0": {
        "axis_framing": "H2",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "downgrade",
        "axis_timing": "none",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
    "h2_dup_authority": {
        "axis_framing": "H2",
        "axis_leniency": "duplicate_resolution",
        "axis_chunk": "none",
        "axis_connection": "downgrade",
        "axis_timing": "none",
        "axis_routing": "authority_conflict",
        "stream_shape": "body_plus_canary",
    },
    "h2_header_gap": {
        "axis_framing": "H2",
        "axis_leniency": "forbidden_retention",
        "axis_chunk": "none",
        "axis_connection": "downgrade",
        "axis_timing": "none",
        "axis_routing": "rewrite_path",
        "stream_shape": "body_plus_canary",
    },
    "h2_end_stream_gap": {
        "axis_framing": "H2",
        "axis_leniency": "strict",
        "axis_chunk": "none",
        "axis_connection": "downgrade",
        "axis_timing": "early_response",
        "axis_routing": "host",
        "stream_shape": "body_plus_canary",
    },
}


def _split_header_block(data: bytes) -> tuple[bytes, bytes, bytes]:
    if b"\r\n\r\n" in data:
        head, rest = data.split(b"\r\n\r\n", 1)
        return head, rest, b"\r\n"
    if b"\n\n" in data:
        head, rest = data.split(b"\n\n", 1)
        return head, rest, b"\n"
    raise ValueError("missing header terminator")


def _extract_control(wire: bytes) -> tuple[dict[str, object], bytes]:
    head, rest, delim = _split_header_block(wire)
    lines = head.split(delim)
    if not lines:
        raise ValueError("empty request")
    kept = [lines[0]]
    meta: dict[str, object] = {
        "request_id": "",
        "variant_family": "unknown",
        "taxonomy_tags": [],
        "request_smuggling_mode": "hybrid",
        "transport_mode": "h1_raw",
        "delivery_mode": "oneshot_h1",
        "probe_mode": "none",
        "pause_ms": 0,
        "chunk_shape": "none",
        "h2_mode": "none",
        "h2_end_stream": "normal",
        "impact_hint": "none",
        "canary_path": "",
        "axis_framing": "unknown",
        "axis_leniency": "unknown",
        "axis_chunk": "unknown",
        "axis_connection": "unknown",
        "axis_timing": "unknown",
        "axis_routing": "unknown",
        "stream_shape": "unknown",
    }
    for raw_line in lines[1:]:
        lower = raw_line.lower()
        if lower.startswith(b"x-wf-request-id:"):
            meta["request_id"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-family:"):
            meta["variant_family"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-tags:"):
            value = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            meta["taxonomy_tags"] = [tag.strip() for tag in value.split(",") if tag.strip()]
            continue
        if lower.startswith(b"x-wf-transport:"):
            meta["transport_mode"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-delivery:"):
            meta["delivery_mode"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-probe:"):
            meta["probe_mode"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-pause-ms:"):
            value = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            try:
                meta["pause_ms"] = int(value)
            except ValueError:
                meta["pause_ms"] = 0
            continue
        if lower.startswith(b"x-wf-chunk-shape:"):
            meta["chunk_shape"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-h2-mode:"):
            meta["h2_mode"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-h2-end-stream:"):
            meta["h2_end_stream"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-impact:"):
            meta["impact_hint"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-canary-path:"):
            meta["canary_path"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-mode:"):
            meta["request_smuggling_mode"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-framing:"):
            meta["axis_framing"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-leniency:"):
            meta["axis_leniency"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-chunk:"):
            meta["axis_chunk"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-connection:"):
            meta["axis_connection"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-timing:"):
            meta["axis_timing"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-routing:"):
            meta["axis_routing"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-stream-shape:"):
            meta["stream_shape"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        kept.append(raw_line)
    stripped = delim.join(kept) + delim + delim + rest
    request_id = str(meta.get("request_id") or "")
    if request_id and not meta.get("canary_path"):
        meta["canary_path"] = f"/__canary__/{request_id}"
    family = str(meta.get("variant_family") or "")
    fallback = _FAMILY_AXIS_FALLBACKS.get(family, {})
    for key, value in fallback.items():
        if str(meta.get(key) or "").strip().lower() in {"", "unknown", "none"}:
            meta[key] = value
    return meta, stripped


def _artifact_root(artifact_dir: str | None) -> Path | None:
    if artifact_dir:
        return Path(artifact_dir)
    output_dir = os.environ.get("WEBFUZZER_OUTPUT_DIR", "").strip()
    if not output_dir:
        return None
    return Path(output_dir) / "artifacts" / "request_smuggling"


def _save_artifact(wire: bytes, request_id: str, artifact_dir: str | None) -> str:
    target_dir = _artifact_root(artifact_dir)
    if target_dir is None:
        return ""
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_id = request_id or f"wire-{zlib.crc32(wire) & 0xFFFFFFFF:08x}"
    artifact = target_dir / f"{safe_id}.wire"
    artifact.write_bytes(wire)
    return str(artifact.resolve())


def _recv_until(sock: socket.socket, buffer: bytes, marker: bytes) -> tuple[bytes, bytes, bool]:
    closed = False
    while marker not in buffer:
        chunk = sock.recv(8192)
        if not chunk:
            closed = True
            break
        buffer += chunk
    if marker not in buffer:
        raise ValueError("incomplete_headers")
    head, rest = buffer.split(marker, 1)
    return head, rest, closed


def _read_exact(sock: socket.socket, buffer: bytes, needed: int) -> tuple[bytes, bytes, bool]:
    closed = False
    while len(buffer) < needed:
        chunk = sock.recv(8192)
        if not chunk:
            closed = True
            break
        buffer += chunk
    return buffer[:needed], buffer[needed:], closed


def _read_chunked(sock: socket.socket, buffer: bytes) -> tuple[bytes, bytes, bool]:
    body = b""
    closed = False
    while True:
        if b"\r\n" in buffer:
            delimiter = b"\r\n"
        elif b"\n" in buffer:
            delimiter = b"\n"
        else:
            chunk = sock.recv(8192)
            if not chunk:
                return body, buffer, True
            buffer += chunk
            continue

        line, buffer = buffer.split(delimiter, 1)
        try:
            size = int(line.decode("ascii", errors="replace").split(";", 1)[0].strip(), 16)
        except ValueError as exc:
            raise ValueError(f"chunk_size:{exc}") from exc
        if size == 0:
            if delimiter not in buffer:
                chunk = sock.recv(8192)
                if not chunk:
                    return body, buffer, True
                buffer += chunk
            _, buffer = buffer.split(delimiter, 1)
            return body, buffer, closed
        data, buffer, more_closed = _read_exact(sock, buffer, size + len(delimiter))
        body += data[:size]
        closed = closed or more_closed


def _parse_response(sock: socket.socket, buffer: bytes) -> tuple[dict[str, object], bytes]:
    head, rest, closed = _recv_until(sock, buffer, b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", errors="replace")
    parts = status_line.split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.strip().decode("latin-1").lower()] = value.strip().decode("latin-1", errors="replace")

    if "chunked" in headers.get("transfer-encoding", "").lower():
        body, rest, closed = _read_chunked(sock, rest)
    else:
        length = int(headers.get("content-length", "0") or "0")
        if length > 0:
            data, rest, more_closed = _read_exact(sock, rest, length)
            body = data
            closed = closed or more_closed
        else:
            body = b""
    return {
        "status": status,
        "headers": headers,
        "body": body,
        "closed": closed,
    }, rest


def _parse_request_components(wire: bytes) -> dict[str, object]:
    head, body, delim = _split_header_block(wire)
    lines = head.split(delim)
    req_line = lines[0].decode("latin-1", errors="replace")
    method, path, _ = (req_line.split() + ["", "", ""])[:3]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers.append(
            (
                key.strip().decode("latin-1", errors="replace"),
                value.strip().decode("latin-1", errors="replace"),
            ),
        )
    return {
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
        "delimiter": delim,
    }


def _body_split_offsets(wire: bytes, probe_mode: str) -> tuple[int, int]:
    head, body, delim = _split_header_block(wire)
    body_start = len(head) + (2 * len(delim))
    body_len = len(body)
    if body_len <= 1:
        return body_start, len(wire)
    if probe_mode == "pause_suffix":
        cut = max(1, body_len - max(4, body_len // 4))
    elif probe_mode == "early_response":
        cut = 0
    elif probe_mode == "connection_locked":
        cut = min(body_len, 1)
    else:
        cut = max(1, body_len // 2)
    return body_start + cut, len(wire)


def _blob_contains_marker(blob_parts: list[bytes], needle: bytes) -> bool:
    return needle in b" ".join(blob_parts).lower()


def _detect_impact(blob_parts: list[bytes], headers: dict[str, object]) -> tuple[bool, str, str]:
    impact_type = ""
    impact_detail = ""
    header_value = str(headers.get("x-impact-marker") or "").strip()
    if header_value:
        impact_type = header_value
    header_detail = str(headers.get("x-impact-detail") or "").strip()
    if header_detail:
        impact_detail = header_detail
    joined = b" ".join(blob_parts)
    low = joined.lower()
    if b"impact:cache_poison" in low and not impact_type:
        impact_type = "cache_poison"
    elif b"impact:acl_bypass" in low and not impact_type:
        impact_type = "acl_bypass"
    elif b"impact:response_queue" in low and not impact_type:
        impact_type = "response_queue"
    elif b"impact:prefix_reflection" in low and not impact_type:
        impact_type = "prefix_reflection"
    return bool(impact_type), impact_type, impact_detail


def _header_value(headers: dict[str, object], name: str) -> str:
    return str(headers.get(name.lower()) or "").strip()


def _axis_projection(result: dict[str, object]) -> str:
    return (
        f"framing={result.get('axis_framing', 'unknown')}"
        f"|leniency={result.get('axis_leniency', 'unknown')}"
        f"|chunk={result.get('axis_chunk', 'unknown')}"
        f"|connection={result.get('axis_connection', 'unknown')}"
        f"|timing={result.get('axis_timing', 'unknown')}"
        f"|routing={result.get('axis_routing', 'unknown')}"
        f"|shape={result.get('stream_shape', 'unknown')}"
    )


def _record_response(
    result: dict[str, object],
    response: dict[str, object],
    *,
    ordinal: int,
    canary: bytes,
    elapsed_ms: float,
) -> None:
    body = bytes(response["body"])
    headers_json = json.dumps(response["headers"]).encode("utf-8", errors="replace")
    blob_parts = [body, headers_json]
    status_key = "first_response_status" if ordinal == 1 else "second_response_status"
    crc_key = "first_body_crc32" if ordinal == 1 else "second_body_crc32"
    canary_key = "canary_seen_in_first" if ordinal == 1 else "canary_seen_in_second"
    timing_key = "first_response_timing_ms" if ordinal == 1 else "second_response_timing_ms"

    result[status_key] = response["status"]
    result[crc_key] = zlib.crc32(body) & 0xFFFFFFFF
    result[canary_key] = bool(canary and canary in body)
    result[timing_key] = round(elapsed_ms, 2)
    result["connection_closed"] = bool(response["closed"])
    result["backend_marker_seen"] = bool(result["backend_marker_seen"]) or _blob_contains_marker(
        blob_parts,
        b"backend-marker",
    )
    result["frontend_marker_seen"] = bool(result["frontend_marker_seen"]) or _blob_contains_marker(
        blob_parts,
        b"frontend-marker",
    )
    impact_seen, impact_type, impact_detail = _detect_impact(blob_parts, response["headers"])
    result["impact_marker_seen"] = bool(result["impact_marker_seen"]) or impact_seen
    if impact_type and not result.get("impact_type"):
        result["impact_type"] = impact_type
    if impact_detail and not result.get("impact_detail"):
        result["impact_detail"] = impact_detail
    effective_headers = _header_value(response["headers"], "x-effective-headers")
    if effective_headers and not result.get("effective_headers"):
        result["effective_headers"] = effective_headers
    body_boundary = _header_value(response["headers"], "x-body-boundary")
    if body_boundary and not result.get("effective_body_boundary"):
        result["effective_body_boundary"] = body_boundary
    forwarded_hash = _header_value(response["headers"], "x-forwarded-request-hash")
    if forwarded_hash and not result.get("forwarded_request_hash"):
        result["forwarded_request_hash"] = forwarded_hash
    trailer_merge = _header_value(response["headers"], "x-trailer-merge")
    if trailer_merge and trailer_merge != "none":
        result["trailer_forwarded"] = True
        if not result.get("trailer_merge_keys"):
            result["trailer_merge_keys"] = trailer_merge
    trailer_forwarded = _header_value(response["headers"], "x-trailer-forwarded")
    if trailer_forwarded:
        result["trailer_forwarded"] = trailer_forwarded.lower() == "true"
    request_line = _header_value(response["headers"], "x-forwarded-request-line")
    if request_line and not result.get("forwarded_request_line"):
        result["forwarded_request_line"] = request_line
    routing_source = _header_value(response["headers"], "x-routing-decision-source")
    if routing_source and not result.get("routing_decision_source"):
        result["routing_decision_source"] = routing_source
    cache_source = _header_value(response["headers"], "x-cache-decision-source")
    if cache_source and not result.get("cache_decision_source"):
        result["cache_decision_source"] = cache_source
    if b"GET /__canary__" in body:
        idx = body.index(b"GET /__canary__")
        result["reflected_smuggled_prefix"] = body[idx:idx + 96].decode("latin-1", errors="replace")
    result["response_count_observed"] = max(int(result["response_count_observed"]), ordinal)


_FRONTEND_ERROR_SIGNATURES = (
    b"Your browser sent an invalid request",  # HAProxy
    b"<center>nginx/",                        # nginx
    b"<center><h1>400 Bad Request</h1>",      # nginx
    b"<title>400 Bad Request</title>",         # nginx / Apache
    b"<title>502 Bad Gateway</title>",         # nginx / generic
    b"caddy",                                  # Caddy
    b"Traefik",                                # Traefik
    b"<title>408 Request Time-out</title>",    # HAProxy
    b"<title>503 Service Unavailable</title>", # generic proxy
)


def _is_frontend_error_page(status: int, body: bytes) -> bool:
    """Detect whether a response is a frontend proxy error page.

    Backend marker targets return plain-text structured responses, never
    HTML error pages.  Any HTML 4xx/5xx response must come from the
    frontend proxy and does NOT indicate pipeline contamination.
    """
    if status is None or status < 400:
        return False
    if b"<html" in body[:256].lower() or b"<!doctype" in body[:256].lower():
        return True
    for sig in _FRONTEND_ERROR_SIGNATURES:
        if sig in body:
            return True
    return False


def _pipeline_victim_probe(
    sock: socket.socket,
    result: dict[str, object],
    timeout: float,
) -> None:
    """After detecting response_count>1, send a victim GET to check pipeline poisoning.

    If the victim response is for a different request (wrong path in body),
    that confirms cross-request contamination on the same connection.
    """
    import uuid
    victim_marker = uuid.uuid4().hex[:12]
    victim_req = (
        b"GET /pipeline-victim-" + victim_marker.encode() + b" HTTP/1.1\r\n"
        b"Host: backend.local\r\n"
        b"User-Agent: pipeline-victim-probe/1.0\r\n"
        b"X-Pipeline-Victim: " + victim_marker.encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    result["pipeline_victim_sent"] = True
    result["pipeline_victim_marker"] = victim_marker
    try:
        sock.sendall(victim_req)
    except (BrokenPipeError, ConnectionResetError, OSError):
        result["pipeline_victim_status"] = None
        result["pipeline_victim_outcome"] = "send_failed"
        return

    sock.settimeout(min(timeout, 2.0))
    buffer = b""
    try:
        resp, buffer = _parse_response(sock, buffer)
    except (socket.timeout, ValueError, Exception):
        result["pipeline_victim_status"] = None
        result["pipeline_victim_outcome"] = "no_response"
        return

    result["pipeline_victim_status"] = resp["status"]
    body = bytes(resp["body"])

    # Check if victim response actually corresponds to our victim request
    has_marker = victim_marker.encode() in body
    # Check for contamination: response body references smuggled/canary paths instead
    has_smuggled = (
        b"/smuggled" in body
        or b"__canary__" in body
        or (b"Backend saw:" in body and victim_marker.encode() not in body)
    )
    if has_marker:
        result["pipeline_victim_outcome"] = "clean"
        result["pipeline_victim_contaminated"] = False
    elif has_smuggled:
        result["pipeline_victim_outcome"] = "contaminated_smuggled"
        result["pipeline_victim_contaminated"] = True
    elif not body:
        result["pipeline_victim_outcome"] = "empty_body"
        result["pipeline_victim_contaminated"] = False
    elif _is_frontend_error_page(resp["status"], body):
        # Frontend proxy (HAProxy/nginx/Caddy/Traefik) returned its own
        # error page — connection state confusion, not backend contamination.
        result["pipeline_victim_outcome"] = "frontend_rejected"
        result["pipeline_victim_contaminated"] = False
    else:
        # Response came back but doesn't contain our marker — could be
        # the response for a leftover smuggled request
        result["pipeline_victim_outcome"] = "misrouted"
        result["pipeline_victim_contaminated"] = True
    result["pipeline_victim_body_preview"] = body[:128].decode("latin-1", errors="replace")


def _execute_oneshot_h1(
    sock: socket.socket,
    stripped_wire: bytes,
    *,
    result: dict[str, object],
    canary: bytes,
    timeout: float,
    start: float,
) -> None:
    sock.sendall(stripped_wire)
    result["request_bytes_sent"] = len(stripped_wire)
    buffer = b""
    first, buffer = _parse_response(sock, buffer)
    _record_response(result, first, ordinal=1, canary=canary, elapsed_ms=(time.monotonic() - start) * 1000)
    if first["closed"]:
        return
    sock.settimeout(timeout)
    try:
        second, buffer = _parse_response(sock, buffer)
    except socket.timeout:
        result["timeout_phase"] = "second_response"
        result["extra_bytes_left"] = len(buffer)
        return
    _record_response(result, second, ordinal=2, canary=canary, elapsed_ms=(time.monotonic() - start) * 1000)
    result["extra_bytes_left"] = len(buffer)

    # Pipeline victim probe: when backend processed >1 responses AND
    # connection is still alive, probe for cross-request contamination
    if (
        int(result.get("response_count_observed", 0)) >= 2
        and not bool(result.get("connection_closed"))
    ):
        _pipeline_victim_probe(sock, result, timeout)


def _execute_pause_probe_h1(
    sock: socket.socket,
    stripped_wire: bytes,
    *,
    result: dict[str, object],
    canary: bytes,
    timeout: float,
    start: float,
    probe_mode: str,
    pause_ms: int,
) -> None:
    split_idx, _ = _body_split_offsets(stripped_wire, probe_mode)
    prefix = stripped_wire[:split_idx]
    suffix = stripped_wire[split_idx:]
    sock.sendall(prefix)
    sent = len(prefix)
    result["request_bytes_sent"] = sent

    buffer = b""
    early_response: dict[str, object] | None = None
    pause_deadline = max(timeout / 2, pause_ms / 1000.0 if pause_ms else 0.1)
    sock.settimeout(pause_deadline)
    try:
        early_response, buffer = _parse_response(sock, buffer)
        result["probe_outcome"] = "early_response_before_body"
        _record_response(
            result,
            early_response,
            ordinal=1,
            canary=canary,
            elapsed_ms=(time.monotonic() - start) * 1000,
        )
    except socket.timeout:
        result["probe_outcome"] = "no_early_signal"
    except (BrokenPipeError, ConnectionResetError, OSError):
        result["probe_outcome"] = "closed_during_pause"
        return
    except Exception as exc:  # pragma: no cover - defensive
        result["parse_error"] = f"pause_probe:{exc}"
        return

    if pause_ms:
        time.sleep(max(0.0, pause_ms / 1000.0))

    if suffix:
        try:
            sock.settimeout(timeout)
            sock.sendall(suffix)
            sent += len(suffix)
            result["request_bytes_sent"] = sent
        except (BrokenPipeError, ConnectionResetError, OSError):
            if early_response is not None:
                result["probe_outcome"] = "closed_after_early_response"
            return

    if early_response is None:
        try:
            first, buffer = _parse_response(sock, buffer)
        except socket.timeout:
            result["timeout_phase"] = "first_response"
            result["probe_outcome"] = "backend_timeout_after_pause"
            result["extra_bytes_left"] = len(buffer)
            return
        _record_response(result, first, ordinal=1, canary=canary, elapsed_ms=(time.monotonic() - start) * 1000)
        early_response = first
        result["probe_outcome"] = "accepted_after_pause"

    if bool(early_response["closed"]):
        result["extra_bytes_left"] = len(buffer)
        return

    try:
        second, buffer = _parse_response(sock, buffer)
        _record_response(result, second, ordinal=2, canary=canary, elapsed_ms=(time.monotonic() - start) * 1000)
        if result["probe_outcome"] == "early_response_before_body":
            result["probe_outcome"] = "late_bytes_consumed_as_second"
    except socket.timeout:
        if result["probe_outcome"] == "no_early_signal":
            result["probe_outcome"] = "pause_timeout_no_desync"
        result["timeout_phase"] = result["timeout_phase"] or "second_response"
    result["extra_bytes_left"] = len(buffer)


def _execute_halfclose_probe_h1(
    sock: socket.socket,
    stripped_wire: bytes,
    *,
    result: dict[str, object],
    canary: bytes,
    timeout: float,
    start: float,
) -> None:
    sock.sendall(stripped_wire)
    result["request_bytes_sent"] = len(stripped_wire)
    sock.shutdown(socket.SHUT_WR)
    result["probe_outcome"] = "shutdown_write"
    buffer = b""
    try:
        first, buffer = _parse_response(sock, buffer)
    except socket.timeout:
        result["timeout_phase"] = "first_response"
        result["probe_outcome"] = "locked_until_halfclose"
        return
    _record_response(result, first, ordinal=1, canary=canary, elapsed_ms=(time.monotonic() - start) * 1000)
    result["probe_outcome"] = "response_after_halfclose"
    if first["closed"]:
        return
    try:
        second, buffer = _parse_response(sock, buffer)
        _record_response(result, second, ordinal=2, canary=canary, elapsed_ms=(time.monotonic() - start) * 1000)
    except socket.timeout:
        result["timeout_phase"] = "second_response"
    result["extra_bytes_left"] = len(buffer)


def _execute_h2_raw(
    sock: socket.socket,
    stripped_wire: bytes,
    *,
    result: dict[str, object],
    canary: bytes,
    timeout: float,
    start: float,
    probe_mode: str,
    pause_ms: int,
) -> None:
    from h2.config import H2Configuration
    from h2.connection import H2Connection
    from h2.events import (
        ConnectionTerminated,
        DataReceived,
        InformationalResponseReceived,
        RemoteSettingsChanged,
        ResponseReceived,
        SettingsAcknowledged,
        StreamEnded,
        StreamReset,
        TrailersReceived,
    )

    components = _parse_request_components(stripped_wire)
    method = str(components["method"] or "GET")
    path = str(components["path"] or "/")
    body = bytes(components["body"])
    header_items: list[tuple[str, str]] = list(components["headers"])
    h2_mode = str(result.get("h2_mode") or "none")
    h2_end_stream = str(result.get("h2_end_stream") or "normal")

    authority = "victim.local"
    h2_headers: list[tuple[str, str]] = [
        (":method", method),
        (":scheme", "http"),
        (":path", path),
        (":authority", authority),
    ]
    for key, value in header_items:
        low = key.lower()
        if low in {"connection", "proxy-connection", "keep-alive", "upgrade"}:
            continue
        if low == "host":
            authority = value
            continue
        if low == "content-length" and h2_mode == "content_length_mismatch":
            try:
                mismatch = int(value) + max(3, len(body))
                value = str(mismatch)
            except ValueError:
                value = str(len(body) + 5)
        if low == "transfer-encoding" and h2_mode != "forbidden_transfer_encoding":
            continue
        h2_headers.append((low, value))
    h2_headers[3] = (":authority", authority)
    if h2_mode == "duplicate_authority":
        h2_headers.append(("host", authority))
        h2_headers.append(("x-forwarded-host", f"shadow.{authority}"))
    if h2_mode == "header_sanitation_gap":
        h2_headers.append(("x-original-url", "/shadow-admin"))
        h2_headers.append(("x-rewrite-url", path))
    if h2_mode == "forbidden_transfer_encoding":
        h2_headers.append(("transfer-encoding", "chunked"))

    config = H2Configuration(
        client_side=True,
        header_encoding="utf-8",
        validate_outbound_headers=False,
        normalize_outbound_headers=False,
    )
    conn = H2Connection(config=config)
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    stream_id = conn.get_next_available_stream_id()
    header_end_stream = (len(body) == 0) or (h2_end_stream == "headers_early")
    conn.send_headers(stream_id, h2_headers, end_stream=header_end_stream)
    sock.sendall(conn.data_to_send())
    sent = 0
    if body and not header_end_stream:
        if probe_mode == "pause_prefix":
            split = max(1, len(body) // 2)
            conn.send_data(stream_id, body[:split], end_stream=False)
            sock.sendall(conn.data_to_send())
            sent += split
            if pause_ms:
                time.sleep(max(0.0, pause_ms / 1000.0))
            conn.send_data(stream_id, body[split:], end_stream=True)
        else:
            conn.send_data(stream_id, body, end_stream=True)
        data = conn.data_to_send()
        if data:
            sock.sendall(data)
            sent = len(body)
    elif body and header_end_stream:
        result["probe_outcome"] = "h2_headers_ended_early"
    result["request_bytes_sent"] = sent

    response_headers: list[tuple[str, str]] = []
    response_body = bytearray()
    ended = False
    buffer_count = 0
    event_trace: list[str] = []
    trailer_count = 0
    data_frames = 0
    reset_error = None
    goaway_error = None
    h2_error_detail = ""
    while not ended:
        try:
            payload = sock.recv(65535)
        except socket.timeout:
            result["timeout_phase"] = result["timeout_phase"] or "first_response"
            break
        if not payload:
            break
        events = conn.receive_data(payload)
        sock.sendall(conn.data_to_send())
        for event in events:
            event_trace.append(type(event).__name__)
            if isinstance(event, ResponseReceived):
                response_headers.extend([(str(k), str(v)) for k, v in event.headers])
                if result["first_response_timing_ms"] is None:
                    result["first_response_timing_ms"] = round((time.monotonic() - start) * 1000, 2)
            elif isinstance(event, InformationalResponseReceived):
                if result["first_response_timing_ms"] is None:
                    result["first_response_timing_ms"] = round((time.monotonic() - start) * 1000, 2)
                result["h2_informational_status"] = [
                    str(v) for k, v in event.headers if str(k) == ":status"
                ]
            elif isinstance(event, DataReceived):
                response_body.extend(event.data)
                conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                data_frames += 1
            elif isinstance(event, TrailersReceived):
                trailer_count += len(event.headers)
            elif isinstance(event, StreamEnded):
                ended = True
            elif isinstance(event, StreamReset):
                reset_error = getattr(event, "error_code", None)
                ended = True
            elif isinstance(event, ConnectionTerminated):
                goaway_error = getattr(event, "error_code", None)
                h2_error_detail = f"last_stream_id={getattr(event, 'last_stream_id', '')}"
                ended = True
            elif isinstance(event, (SettingsAcknowledged, RemoteSettingsChanged)):
                continue
        buffer_count += len(payload)

    header_map: dict[str, str] = {}
    status = None
    for key, value in response_headers:
        if key == ":status":
            if value.isdigit():
                status = int(value)
            continue
        header_map[key.lower()] = value
    response = {
        "status": status,
        "headers": header_map,
        "body": bytes(response_body),
        "closed": False,
    }
    _record_response(result, response, ordinal=1, canary=canary, elapsed_ms=(time.monotonic() - start) * 1000)
    result["response_count_observed"] = 1 if status is not None else 0
    result["h2_event_trace"] = event_trace[:24]
    result["h2_headers_seen"] = len(response_headers)
    result["h2_trailers_seen"] = trailer_count
    result["h2_data_frames"] = data_frames
    result["h2_bytes_received"] = buffer_count
    result["h2_reset_error"] = str(reset_error) if reset_error is not None else ""
    result["h2_goaway_error"] = str(goaway_error) if goaway_error is not None else ""
    result["h2_error_detail"] = h2_error_detail
    if reset_error is not None:
        result["probe_outcome"] = f"h2_stream_reset:{reset_error}"
    elif goaway_error is not None:
        result["probe_outcome"] = f"h2_goaway:{goaway_error}"
    elif status is not None and len(response_body) == 0:
        result["probe_outcome"] = "h2_headers_only"
    elif status is not None:
        result["probe_outcome"] = "h2_complete"
    else:
        result["probe_outcome"] = "h2_no_response"
    result["extra_bytes_left"] = buffer_count


def execute_wire(
    wire: bytes,
    *,
    host: str,
    port: int,
    timeout: float = 2.0,
    artifact_dir: str | None = None,
    artifact_path: str | None = None,
) -> dict[str, object]:
    meta, stripped_wire = _extract_control(wire)
    stable_artifact = _save_artifact(
        wire,
        str(meta.get("request_id") or ""),
        artifact_dir,
    )
    result: dict[str, object] = {
        "request_smuggling_mode": meta.get("request_smuggling_mode", "hybrid"),
        "transport_mode": meta.get("transport_mode", "h1_raw"),
        "delivery_mode": meta.get("delivery_mode", "oneshot_h1"),
        "probe_mode": meta.get("probe_mode", "none"),
        "probe_outcome": "not_run",
        "h2_mode": meta.get("h2_mode", "none"),
        "h2_end_stream": meta.get("h2_end_stream", "normal"),
        "impact_hint": meta.get("impact_hint", "none"),
        "axis_framing": meta.get("axis_framing", "unknown"),
        "axis_leniency": meta.get("axis_leniency", "unknown"),
        "axis_chunk": meta.get("axis_chunk", "unknown"),
        "axis_connection": meta.get("axis_connection", "unknown"),
        "axis_timing": meta.get("axis_timing", "unknown"),
        "axis_routing": meta.get("axis_routing", "unknown"),
        "stream_shape": meta.get("stream_shape", "unknown"),
        "request_id": meta.get("request_id", ""),
        "variant_family": meta.get("variant_family", "unknown"),
        "taxonomy_tags": meta.get("taxonomy_tags", []),
        "first_response_status": None,
        "second_response_status": None,
        "first_body_crc32": None,
        "second_body_crc32": None,
        "first_response_timing_ms": None,
        "second_response_timing_ms": None,
        "response_count_observed": 0,
        "connection_closed": False,
        "timeout_phase": None,
        "parse_error": None,
        "canary_seen_in_first": False,
        "canary_seen_in_second": False,
        "backend_marker_seen": False,
        "frontend_marker_seen": False,
        "impact_marker_seen": False,
        "impact_type": "",
        "impact_detail": "",
        "effective_headers": "",
        "effective_body_boundary": "",
        "forwarded_request_hash": "",
        "forwarded_request_line": "",
        "trailer_forwarded": False,
        "trailer_merge_keys": "",
        "routing_decision_source": "",
        "cache_decision_source": "",
        "reflected_smuggled_prefix": "",
        "extra_bytes_left": 0,
        "request_bytes_sent": 0,
        "h2_event_trace": [],
        "h2_headers_seen": 0,
        "h2_trailers_seen": 0,
        "h2_data_frames": 0,
        "h2_bytes_received": 0,
        "h2_reset_error": "",
        "h2_goaway_error": "",
        "h2_error_detail": "",
        "pipeline_victim_sent": False,
        "pipeline_victim_marker": "",
        "pipeline_victim_status": None,
        "pipeline_victim_outcome": "not_probed",
        "pipeline_victim_contaminated": False,
        "pipeline_victim_body_preview": "",
        "raw_artifact_path": stable_artifact or artifact_path or "",
        "artifact_path_stable": stable_artifact,
        "target_host": host,
        "target_port": port,
    }
    result["axis_projection"] = _axis_projection(result)
    canary = str(meta.get("canary_path") or "").encode("ascii", errors="ignore")
    start = time.monotonic()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except socket.timeout:
            result["timeout_phase"] = "connect"
            return result
        except OSError as exc:
            result["parse_error"] = f"connect:{exc}"
            return result

        transport_mode = str(meta.get("transport_mode") or "h1_raw")
        delivery_mode = str(meta.get("delivery_mode") or "oneshot_h1")
        probe_mode = str(meta.get("probe_mode") or "none")
        pause_ms = int(meta.get("pause_ms") or 0)

        try:
            if transport_mode == "h2_raw" or delivery_mode == "h2_raw":
                _execute_h2_raw(
                    sock,
                    stripped_wire,
                    result=result,
                    canary=canary,
                    timeout=timeout,
                    start=start,
                    probe_mode=probe_mode,
                    pause_ms=pause_ms,
                )
            elif delivery_mode == "pause_probe_h1":
                _execute_pause_probe_h1(
                    sock,
                    stripped_wire,
                    result=result,
                    canary=canary,
                    timeout=timeout,
                    start=start,
                    probe_mode=probe_mode,
                    pause_ms=pause_ms,
                )
            elif delivery_mode == "halfclose_probe_h1":
                _execute_halfclose_probe_h1(
                    sock,
                    stripped_wire,
                    result=result,
                    canary=canary,
                    timeout=timeout,
                    start=start,
                )
            else:
                _execute_oneshot_h1(
                    sock,
                    stripped_wire,
                    result=result,
                    canary=canary,
                    timeout=timeout,
                    start=start,
                )
        except socket.timeout:
            result["timeout_phase"] = result["timeout_phase"] or "runtime"
        except Exception as exc:  # pragma: no cover - defensive
            result["parse_error"] = result["parse_error"] or f"runtime:{exc}"

    result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
    if result["probe_outcome"] == "not_run":
        result["probe_outcome"] = "completed"
    if not result["effective_body_boundary"]:
        result["effective_body_boundary"] = f"sent={result['request_bytes_sent']};responses={result['response_count_observed']}"
    if not result["forwarded_request_hash"]:
        hash_material = (
            f"{result.get('variant_family')}|{result.get('axis_projection')}|"
            f"{result.get('first_response_status')}|{result.get('second_response_status')}|"
            f"{result.get('impact_type')}|{result.get('probe_outcome')}"
        )
        result["forwarded_request_hash"] = hashlib.sha1(
            hash_material.encode("utf-8", errors="replace")
        ).hexdigest()[:20]
    if not result["routing_decision_source"]:
        result["routing_decision_source"] = str(result.get("axis_routing") or "unknown")
    if not result["cache_decision_source"]:
        result["cache_decision_source"] = (
            "trailer"
            if bool(result.get("trailer_forwarded"))
            else str(result.get("axis_routing") or "none")
        )
    return result


def _read_nbytes(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError("persistent client closed")
        buf += chunk
    return buf


def _run_persistent_loop(*, host: str, port: int, timeout: float, artifact_dir: str | None) -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        header = stdin.read(4)
        if len(header) < 4:
            break
        length = struct.unpack(">I", header)[0]
        wire = _read_nbytes(stdin, length)
        exit_code = 0
        try:
            result = execute_wire(
                wire,
                host=host,
                port=port,
                timeout=timeout,
                artifact_dir=artifact_dir,
            )
        except Exception as exc:  # pragma: no cover - defensive
            exit_code = 1
            result = {
                "parse_error": f"persistent:{exc}",
                "probe_outcome": "persistent_exception",
                "request_bytes_sent": 0,
                "artifact_path_stable": "",
                "raw_artifact_path": "",
            }
        payload = json.dumps(result, ensure_ascii=False).encode("utf-8", errors="replace")
        stdout.write(struct.pack(">I", len(payload)))
        stdout.write(payload)
        stdout.write(struct.pack(">I", exit_code))
        stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Request smuggling raw target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--artifact-dir", default=None)
    parser.add_argument("--persistent", action="store_true")
    parser.add_argument("input_file", nargs="?")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.persistent:
        _run_persistent_loop(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            artifact_dir=args.artifact_dir,
        )
        return
    if args.input_file:
        wire = Path(args.input_file).read_bytes()
        result = execute_wire(
            wire,
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            artifact_dir=args.artifact_dir,
            artifact_path=str(Path(args.input_file).resolve()),
        )
        print(json.dumps(result, ensure_ascii=False))
        return

    data = sys.stdin.buffer.read()
    if not data:
        return
    result = execute_wire(
        data,
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        artifact_dir=args.artifact_dir,
    )
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
