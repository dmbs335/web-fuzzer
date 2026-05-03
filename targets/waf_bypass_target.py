"""WAF bypass differential target — send raw HTTP to WAF-protected endpoint, analyze response."""

from __future__ import annotations

import argparse
import base64
import json
import socket
import struct
import sys
import time
import zlib
from pathlib import Path

try:
    import hpack as _hpack
    _HPACK_AVAILABLE = True
except ImportError:
    _hpack = None  # type: ignore[assignment]
    _HPACK_AVAILABLE = False

# H2c client preface — every H2c Prior Knowledge connection starts with this.
H2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

WAF_BLOCK_STATUSES = {400, 403, 406, 418, 429, 493}


def _split_header_block(data: bytes) -> tuple[bytes, bytes, bytes]:
    if b"\r\n\r\n" in data:
        head, rest = data.split(b"\r\n\r\n", 1)
        return head, rest, b"\r\n"
    if b"\n\n" in data:
        head, rest = data.split(b"\n\n", 1)
        return head, rest, b"\n"
    if b"\r\r" in data:
        head, rest = data.split(b"\r\r", 1)
        return head, rest, b"\r"
    raise ValueError("missing header terminator")


def _extract_control(wire: bytes) -> tuple[dict[str, object], bytes]:
    """Strip X-WF-* control headers from raw wire bytes, return (meta, stripped_wire).

    Handles two wire formats:

    H1 format (normal)::

        GET /path HTTP/1.1\\r\\n
        X-WF-Family: some_family\\r\\n
        Host: target.local\\r\\n
        \\r\\n
        [body]

    H2 envelope format (H2c with control metadata prepended)::

        X-WF-Family: h2_header_inject_crlf\\r\\n
        X-WF-Canary-Marker: abc123\\r\\n
        ...\\r\\n
        \\r\\n
        PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n[H2 frames]

    In the H2 envelope case ``lines[0]`` starts with ``x-wf-`` (not a request
    line), so ``stripped_wire`` is the raw ``rest`` (pure H2 binary).
    """
    head, rest, delim = _split_header_block(wire)
    lines = head.split(delim)
    if not lines:
        raise ValueError("empty request")
    # H2 envelope detection: first line is an X-WF-* control header, not a
    # request line.  For H2, stripped_wire = rest (the pure H2 binary).
    is_h2_envelope = lines[0].lower().startswith(b"x-wf-")
    kept = [] if is_h2_envelope else [lines[0]]
    meta: dict[str, object] = {
        "request_id": "",
        "variant_family": "unknown",
        "taxonomy_tags": [],
        "canary_marker": "",
        "payload_type": "",
        "payload_b64": "",
        "axis_evasion": "unknown",
        "axis_payload": "unknown",
        "axis_depth": "unknown",
        "axis_parser": "unknown",
        "axis_variant": "unknown",
    }
    # For H2 envelope, process ALL lines (including lines[0]); for H1, skip the
    # request line (lines[0]) which was already added to kept above.
    loop_lines = lines if is_h2_envelope else lines[1:]
    for raw_line in loop_lines:
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
        if lower.startswith(b"x-wf-canary-marker:") or lower.startswith(b"x-wf-canary:"):
            meta["canary_marker"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-payload-type:"):
            meta["payload_type"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-payload:"):
            meta["payload_b64"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-evasion:"):
            meta["axis_evasion"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-payload:"):
            meta["axis_payload"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-depth:"):
            meta["axis_depth"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-parser:"):
            meta["axis_parser"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-axis-variant:"):
            meta["axis_variant"] = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            continue
        if lower.startswith(b"x-wf-transforms:"):
            raw_val = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            meta["applied_transforms"] = sorted(t.strip() for t in raw_val.split(",") if t.strip())
            continue
        if lower.startswith(b"x-wf-chain-depth:"):
            try:
                meta["chain_depth"] = int(raw_line.split(b":", 1)[1].strip())
            except (ValueError, IndexError):
                meta["chain_depth"] = 0
            continue
        if lower.startswith(b"x-wf-chain-layers:"):
            raw_val = raw_line.split(b":", 1)[1].strip().decode("ascii", errors="replace")
            meta["chain_layers"] = raw_val
            continue
        # Strip any remaining X-WF-* headers not explicitly handled
        if lower.startswith(b"x-wf-"):
            continue
        kept.append(raw_line)
    # H2 envelope: rest IS the pure H2 binary — return it directly.
    # H1: reconstruct the stripped request (kept headers + body).
    if is_h2_envelope:
        stripped = rest
    else:
        stripped = delim.join(kept) + delim + delim + rest
    return meta, stripped


def _extract_wire_enrichment(stripped_wire: bytes) -> dict[str, object]:
    """Extract protocol-level enrichment from the stripped wire (after X-WF-* removal)."""
    enrichment: dict[str, object] = {"encoding_depth": 0}

    # H2c Prior Knowledge: stripped wire is the raw H2 binary.
    # Skip H1 header parsing entirely and return H2-specific enrichment.
    if stripped_wire.startswith(H2_CLIENT_PREFACE):
        enrichment["transport_mode"] = "h2c"
        enrichment["body_structure"] = "h2"
        enrichment["http_version"] = "HTTP/2.0"
        enrichment["h2_variant"] = _detect_h2_variant(stripped_wire)
        return enrichment

    try:
        head, _rest, delim = _split_header_block(stripped_wire)
    except ValueError:
        return enrichment
    lines = head.split(delim)
    if lines:
        parts = lines[0].split(b" ")
        if len(parts) >= 2:
            enrichment["url_path"] = parts[1].decode("latin-1", errors="replace")
        if len(parts) >= 3:
            enrichment["http_version"] = parts[2].decode("latin-1", errors="replace").strip()
        else:
            enrichment["http_version"] = "HTTP/1.1"
    te_parts: list[str] = []
    ce_parts: list[str] = []
    non_control_count = 0
    has_null = False
    ct_count = 0
    cl_count = 0
    te_count = 0
    has_cl = False
    charset_declared = ""
    first_cl_val = 0
    method_override = ""
    te_raw_values: list[str] = []
    for raw_line in lines[1:]:
        lower = raw_line.lower()
        if b"\x00" in raw_line:
            has_null = True
        if not lower.startswith(b"x-wf-"):
            non_control_count += 1
        if lower.startswith(b"content-type:"):
            ct_count += 1
            ct_val = raw_line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
            enrichment["content_type_sent"] = ct_val
            for param in ct_val.split(";"):
                p = param.strip()
                if p.lower().startswith("boundary="):
                    enrichment["boundary_used"] = p.split("=", 1)[1].strip().strip('"')
                elif p.lower().startswith("charset="):
                    charset_declared = p.split("=", 1)[1].strip().strip('"')
        elif lower.startswith(b"content-length:"):
            cl_count += 1
            has_cl = True
            try:
                if cl_count == 1:
                    first_cl_val = int(raw_line.split(b":", 1)[1].strip())
            except (ValueError, IndexError):
                pass
        elif lower.startswith(b"transfer-encoding:"):
            te_count += 1
            te_raw_val = raw_line.split(b":", 1)[1].decode("latin-1", errors="replace")
            te_raw_values.append(te_raw_val.strip())
            for v in te_raw_val.split(","):
                v = v.strip()
                if v and v.lower() != "identity":
                    te_parts.append(v)
        elif lower.startswith(b"content-encoding:"):
            for v in raw_line.split(b":", 1)[1].decode("latin-1", errors="replace").split(","):
                v = v.strip()
                if v and v.lower() != "identity":
                    ce_parts.append(v)
        # Method override headers
        for prefix in (b"x-http-method-override:", b"x-method-override:", b"x-http-method:"):
            if lower.startswith(prefix):
                method_override = raw_line.split(b":", 1)[1].strip().decode("latin-1", errors="replace")
                break
    chain = te_parts + ce_parts
    if chain:
        enrichment["encoding_chain"] = "+".join(chain)
    enrichment["encoding_depth"] = len(chain)

    # v3.3 enrichment: method override and TE variation
    enrichment["method_override"] = method_override
    te_variation = ""
    for raw_te in te_raw_values:
        if raw_te.lower().strip() == "chunked" and raw_te != "chunked":
            te_variation = raw_te
            break
    enrichment["te_variation"] = te_variation

    # Chain enrichment
    enrichment["ct_count"] = ct_count
    enrichment["cl_te_conflict"] = has_cl and bool(te_parts)
    enrichment["charset_declared"] = charset_declared

    # Structural enrichment for coverage features
    enrichment["header_count"] = non_control_count
    enrichment["has_null_bytes"] = has_null

    # Body structure classification
    ct_sent = str(enrichment.get("content_type_sent") or "").lower()
    has_te = bool(te_parts)
    has_boundary = "boundary_used" in enrichment
    if has_te and "chunked" in " ".join(te_parts).lower():
        enrichment["body_structure"] = "chunked"
    elif "multipart" in ct_sent and has_boundary:
        enrichment["body_structure"] = "multipart"
    elif "json" in ct_sent:
        enrichment["body_structure"] = "json"
    elif "xml" in ct_sent:
        enrichment["body_structure"] = "xml"
    elif "urlencoded" in ct_sent or "form" in ct_sent:
        enrichment["body_structure"] = "form"
    elif not ct_sent and _looks_like_json(_rest):
        # CT removal smuggle: body sniffs as JSON but no Content-Type header
        enrichment["body_structure"] = "json"
    else:
        enrichment["body_structure"] = "raw"

    # Line terminator type
    if delim == b"\r\n":
        # Check for mixed: any bare LF in the header block?
        bare_lf = head.replace(b"\r\n", b"").count(b"\n")
        bare_cr = head.replace(b"\r\n", b"").count(b"\r")
        if bare_lf > 0 or bare_cr > 0:
            enrichment["lt_type"] = "mixed"
        else:
            enrichment["lt_type"] = "crlf"
    elif delim == b"\n":
        enrichment["lt_type"] = "lf"
    else:
        enrichment["lt_type"] = "other"

    # HRS-derived enrichment: duplicate framing, trailers, chunk quirks, zero-body
    enrichment["duplicate_cl"] = cl_count > 1
    enrichment["duplicate_te"] = te_count > 1

    # Trailer detection: data between 0-chunk and final CRLFCRLF in chunked body
    has_trailers = False
    trailer_names = ""
    is_chunked = has_te and "chunked" in " ".join(te_parts).lower()
    rest = _rest  # body from _split_header_block
    if is_chunked and rest:
        zero_markers = (b"0\r\n", b"0\n")
        for zm in zero_markers:
            pos = rest.find(zm)
            if pos >= 0:
                after_zero = rest[pos + len(zm):]
                # If there's non-empty content before the final empty line, those are trailers
                term = b"\r\n\r\n" if b"\r\n\r\n" in after_zero else b"\n\n"
                if term in after_zero:
                    trailer_block = after_zero[:after_zero.index(term)]
                    if trailer_block.strip():
                        has_trailers = True
                        names = []
                        for tl in trailer_block.split(b"\r\n" if b"\r\n" in trailer_block else b"\n"):
                            if b":" in tl:
                                names.append(tl.split(b":", 1)[0].strip().decode("latin-1", errors="replace").lower())
                        trailer_names = ",".join(names)
                break
    enrichment["has_trailers"] = has_trailers
    enrichment["trailer_names"] = trailer_names

    # Chunk quirk detection
    chunk_quirks: list[str] = []
    if is_chunked and rest:
        # Check first line of body for chunk size quirks
        first_line_end = rest.find(b"\r\n") if b"\r\n" in rest else rest.find(b"\n")
        if first_line_end > 0:
            chunk_line = rest[:first_line_end]
            size_part = chunk_line.split(b";", 1)[0]  # strip extensions
            if size_part != size_part.strip():
                chunk_quirks.append("ws")
            if len(size_part.strip()) > 1 and size_part.strip().startswith(b"0"):
                chunk_quirks.append("zeros")
        # Extra terminator: 0\r\n followed by more than one CRLFCRLF
        if rest.count(b"\r\n\r\n") > 1 or rest.endswith(b"\r\n\r\n\r\n"):
            chunk_quirks.append("extra_term")
    enrichment["chunk_quirk_type"] = ",".join(chunk_quirks)

    # Zero-body detection
    zero_body_type = ""
    if has_cl and first_cl_val == 0 and rest:
        zero_body_type = "cl0"
    elif is_chunked and rest and rest.lstrip().startswith(b"0"):
        # Immediate 0-chunk but body has more data after
        for zm in (b"0\r\n\r\n", b"0\n\n"):
            if rest.startswith(zm) and len(rest) > len(zm):
                zero_body_type = "te0"
                break
    enrichment["zero_body_type"] = zero_body_type

    # v3.4: XML variant detection
    xml_variant = ""
    if enrichment.get("body_structure") == "xml" and rest:
        xml_variants = []
        body_head = rest[:2048]
        if b"<!DOCTYPE" in body_head:
            xml_variants.append("doctype")
        if b"<![CDATA[" in body_head:
            xml_variants.append("cdata")
        # Duplicate xmlns detection: count xmlns attributes
        if body_head.lower().count(b"xmlns:") >= 2:
            xml_variants.append("schema")
        # Attribute-value injection: first element has attributes
        lt_pos = body_head.find(b"<")
        if lt_pos >= 0:
            gt_pos = body_head.find(b">", lt_pos)
            if gt_pos > lt_pos:
                first_tag = body_head[lt_pos:gt_pos]
                if b"=" in first_tag and b'"' in first_tag:
                    xml_variants.append("attribute")
        # Newline-abuse: non-standard whitespace in body
        if any(b in body_head for b in (b"\x0b", b"\x0c")):
            xml_variants.append("newline")
        # Extra-field heuristic: more than one top-level element-ish shape
        if body_head.count(b"</") >= 2:
            xml_variants.append("multi_field")
        xml_variant = ",".join(xml_variants)
    enrichment["xml_variant"] = xml_variant

    # v3.4: JSON quirk detection
    json_quirk_type = ""
    if enrichment.get("body_structure") == "json" and rest:
        quirks = []
        body_head = rest[:2048]
        if not ct_sent:
            quirks.append("ct_removed")
        # Null bytes between quoted key and colon: "key"\x00:
        if b'"\x00:' in body_head or b'"\x00 :' in body_head:
            quirks.append("field_wrapper")
        # Null bytes inside a JSON key: "foo\x00bar"
        if b'"' in body_head and b"\x00" in body_head:
            # Heuristic: a double-quoted segment containing \x00 followed by "
            idx = 0
            while True:
                open_q = body_head.find(b'"', idx)
                if open_q < 0:
                    break
                close_q = body_head.find(b'"', open_q + 1)
                if close_q < 0:
                    break
                if b"\x00" in body_head[open_q + 1:close_q]:
                    quirks.append("field_name_null")
                    break
                idx = close_q + 1
        # Bare-identifier / single-quote JSON (RFC 8259 violation)
        stripped_body = body_head.lstrip()
        if stripped_body.startswith(b"{"):
            inner = stripped_body[1:].lstrip()
            if inner.startswith(b"'"):
                quirks.append("quote_replace")
            elif inner and inner[0:1].isalpha():
                # bare identifier key like {foo: "bar"}
                quirks.append("quote_replace")
        json_quirk_type = ",".join(sorted(set(quirks)))
    enrichment["json_quirk_type"] = json_quirk_type

    # v3.4: Encoding overflow / 2024 smuggling variant detection
    enc_overflow_type = ""
    overflow_flags = []
    for te_raw in te_raw_values:
        if te_raw.strip() == "0":
            overflow_flags.append("te_zero")
            break
    # Chunk size overflow: 8+ hex digit size on first chunk line
    if is_chunked and rest:
        first_line_end = rest.find(b"\r\n") if b"\r\n" in rest else rest.find(b"\n")
        if first_line_end > 0:
            chunk_line = rest[:first_line_end]
            size_part = chunk_line.split(b";", 1)[0].strip()
            try:
                size_txt = size_part.decode("ascii", errors="replace")
                if len(size_txt) >= 8 and all(c in "0123456789abcdefABCDEF" for c in size_txt):
                    size_int = int(size_txt, 16)
                    if size_int >= 0xFFFFFFFF:
                        overflow_flags.append("chunk_overflow")
            except (ValueError, UnicodeDecodeError):
                pass
    # 0.CL smuggle: CL=0 but body is non-trivial (contains HTTP request-line-ish shape)
    if has_cl and first_cl_val == 0 and rest and len(rest.strip()) > 0:
        body_head = rest.strip()[:128]
        if b" HTTP/" in body_head or b"\r\n\r\n" in rest:
            overflow_flags.append("zero_cl")
    enc_overflow_type = ",".join(overflow_flags)
    enrichment["enc_overflow_type"] = enc_overflow_type

    return enrichment


def _looks_like_json(body: bytes) -> bool:
    """Lightweight content-sniff for JSON when no Content-Type header is set."""
    if not body:
        return False
    stripped = body.lstrip()[:64]
    return stripped.startswith(b"{") or stripped.startswith(b"[")


def _detect_h2_variant(wire: bytes) -> str:
    """Identify the H2 bypass technique used in *wire* by HPACK-decoding the first HEADERS frame.

    Returns one of: ``"header_crlf"``, ``"cl_zero_body"``, ``"te_forbidden"``,
    ``"path_inject"``, ``"authority_mismatch"``, ``"scheme_mismatch"``, or ``""``
    if the technique cannot be determined (hpack unavailable or parse error).
    """
    if not _HPACK_AVAILABLE:
        return ""
    # Scan frames after the 24-byte client preface.
    pos = len(H2_CLIENT_PREFACE)
    while pos + 9 <= len(wire):
        frame_len = (wire[pos] << 16) | (wire[pos + 1] << 8) | wire[pos + 2]
        type_id = wire[pos + 3]
        pos += 9  # skip 9-byte frame header
        payload_end = pos + frame_len
        if payload_end > len(wire):
            break
        if type_id == 0x1:  # HEADERS frame
            payload = wire[pos:payload_end]
            try:
                dec = _hpack.Decoder()
                # Keep FIRST value for each header name (duplicates are valid in
                # H2 but the detection logic cares about presence, not last value).
                headers: dict[str, str] = {}
                for raw_name, raw_val in dec.decode(payload):
                    name = raw_name.decode("utf-8", errors="replace") if isinstance(raw_name, bytes) else raw_name
                    val = raw_val.decode("utf-8", errors="replace") if isinstance(raw_val, bytes) else raw_val
                    headers.setdefault(name, val)
            except Exception:
                break
            if "x-wf-crlf-inject" in headers:
                return "header_crlf"
            scheme = headers.get(":scheme", "")
            if scheme not in ("http", "https"):
                return "scheme_mismatch"
            authority = headers.get(":authority", "")
            host = headers.get("host", "")
            if host and authority and host != authority:
                return "authority_mismatch"
            path = headers.get(":path", "")
            if "\r\n" in path or " HTTP/" in path:
                return "path_inject"
            if "transfer-encoding" in headers:
                return "te_forbidden"
            if headers.get("content-length") == "0":
                return "cl_zero_body"
            break
        pos = payload_end
    return ""


def _parse_h2_response(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    """Parse raw H2 response bytes into (status_code, headers_dict, body).

    Returns (-1, {}, b"") on parse failure or if hpack is unavailable.
    Best-effort: stops on truncated frame.
    """
    if not _HPACK_AVAILABLE:
        return -1, {}, b""
    status = -1
    resp_headers: dict[str, str] = {}
    body_parts: list[bytes] = []
    try:
        dec = _hpack.Decoder()
        pos = 0
        while pos + 9 <= len(raw):
            frame_len = (raw[pos] << 16) | (raw[pos + 1] << 8) | raw[pos + 2]
            type_id = raw[pos + 3]
            payload_end = pos + 9 + frame_len
            if payload_end > len(raw):
                break
            payload = raw[pos + 9:payload_end]
            if type_id == 0x1:  # HEADERS
                try:
                    hdrs = dec.decode(payload)
                    for name, value in hdrs:
                        if isinstance(name, bytes):
                            name = name.decode("utf-8", errors="replace")
                        if isinstance(value, bytes):
                            value = value.decode("utf-8", errors="replace")
                        if name == ":status":
                            try:
                                status = int(value)
                            except ValueError:
                                pass
                        else:
                            resp_headers[name] = value
                except Exception:
                    pass
            elif type_id == 0x0:  # DATA
                body_parts.append(payload)
            elif type_id == 0x3:  # RST_STREAM — server rejected the stream
                # Treat as a protocol-level rejection (400) so waf_blocked=True
                # is set correctly.  Without this, status stays -1 → None →
                # waf_blocked=False, creating spurious bypass findings.
                if status == -1:
                    status = 400
            pos = payload_end
    except Exception:
        pass
    return status, resp_headers, b"".join(body_parts)


def _h2c_end_stream_received(raw: bytes) -> bool:
    """Return True once a DATA or HEADERS frame with END_STREAM (0x1) on stream 1 is seen.

    Used to terminate the H2c recv loop early instead of waiting for the full
    socket timeout — H2 servers keep the connection alive after responding.
    """
    pos = 0
    while pos + 9 <= len(raw):
        frame_len = (raw[pos] << 16) | (raw[pos + 1] << 8) | raw[pos + 2]
        type_id = raw[pos + 3]
        flags = raw[pos + 4]
        stream_id = struct.unpack(">I", raw[pos + 5:pos + 9])[0] & 0x7FFFFFFF
        payload_end = pos + 9 + frame_len
        if payload_end > len(raw):
            break  # truncated frame — need more data
        if stream_id == 1 and type_id in (0x0, 0x1) and (flags & 0x1):
            return True
        pos = payload_end
    return False


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


def _analyze_response(
    meta: dict[str, object],
    response: dict[str, object],
    *,
    elapsed_ms: float,
    request_bytes_sent: int,
    wire_enrichment: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the full result dict from parsed response and control metadata."""
    status = response["status"]
    headers = response["headers"]
    body = bytes(response["body"])
    body_text = body.decode("utf-8", errors="replace")

    # WAF detection
    waf_blocked = status in WAF_BLOCK_STATUSES if status is not None else False
    waf_block_status = status if waf_blocked else None

    # Extract WAF-specific headers
    waf_headers: dict[str, str] = {}
    for k, v in headers.items():
        kl = k.lower()
        if kl.startswith("x-coraza") or kl.startswith("x-modsecurity") or kl == "server":
            waf_headers[kl] = v

    # Detect WAF product signature
    server_val = str(waf_headers.get("server", "")).lower()
    if "coraza" in server_val:
        waf_signature = "coraza"
    elif "modsecurity" in body_text.lower():
        waf_signature = "modsecurity"
    else:
        waf_signature = ""

    # Backend marker detection
    backend_reached = "x-backend-marker" in headers
    backend_marker = str(headers.get("x-backend-marker", ""))

    # Payload and canary reflection
    canary = str(meta.get("canary_marker") or "")
    payload_b64 = str(meta.get("payload_b64") or "")
    try:
        payload_bytes = base64.b64decode(payload_b64) if payload_b64 else b""
    except Exception:
        payload_bytes = b""

    payload_reflected = bool(payload_bytes) and payload_bytes in body
    canary_in_body = bool(canary) and canary.encode() in body
    canary_in_headers = bool(canary) and canary in str(headers)
    bypass_detected = (not waf_blocked) and (payload_reflected or canary_in_body)

    result = {
        # Metadata (forwarded from X-WF-*)
        "request_id": meta.get("request_id", ""),
        "variant_family": meta.get("variant_family", "unknown"),
        "taxonomy_tags": meta.get("taxonomy_tags", []),
        "payload_type": meta.get("payload_type", ""),
        "canary_marker": canary,
        "axis_evasion": meta.get("axis_evasion", "unknown"),
        "axis_payload": meta.get("axis_payload", "unknown"),
        "axis_depth": meta.get("axis_depth", "unknown"),
        "axis_parser": meta.get("axis_parser", "unknown"),
        "axis_variant": meta.get("axis_variant", "unknown"),

        # Response analysis
        "response_status": status,
        "response_headers": dict(headers),
        "response_body_prefix": body_text[:512],
        "response_body_crc32": (zlib.crc32(body) & 0xFFFFFFFF) if body else None,
        "response_body_length": len(body),
        "duration_ms": round(elapsed_ms, 2),

        # WAF detection
        "waf_blocked": waf_blocked,
        "waf_block_status": waf_block_status,
        "waf_headers": waf_headers,
        "waf_signature": waf_signature,

        # Backend detection
        "backend_reached": backend_reached,
        "backend_marker": backend_marker,

        # Bypass signal
        "payload_reflected": payload_reflected,
        "canary_in_body": canary_in_body,
        "canary_in_headers": canary_in_headers,
        "bypass_detected": bypass_detected,

        # Connection state
        "connection_closed": bool(response["closed"]),
        "timeout_phase": None,
        "parse_error": None,
        "request_bytes_sent": request_bytes_sent,

        # Wire enrichment defaults
        "content_type_sent": "",
        "content_type_parsed": "",
        "boundary_used": "",
        "boundary_parsed": "",
        "encoding_chain": "",
        "encoding_depth": 0,
        "url_path": "",
        "url_path_raw": "",
        "path_normalized": "",
        "path_raw": "",
        "headers_normalized": False,
        "payload_in_header": False,
        "has_trailers": False,
        "trailer_names": "",
        "duplicate_cl": False,
        "duplicate_te": False,
        "chunk_quirk_type": "",
        "zero_body_type": "",
        "http_version": "HTTP/1.1",
        "method_override": "",
        "te_variation": "",
        "xml_variant": "",
        "json_quirk_type": "",
        "enc_overflow_type": "",
        "transport_mode": "",
        "h2_variant": "",
    }

    # Merge wire-side enrichment
    if wire_enrichment:
        result.update(wire_enrichment)

    # Response-side enrichment from backend echo headers
    echoed_ct = headers.get("x-echoed-content-type", "")
    if echoed_ct:
        result["content_type_parsed"] = echoed_ct
        for param in echoed_ct.split(";"):
            p = param.strip()
            if p.lower().startswith("boundary="):
                result["boundary_parsed"] = p.split("=", 1)[1].strip().strip('"')

    echoed_path = headers.get("x-echoed-request-path", "")
    if echoed_path:
        result["path_normalized"] = echoed_path

    ct_sent = result.get("content_type_sent", "")
    ct_parsed = result.get("content_type_parsed", "")
    result["headers_normalized"] = bool(
        ct_sent and ct_parsed
        and str(ct_sent).strip().lower() != str(ct_parsed).strip().lower()
    )
    result["payload_in_header"] = bool(canary) and any(
        canary in str(v) for v in headers.values()
    )

    # Aliases for strategy compatibility
    result["url_path_raw"] = result.get("url_path", "")
    result["path_raw"] = result.get("url_path", "")

    # Forward applied_transforms from control metadata
    result["applied_transforms"] = meta.get("applied_transforms", [])

    # Chain fields from control metadata
    result["chain_depth"] = meta.get("chain_depth", 0)
    result["chain_layers"] = meta.get("chain_layers", "")
    result["technique_family"] = meta.get("variant_family", "unknown")

    return result


def _empty_result(meta: dict[str, object]) -> dict[str, object]:
    """Return a result dict with all keys populated to defaults (for error paths)."""
    return {
        "request_id": meta.get("request_id", ""),
        "variant_family": meta.get("variant_family", "unknown"),
        "taxonomy_tags": meta.get("taxonomy_tags", []),
        "payload_type": meta.get("payload_type", ""),
        "canary_marker": str(meta.get("canary_marker") or ""),
        "axis_evasion": meta.get("axis_evasion", "unknown"),
        "axis_payload": meta.get("axis_payload", "unknown"),
        "axis_depth": meta.get("axis_depth", "unknown"),
        "axis_parser": meta.get("axis_parser", "unknown"),
        "axis_variant": meta.get("axis_variant", "unknown"),
        "response_status": None,
        "response_headers": {},
        "response_body_prefix": "",
        "response_body_crc32": None,
        "response_body_length": 0,
        "duration_ms": 0.0,
        "waf_blocked": False,
        "waf_block_status": None,
        "waf_headers": {},
        "waf_signature": "",
        "backend_reached": False,
        "backend_marker": "",
        "payload_reflected": False,
        "canary_in_body": False,
        "canary_in_headers": False,
        "bypass_detected": False,
        "connection_closed": False,
        "timeout_phase": None,
        "parse_error": None,
        "request_bytes_sent": 0,
        "content_type_sent": "",
        "content_type_parsed": "",
        "boundary_used": "",
        "boundary_parsed": "",
        "encoding_chain": "",
        "encoding_depth": 0,
        "url_path": "",
        "url_path_raw": "",
        "path_normalized": "",
        "path_raw": "",
        "headers_normalized": False,
        "payload_in_header": False,
        "header_count": 0,
        "body_structure": "raw",
        "lt_type": "crlf",
        "has_null_bytes": False,
        "applied_transforms": [],
        "chain_depth": 0,
        "chain_layers": "",
        "technique_family": "unknown",
        "ct_count": 1,
        "cl_te_conflict": False,
        "charset_declared": "",
        "has_trailers": False,
        "trailer_names": "",
        "duplicate_cl": False,
        "duplicate_te": False,
        "chunk_quirk_type": "",
        "zero_body_type": "",
        "http_version": "HTTP/1.1",
        "method_override": "",
        "te_variation": "",
        "xml_variant": "",
        "json_quirk_type": "",
        "enc_overflow_type": "",
        "transport_mode": "",
        "h2_variant": "",
    }


def execute_wire(
    wire: bytes,
    *,
    host: str,
    port: int,
    timeout: float = 2.0,
) -> dict[str, object]:
    meta, stripped_wire = _extract_control(wire)
    wire_enrichment = _extract_wire_enrichment(stripped_wire)
    start = time.monotonic()

    result = _empty_result(meta)
    result.update(wire_enrichment)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)

        # Connect
        try:
            sock.connect((host, port))
        except socket.timeout:
            result["timeout_phase"] = "connect"
            result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            return result
        except OSError as exc:
            result["parse_error"] = f"connect:{exc}"
            result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            return result

        # Send
        try:
            sock.sendall(stripped_wire)
            result["request_bytes_sent"] = len(stripped_wire)
        except socket.timeout:
            result["timeout_phase"] = "send"
            result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            return result
        except OSError as exc:
            result["parse_error"] = f"send:{exc}"
            result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
            return result

        # Receive and parse
        if stripped_wire.startswith(H2_CLIENT_PREFACE):
            # H2c Prior Knowledge: recv raw bytes and parse H2 frames.
            # Stop as soon as a DATA or HEADERS frame with END_STREAM is
            # received on stream 1 — the server keeps the connection alive
            # (H2 keepalive), so waiting for EOF would block for the full
            # timeout period on every request.
            raw_h2_resp = b""
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    raw_h2_resp += chunk
                    if _h2c_end_stream_received(raw_h2_resp):
                        break
            except socket.timeout:
                pass  # use what we received so far
            except OSError as exc:
                result["parse_error"] = f"recv:{exc}"
                result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
                return result
            status, resp_hdrs, resp_body = _parse_h2_response(raw_h2_resp)
            response = {
                "status": status if status != -1 else None,
                "headers": resp_hdrs,
                "body": resp_body,
                "closed": True,
            }
        else:
            buffer = b""
            try:
                response, _leftover = _parse_response(sock, buffer)
            except socket.timeout:
                result["timeout_phase"] = "recv"
                result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
                return result
            except ValueError as exc:
                result["parse_error"] = f"response:{exc}"
                result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
                return result
            except OSError as exc:
                result["parse_error"] = f"recv:{exc}"
                result["duration_ms"] = round((time.monotonic() - start) * 1000, 2)
                return result

    elapsed_ms = (time.monotonic() - start) * 1000
    return _analyze_response(
        meta,
        response,
        elapsed_ms=elapsed_ms,
        request_bytes_sent=len(stripped_wire),
        wire_enrichment=wire_enrichment,
    )


def _read_nbytes(stream, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            raise EOFError("persistent client closed")
        buf += chunk
    return buf


def _run_persistent_loop(*, host: str, port: int, timeout: float) -> None:
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
            )
        except Exception as exc:
            exit_code = 1
            result = {
                "parse_error": f"persistent:{exc}",
                "request_bytes_sent": 0,
                "waf_blocked": False,
                "bypass_detected": False,
            }
        payload = json.dumps(result, ensure_ascii=False).encode("utf-8", errors="replace")
        stdout.write(struct.pack(">I", len(payload)))
        stdout.write(payload)
        stdout.write(struct.pack(">I", exit_code))
        stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="WAF bypass raw target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--persistent", action="store_true")
    parser.add_argument("input_file", nargs="?")
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.persistent:
        _run_persistent_loop(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
        )
        return
    if args.input_file:
        wire = Path(args.input_file).read_bytes()
        result = execute_wire(
            wire,
            host=args.host,
            port=args.port,
            timeout=args.timeout,
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
    )
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
