"""Gunicorn WSGI marker backend.

Mirrors marker_backend.py response format but runs under Gunicorn's
own C-based HTTP parser (http_parser / llhttp depending on version).
"""
import hashlib


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    content_length = int(environ.get("CONTENT_LENGTH") or 0)

    body = b""
    if content_length > 0:
        body = environ["wsgi.input"].read(content_length)

    headers_dict = {}
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            header_name = key[5:].replace("_", "-").lower()
            headers_dict[header_name] = value
    if "CONTENT_TYPE" in environ:
        headers_dict["content-type"] = environ["CONTENT_TYPE"]
    if "CONTENT_LENGTH" in environ:
        headers_dict["content-length"] = environ["CONTENT_LENGTH"]

    host = headers_dict.get("host", "backend")
    te = headers_dict.get("transfer-encoding", "")

    status_code = "200 OK"
    marker = "ok"
    impact = "none"
    detail = "generic"
    routing_source = "request-path"
    cache_source = "request-path"

    if path.startswith("/__canary__/"):
        payload = f"BACKEND-MARKER canary {path}"
        status_code = "404 Not Found"
        marker = "canary"
        impact = "canary"
        detail = path
    elif path.startswith("/early"):
        payload = "BACKEND-MARKER early"
        status_code = "401 Unauthorized"
        marker = "early"
        impact = "acl_bypass"
        detail = "early-gadget"
    elif path.startswith("/cache/store"):
        cache_key = headers_dict.get("x-original-url", path)
        cache_source = "trailer" if "x-original-url" in headers_dict else "header"
        payload = f"BACKEND-MARKER cache IMPACT:cache_poison key={cache_key} source={cache_source}"
        marker = "cache"
        impact = "cache_poison"
        detail = cache_key
    elif path.startswith("/admin/panel"):
        routing_source = "host"
        payload = f"BACKEND-MARKER admin IMPACT:acl_bypass role=backend-admin host={host}"
        status_code = "403 Forbidden"
        marker = "admin"
        impact = "acl_bypass"
        detail = host
    elif path.startswith("/queue/append"):
        routing_source = "queue"
        payload = "BACKEND-MARKER queue IMPACT:response_queue slot=primary"
        status_code = "202 Accepted"
        marker = "queue"
        impact = "response_queue"
        detail = "slot=primary"
    elif path.startswith("/pipeline-victim-"):
        payload = f"BACKEND-MARKER ok Backend saw: {method} {path} HTTP/1.1"
    else:
        payload = f"BACKEND-MARKER ok {body[:32].decode('latin-1', errors='replace')}"

    effective_keys = sorted(
        k for k in ("host", "x-forwarded-host", "x-original-url",
                     "transfer-encoding", "content-length")
        if k in headers_dict
    )
    effective_headers = ";".join(f"{k}={headers_dict[k]}" for k in effective_keys) or "none"

    body_boundary = (
        f"bytes={len(body)};chunked={'chunked' in te.lower()};trailers=0"
    )

    request_line = f"{method} {path} HTTP/1.1"
    hash_material = f"{request_line}|{effective_headers}|{path}|{len(body)}|"
    forwarded_hash = hashlib.sha1(
        hash_material.encode("utf-8", errors="replace")
    ).hexdigest()[:20]

    payload_bytes = payload.encode("utf-8", errors="replace")

    response_headers = [
        ("Content-Length", str(len(payload_bytes))),
        ("X-Backend-Marker", marker),
        ("X-Impact-Marker", impact),
        ("X-Impact-Detail", detail),
        ("X-Forwarded-Request-Line", request_line),
        ("X-Forwarded-Request-Hash", forwarded_hash),
        ("X-Effective-Headers", effective_headers),
        ("X-Body-Boundary", body_boundary),
        ("X-Trailer-Forwarded", "false"),
        ("X-Trailer-Merge", "none"),
        ("X-Routing-Decision-Source", routing_source),
        ("X-Cache-Decision-Source", cache_source),
        ("Connection", "keep-alive"),
    ]

    start_response(status_code, response_headers)
    return [payload_bytes]
