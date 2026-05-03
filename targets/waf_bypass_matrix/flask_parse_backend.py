"""Flask/Werkzeug parse echo backend for WAF bypass finding validation.

Uses Werkzeug's production-grade multipart/form/JSON parser so we can observe
what Python web apps actually see after WAF bypass.

Port: 19111
Usage: flask run --host 0.0.0.0 --port 5000  (or direct: python flask_parse_backend.py)
"""

from __future__ import annotations

import json
from typing import Any

from flask import Flask, Response, jsonify, request

app = Flask(__name__)
# Cap request body to avoid Werkzeug swallowing huge buffers on long runs
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MiB


def _flatten_json(obj: Any, prefix: str = "", depth: int = 6) -> dict[str, list[str]]:
    if depth <= 0:
        return {}
    result: dict[str, list[str]] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            result.update(_flatten_json(v, key, depth - 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]" if prefix else f"[{i}]"
            result.update(_flatten_json(v, key, depth - 1))
    else:
        result.setdefault(prefix or "_root", []).append(str(obj) if obj is not None else "")
    return result


def _detect_format() -> str:
    ct = (request.content_type or "").lower()
    if ct.startswith("multipart/form-data"):
        return "multipart"
    if ct.startswith("application/x-www-form-urlencoded"):
        return "form"
    if "json" in ct:
        return "json"
    return "unknown"


@app.route("/health")
def health() -> Response:
    return jsonify({"status": "ok"})


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
def echo(path: str) -> Response:
    fmt = _detect_format()
    fields: dict[str, list[str]] = {}
    parse_status = "ok"
    parse_error = ""

    try:
        if fmt in ("form", "multipart"):
            # Werkzeug parses form + files
            for k in request.form:
                fields[k] = request.form.getlist(k)
            for k, fobj in request.files.items():
                val = fobj.read().decode("latin-1", errors="replace")[:500]
                fields.setdefault(k, []).append(val)
        elif fmt == "json":
            obj = request.get_json(force=True, silent=True)
            if obj is not None:
                fields = _flatten_json(obj)
            else:
                parse_status = "error"
                parse_error = "json decode failed"
        else:
            # Try raw body as form anyway (some bypass techniques confuse CT)
            raw = request.get_data(as_text=False)
            if raw:
                import urllib.parse
                text = raw.decode("latin-1", errors="replace")
                parsed = urllib.parse.parse_qs(text, keep_blank_values=True)
                if parsed:
                    fields = parsed
                    fmt = "form_raw"
                else:
                    parse_status = "skip"
    except Exception as exc:
        parse_status = "error"
        parse_error = str(exc)[:200]

    field_count = len(fields)
    field_names = list(fields.keys())[:20]

    safe_fields = {k: [v[:500] for v in vs] for k, vs in fields.items()}
    resp_obj: dict[str, Any] = {
        "status": parse_status,
        "format": fmt,
        "fields": safe_fields,
        "field_count": field_count,
    }
    if parse_error:
        resp_obj["error"] = parse_error

    resp = jsonify(resp_obj)
    resp.headers["X-Backend-Reached"] = "true"
    resp.headers["X-Parse-Status"] = parse_status
    resp.headers["X-Parse-Format"] = fmt
    resp.headers["X-Parsed-Field-Count"] = str(field_count)
    resp.headers["X-Parsed-Field-Names"] = ",".join(field_names)
    if parse_error:
        resp.headers["X-Parse-Error"] = parse_error[:200]

    for name in field_names[:10]:
        vals = fields.get(name, [])
        if vals:
            safe_name = name[:30].encode("ascii", errors="replace").decode()
            safe_val = vals[0][:100].encode("ascii", errors="replace").decode()
            resp.headers[f"X-Parsed-{safe_name}"] = safe_val

    return resp


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    print(f"Flask parse backend listening on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True)
