"""Tests for JWT target wrappers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_PY_TARGET = ROOT / "targets" / "jwt_python_strict.py"
_SPEC = importlib.util.spec_from_file_location("jwt_python_strict", _PY_TARGET)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
verify_jwt = _MODULE.verify_jwt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _json_segment(obj: dict, raw: str | None = None) -> str:
    if raw is not None:
        return _b64url(raw.encode("utf-8"))
    return _b64url(json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))


def _sign_hs256(header: dict, payload: dict, secret: bytes = b"secret") -> str:
    encoded_header = _json_segment(header)
    encoded_payload = _json_segment(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url(signature)}"


def _make_nested_plainjwt_jwe(payload: dict) -> str:
    inner_header = {"alg": "none", "typ": "JWT"}
    inner_token = f"{_json_segment(inner_header)}.{_json_segment(payload)}."
    outer_header = {"alg": "RSA-OAEP", "enc": "A256GCM", "cty": "JWT", "typ": "JWT"}
    return ".".join(
        [
            _json_segment(outer_header),
            _b64url(b"encrypted-key"),
            _b64url(b"iv"),
            _b64url(inner_token.encode("utf-8")),
            _b64url(b"tag"),
        ]
    )


class TestJwtPythonStrictTarget:
    def test_accepts_valid_hs256(self):
        token = _sign_hs256(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "user-1", "role": "user"},
        )
        result = json.loads(verify_jwt(token))
        assert result["signature_valid"] is True
        assert result["key_source"] == "configured"
        assert result["token_type_observed"] == "jws"


class TestJwtPac4jLikeTarget:
    def test_accepts_nested_plainjwt_without_inner_signature(self):
        token = _make_nested_plainjwt_jwe({"sub": "admin", "role": "admin"})
        path = _write_temp(token)
        try:
            proc = subprocess.run(
                ["node", str(ROOT / "targets" / "jwt_node_pac4j_like.js"), str(path)],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            result = json.loads(proc.stdout)
            assert result["signature_valid"] is True
            assert result["token_type_expected"] == "nested_jws"
            assert result["token_type_observed"] == "jwe"
            assert result["nested_jwt"] is True
            assert result["inner_alg"] == "none"
            assert result["inner_signature_valid"] is None
            assert result["sub"] == "admin"
        finally:
            path.unlink(missing_ok=True)


def _write_temp(token: str) -> Path:
    fd, path = tempfile.mkstemp(prefix="jwt-target-", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token)
    return Path(path)
