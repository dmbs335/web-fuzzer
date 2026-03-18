"""Tests for the JWT taxonomy-driven mutator."""

import json

from webfuzzer.fuzzer.mutators.jwt_mutator import JwtMutator, _b64url_decode, _parse_compact_jwt
from webfuzzer.fuzzer.protocols import Input


def _decode_segments(token: bytes) -> tuple[bytes, bytes]:
    parts = token.split(b".")
    assert len(parts) == 3
    return _b64url_decode(parts[0]), _b64url_decode(parts[1])


class TestJwtMutator:
    def test_name(self):
        assert JwtMutator().name == "jwt"

    def test_strategy_count(self):
        m = JwtMutator(seed=1)
        assert len(m._strategies) == 59
        assert len(m._weights) == 59

    def test_mutate_bootstraps_seed_token(self):
        m = JwtMutator(seed=1)
        out = m.mutate(Input(data=b"not-a-jwt"), [])
        assert _parse_compact_jwt(out.data) is not None
        assert out.metadata["mutator"] == "jwt"

    def test_alg_none_strategy(self):
        m = JwtMutator(seed=1)
        token, resigned = m._alg_none(b"not-a-jwt", {})
        header_raw, _ = _decode_segments(token)
        assert resigned is False
        assert json.loads(header_raw)["alg"] == "none"
        assert token.endswith(b".")

    def test_rs_to_hs_confusion_resigns(self):
        m = JwtMutator(seed=1)
        token, resigned = m._alg_rs_to_hs_confusion(
            b"not-a-jwt",
            {"jwt_public_key": "PUBLICKEY"},
        )
        header_raw, _ = _decode_segments(token)
        assert resigned is True
        assert json.loads(header_raw)["alg"] == "HS256"
        assert not token.endswith(b".")

    def test_duplicate_role_claim_keeps_raw_duplicates(self):
        m = JwtMutator(seed=1)
        token, _ = m._duplicate_role_claim(b"not-a-jwt", {})
        _, payload_raw = _decode_segments(token)
        assert b'"role":"user"' in payload_raw
        assert b'"role":"admin"' in payload_raw

    def test_b64_false_crit_header_present(self):
        m = JwtMutator(seed=1)
        token, _ = m._b64_false_crit(b"not-a-jwt", {})
        header_raw, _ = _decode_segments(token)
        header = json.loads(header_raw)
        assert header["b64"] is False
        assert header["crit"] == ["b64"]

    def test_embedded_jwk_in_header(self):
        m = JwtMutator(seed=1)
        token, resigned = m._embedded_jwk(b"not-a-jwt", {"jwt_hs_secret": "secret"})
        header_raw, _ = _decode_segments(token)
        header = json.loads(header_raw)
        assert resigned is True
        assert "jwk" in header
        assert header["alg"] == "HS256"

    def test_mutate_sets_strategy_metadata(self):
        m = JwtMutator(seed=7)
        out = m.mutate(Input(data=b"not-a-jwt"), [])
        assert isinstance(out.metadata.get("strategies"), list)
        assert "resigned" in out.metadata

    def test_sentinel_injection_metadata(self):
        m = JwtMutator(seed=42)
        # Run enough mutations to expect sentinel in some
        sentinels = []
        for i in range(100):
            out = m.mutate(Input(data=b"not-a-jwt"), [])
            sentinels.append(out.metadata.get("jwt_evil_sentinel"))
        # Expect ~10% have sentinel
        has_sentinel = [s for s in sentinels if s is not None]
        assert len(has_sentinel) > 0, "Expected some mutations with sentinel"
        assert len(has_sentinel) < 50, "Expected sentinel in ~10% of mutations"

    def test_utf8_bom_payload(self):
        m = JwtMutator(seed=1)
        token, resigned = m._utf8_bom_payload(b"not-a-jwt", {})
        parts = token.split(b".")
        assert len(parts) == 3
        from webfuzzer.fuzzer.mutators.jwt_mutator import _b64url_decode
        payload_raw = _b64url_decode(parts[1])
        assert payload_raw.startswith(b"\xef\xbb\xbf")

    def test_exp_boundary(self):
        m = JwtMutator(seed=1)
        token, resigned = m._exp_boundary(b"not-a-jwt", {})
        assert _parse_compact_jwt(token) is not None
        assert resigned is True

    def test_extra_dot_segment(self):
        m = JwtMutator(seed=1)
        token, resigned = m._extra_dot_segment(b"not-a-jwt", {})
        parts = token.split(b".")
        assert len(parts) == 4

    # ── J8: RFC gap exploitation strategies ──

    def test_duplicate_alg_header(self):
        m = JwtMutator(seed=1)
        token, resigned = m._duplicate_alg_header(b"not-a-jwt", {})
        assert resigned is False
        _, payload = _decode_segments(token)
        # Raw header should contain two "alg" keys
        header_b64 = token.split(b".")[0]
        header_raw = _b64url_decode(header_b64)
        assert header_raw.count(b'"alg"') == 2

    def test_claim_type_confusion(self):
        m = JwtMutator(seed=1)
        token, resigned = m._claim_type_confusion(b"not-a-jwt", {})
        assert resigned is False
        assert token.endswith(b".")

    def test_duplicate_sub_claim(self):
        m = JwtMutator(seed=1)
        token, resigned = m._duplicate_sub_claim(b"not-a-jwt", {})
        assert resigned is False
        payload_b64 = token.split(b".")[1]
        payload_raw = _b64url_decode(payload_b64)
        assert payload_raw.count(b'"sub"') == 2

    def test_lenient_json_parsing(self):
        m = JwtMutator(seed=1)
        token, resigned = m._lenient_json_parsing(b"not-a-jwt", {})
        assert resigned is False
        assert len(token.split(b".")) == 3

    def test_null_byte_injection(self):
        m = JwtMutator(seed=1)
        token, resigned = m._null_byte_injection(b"not-a-jwt", {})
        assert resigned is False
        assert token.endswith(b".")

    def test_b64_type_variants(self):
        m = JwtMutator(seed=1)
        token, resigned = m._b64_type_variants(b"not-a-jwt", {})
        assert resigned is False
        header_raw = _b64url_decode(token.split(b".")[0])
        header = json.loads(header_raw)
        assert "b64" in header

    def test_duplicate_exp_type_confused(self):
        m = JwtMutator(seed=1)
        token, resigned = m._duplicate_exp_type_confused(b"not-a-jwt", {})
        assert resigned is False
        payload_b64 = token.split(b".")[1]
        payload_raw = _b64url_decode(payload_b64)
        assert payload_raw.count(b'"exp"') == 2

    def test_crit_edge_cases(self):
        m = JwtMutator(seed=1)
        token, resigned = m._crit_edge_cases(b"not-a-jwt", {})
        assert resigned is False
        header_raw = _b64url_decode(token.split(b".")[0])
        header = json.loads(header_raw)
        assert "crit" in header

    def test_exp_negative_and_zero(self):
        m = JwtMutator(seed=1)
        token, resigned = m._exp_negative_and_zero(b"not-a-jwt", {})
        assert resigned is False
        payload_raw = _b64url_decode(token.split(b".")[1])
        payload = json.loads(payload_raw)
        assert payload["exp"] in (-1, 0, 9007199254740993)

    def test_base64_whitespace(self):
        m = JwtMutator(seed=1)
        token, resigned = m._base64_whitespace(b"not-a-jwt", {})
        assert resigned is False

    def test_missing_alg_header(self):
        m = JwtMutator(seed=1)
        token, resigned = m._missing_alg_header(b"not-a-jwt", {})
        assert resigned is False
        header_raw = _b64url_decode(token.split(b".")[0])
        header = json.loads(header_raw)
        assert "alg" not in header
        assert header.get("typ") == "JWT"

    def test_segment_count_variants(self):
        m = JwtMutator(seed=1)
        token, resigned = m._segment_count_variants(b"not-a-jwt", {})
        assert resigned is False
        # Should have non-standard segment count
        parts = token.split(b".")
        assert len(parts) != 3 or parts == [b"", b"", b""]

    # J9 — CVE-driven attack vectors

    def test_zip_in_jws(self):
        m = JwtMutator(seed=1)
        token, resigned = m._zip_in_jws(b"not-a-jwt", {})
        assert token is not None and resigned is True
        header = json.loads(_b64url_decode(token.split(b".")[0]))
        assert header.get("zip") == "DEF"

    def test_iss_mixed_array(self):
        m = JwtMutator(seed=1)
        token, resigned = m._iss_mixed_array(b"not-a-jwt", {})
        assert token is not None and resigned is True
        payload = json.loads(_b64url_decode(token.split(b".")[1]))
        assert isinstance(payload.get("iss"), list)

    def test_deeply_nested_claims(self):
        m = JwtMutator(seed=1)
        token, resigned = m._deeply_nested_claims(b"not-a-jwt", {})
        assert token is not None and resigned is True
        payload = json.loads(_b64url_decode(token.split(b".")[1]))
        # At least one claim should be an object
        assert any(isinstance(v, dict) for v in payload.values())

    def test_pkcs1_pem_confusion(self):
        m = JwtMutator(seed=1)
        token, resigned = m._pkcs1_pem_confusion(b"not-a-jwt", {})
        assert token is not None
        # resigned=False because RS256 can't be signed without private key
        header = json.loads(_b64url_decode(token.split(b".")[0]))
        assert header.get("x5t") == "pkcs1-format-hint"
        assert header.get("alg") == "RS256"

    def test_zip_variant_headers(self):
        m = JwtMutator(seed=1)
        token, resigned = m._zip_variant_headers(b"not-a-jwt", {})
        assert token is not None and resigned is True
        header = json.loads(_b64url_decode(token.split(b".")[0]))
        assert header.get("zip") in ("gzip", "none", "", "DEFLATE", "zlib")
