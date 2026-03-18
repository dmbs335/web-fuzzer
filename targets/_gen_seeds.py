"""Generate PKCE (146-160), token exchange (161-180), and DPoP (181-210) seeds."""
import json
import os
import base64
import hashlib

SEEDS_DIR = os.path.join(os.path.dirname(__file__), "oauth_seeds")


def b64url(s):
    if isinstance(s, str):
        s = s.encode()
    return base64.urlsafe_b64encode(s).rstrip(b"=").decode()


def write_seed(num, name, data):
    path = os.path.join(SEEDS_DIR, f"{num:03d}_{name}.json")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(data, separators=(",", ":"), ensure_ascii=True))
    print(f"Wrote {path}")


# ===== PKCE seeds 146-160 =====
v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
ch = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
ch_padded = ch + "="

write_seed(146, "pkce_plain_downgrade", {"type": "pkce", "method": "plain", "verifier": v, "challenge": v})
write_seed(147, "pkce_s256_to_plain", {"type": "pkce", "method": "plain", "verifier": v, "challenge": ch})
write_seed(148, "pkce_s256_no_challenge", {"type": "pkce", "method": "S256", "verifier": v})
write_seed(149, "pkce_s256_no_verifier", {"type": "pkce", "method": "S256", "challenge": ch})
write_seed(150, "pkce_no_method", {"type": "pkce", "verifier": v, "challenge": ch})
write_seed(151, "pkce_empty_method", {"type": "pkce", "method": "", "verifier": v, "challenge": ch})
write_seed(152, "pkce_s256_no_both", {"type": "pkce", "method": "S256"})
write_seed(153, "pkce_plain_empty_both", {"type": "pkce", "method": "plain", "verifier": "", "challenge": ""})
write_seed(154, "pkce_s256_verifier_empty_challenge", {"type": "pkce", "method": "S256", "verifier": v, "challenge": ""})
write_seed(155, "pkce_s256_empty_verifier_challenge", {"type": "pkce", "method": "S256", "verifier": "", "challenge": ch})
write_seed(156, "pkce_PLAIN_uppercase", {"type": "pkce", "method": "PLAIN", "verifier": v, "challenge": v})
write_seed(157, "pkce_s256_lowercase", {"type": "pkce", "method": "s256", "verifier": v, "challenge": ch})
write_seed(158, "pkce_s256_challenge_padding", {"type": "pkce", "method": "S256", "verifier": v, "challenge": ch_padded})
write_seed(159, "pkce_no_method_verifier_only", {"type": "pkce", "verifier": v})
write_seed(160, "pkce_bare_type", {"type": "pkce"})

print("--- PKCE seeds done ---")

# ===== Token exchange seeds 161-180 =====
base_reg = ["https://example.com/callback"]
base_auth = "https://example.com/callback"

write_seed(161, "texch_baseline", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(162, "texch_port443", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com:443/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(163, "texch_host_uppercase", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://EXAMPLE.COM/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(164, "texch_trailing_slash", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com/callback/", "grant_type": "authorization_code", "code": "abc123"})
write_seed(165, "texch_percent_encoded", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com/callba%63k", "grant_type": "authorization_code", "code": "abc123"})
write_seed(166, "texch_dot_segment", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com/foo/../callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(167, "texch_query_added", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com/callback?evil=1", "grant_type": "authorization_code", "code": "abc123"})
write_seed(168, "texch_token_uri_missing", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "grant_type": "authorization_code", "code": "abc123"})
write_seed(169, "texch_scheme_diff", {"type": "token_exchange", "registered": ["http://example.com/callback"], "auth_redirect_uri": "http://example.com/callback", "token_redirect_uri": "https://example.com/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(170, "texch_backslash", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": "https://example.com/callback", "token_redirect_uri": "https://example.com\\callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(171, "texch_double_slash", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com//callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(172, "texch_fragment", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com/callback#frag", "grant_type": "authorization_code", "code": "abc123"})
write_seed(173, "texch_port80", {"type": "token_exchange", "registered": ["http://example.com:80/callback"], "auth_redirect_uri": "http://example.com:80/callback", "token_redirect_uri": "http://example.com:80/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(174, "texch_trailing_space", {"type": "token_exchange", "registered": ["http://example.com/callback"], "auth_redirect_uri": "http://example.com/callback", "token_redirect_uri": "http://example.com/callback ", "grant_type": "authorization_code", "code": "abc123"})
write_seed(175, "texch_case_diff", {"type": "token_exchange", "registered": ["https://Example.Com/Callback"], "auth_redirect_uri": "https://Example.Com/Callback", "token_redirect_uri": "https://example.com/Callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(176, "texch_unicode_dot", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example\u00b7com/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(177, "texch_zwsp", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://example.com/callback\u200b", "grant_type": "authorization_code", "code": "abc123"})
write_seed(178, "texch_userinfo", {"type": "token_exchange", "registered": base_reg, "auth_redirect_uri": base_auth, "token_redirect_uri": "https://evil@example.com/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(179, "texch_loopback", {"type": "token_exchange", "registered": ["http://127.0.0.1/callback"], "auth_redirect_uri": "http://127.0.0.1/callback", "token_redirect_uri": "http://127.0.0.1:8080/callback", "grant_type": "authorization_code", "code": "abc123"})
write_seed(180, "texch_query_diff", {"type": "token_exchange", "registered": ["https://example.com/callback?state=a"], "auth_redirect_uri": "https://example.com/callback?state=a", "token_redirect_uri": "https://example.com/callback?state=b", "grant_type": "authorization_code", "code": "abc123"})

print("--- Token exchange seeds done ---")

# ===== DPoP seeds 181-210 =====
sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
ts = 1709136000

h_es256 = b64url(json.dumps({"typ": "dpop+jwt", "alg": "ES256"}, separators=(",", ":")))
h_notyp = b64url(json.dumps({"alg": "ES256"}, separators=(",", ":")))
h_jwt = b64url(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")))
h_atjwt = b64url(json.dumps({"typ": "at+jwt", "alg": "ES256"}, separators=(",", ":")))
h_none = b64url(json.dumps({"typ": "dpop+jwt", "alg": "none"}, separators=(",", ":")))
h_hs256 = b64url(json.dumps({"typ": "dpop+jwt", "alg": "HS256"}, separators=(",", ":")))

ath_nopad = b64url(hashlib.sha256(b"at_abc123").digest())
ath_padded = base64.urlsafe_b64encode(hashlib.sha256(b"at_abc123").digest()).decode()


def make_jwt(header_b64, payload_dict):
    payload_b64 = b64url(json.dumps(payload_dict, separators=(",", ":")))
    return f"{header_b64}.{payload_b64}.{sig}"


def dpop_seed(num, name, header_b64, payload, access_token=None, server_nonce=None):
    jwt = make_jwt(header_b64, payload)
    data = {
        "type": "dpop_proof",
        "proof_jwt": jwt,
        "http_method": "POST",
        "http_uri": "https://auth.example.com/token",
    }
    if access_token is not None:
        data["access_token"] = access_token
    if server_nonce is not None:
        data["server_nonce"] = server_nonce
    write_seed(num, name, data)


# 181: Baseline valid
dpop_seed(181, "dpop_baseline", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})

# 182: htm lowercase
dpop_seed(182, "dpop_htm_lowercase", h_es256,
          {"htm": "post", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-182"})

# 183: htm mixed case
dpop_seed(183, "dpop_htm_mixedcase", h_es256,
          {"htm": "Post", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-183"})

# 184: htm with space
dpop_seed(184, "dpop_htm_space", h_es256,
          {"htm": " POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-184"})

# 185: htu with port 443
dpop_seed(185, "dpop_htu_port443", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com:443/token", "iat": ts, "jti": "test-jti-185"})

# 186: htu uppercase host
dpop_seed(186, "dpop_htu_uppercase_host", h_es256,
          {"htm": "POST", "htu": "https://AUTH.EXAMPLE.COM/token", "iat": ts, "jti": "test-jti-186"})

# 187: htu trailing slash
dpop_seed(187, "dpop_htu_trailing_slash", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token/", "iat": ts, "jti": "test-jti-187"})

# 188: htu with query
dpop_seed(188, "dpop_htu_query", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token?foo=bar", "iat": ts, "jti": "test-jti-188"})

# 189: htu percent-encoded
dpop_seed(189, "dpop_htu_percent_encoded", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/to%6Ben", "iat": ts, "jti": "test-jti-189"})

# 190: htu uppercase scheme
dpop_seed(190, "dpop_htu_uppercase_scheme", h_es256,
          {"htm": "POST", "htu": "HTTPS://auth.example.com/token", "iat": ts, "jti": "test-jti-190"})

# 191: ath with padding
dpop_seed(191, "dpop_ath_padding", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-191", "ath": ath_padded},
          access_token="at_abc123")

# 192: ath without padding
dpop_seed(192, "dpop_ath_nopadding", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-192", "ath": ath_nopad},
          access_token="at_abc123")

# 193: ath wrong hash
dpop_seed(193, "dpop_ath_wrong", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-193", "ath": "wronghashvalue1234567890ABCDEFGHIJKLMNOPQRS"},
          access_token="at_abc123")

# 194: ath missing but access_token present
dpop_seed(194, "dpop_ath_missing", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-194"},
          access_token="at_abc123")

# 195: ath present but no access_token
dpop_seed(195, "dpop_ath_no_token", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-195", "ath": ath_nopad})

# 196: iat future
dpop_seed(196, "dpop_iat_future", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts + 3600, "jti": "test-jti-196"})

# 197: iat expired
dpop_seed(197, "dpop_iat_expired", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts - 3600, "jti": "test-jti-197"})

# 198: iat way off
dpop_seed(198, "dpop_iat_wayoff", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts - 86400, "jti": "test-jti-198"})

# 199: jti empty string
dpop_seed(199, "dpop_jti_empty", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": ""})

# 200: jti very long
dpop_seed(200, "dpop_jti_long", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "A" * 256})

# 201: jti missing
dpop_seed(201, "dpop_jti_missing", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts})

# 202: nonce matches
dpop_seed(202, "dpop_nonce_match", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-202", "nonce": "nonce_xyz"},
          server_nonce="nonce_xyz")

# 203: nonce mismatch
dpop_seed(203, "dpop_nonce_mismatch", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-203", "nonce": "wrong_nonce"},
          server_nonce="nonce_xyz")

# 204: nonce empty, server_nonce provided
dpop_seed(204, "dpop_nonce_empty", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-204", "nonce": ""},
          server_nonce="nonce_xyz")

# 205: nonce missing, server_nonce provided
dpop_seed(205, "dpop_nonce_missing", h_es256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-205"},
          server_nonce="nonce_xyz")

# 206: typ missing
dpop_seed(206, "dpop_typ_missing", h_notyp,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-206"})

# 207: typ = "JWT"
dpop_seed(207, "dpop_typ_jwt", h_jwt,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-207"})

# 208: typ = "at+jwt"
dpop_seed(208, "dpop_typ_atjwt", h_atjwt,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-208"})

# 209: alg = "none"
dpop_seed(209, "dpop_alg_none", h_none,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-209"})

# 210: alg = "HS256"
dpop_seed(210, "dpop_alg_hs256", h_hs256,
          {"htm": "POST", "htu": "https://auth.example.com/token", "iat": ts, "jti": "test-jti-210"})

print("--- DPoP seeds done ---")
print("All seeds generated successfully!")
