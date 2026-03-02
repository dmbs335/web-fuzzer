"""Generate a self-signed X.509 certificate and RSA private key for SAML test IdP.

Outputs:
  targets/saml_fixtures/idp_cert.pem   (X.509 certificate, PEM)
  targets/saml_fixtures/idp_key.pem    (RSA 2048-bit private key, unencrypted PEM)
  targets/saml_fixtures/idp_cert.der   (DER-encoded certificate)
"""

from __future__ import annotations

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES_DIR = os.path.join(
    os.path.dirname(__file__), os.pardir, "targets", "saml_fixtures"
)


def generate_keypair(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)

    # RSA 2048-bit private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-idp.fuzzer.local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WebFuzzer SAML Test"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write PEM certificate
    cert_pem_path = os.path.join(output_dir, "idp_cert.pem")
    with open(cert_pem_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # Write DER certificate
    cert_der_path = os.path.join(output_dir, "idp_cert.der")
    with open(cert_der_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    # Write PEM private key (unencrypted)
    key_pem_path = os.path.join(output_dir, "idp_key.pem")
    with open(key_pem_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    print(f"IdP certificate: {cert_pem_path}")
    print(f"IdP certificate (DER): {cert_der_path}")
    print(f"IdP private key: {key_pem_path}")
    print(f"Subject: CN={cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
    print(f"Valid: {cert.not_valid_before_utc} - {cert.not_valid_after_utc}")


def main() -> None:
    output_dir = sys.argv[1] if len(sys.argv) > 1 else FIXTURES_DIR
    generate_keypair(os.path.abspath(output_dir))


if __name__ == "__main__":
    main()
