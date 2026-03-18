/**
 * Shared EC P-256 keypair for JWT ECDSA targets.
 * The public key is "known" to the attacker (like OIDC /.well-known/jwks.json).
 * Targets verify with this public key using ES256.
 */
"use strict";

const EC_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX3+hdI8wUgMPJuIocOFdBxh+VZp6
GnlaqRqKGi1WSRcgg1+SLcoGu3XEP63c65tVW952Xw9lGiF5B3Q56sdssA==
-----END PUBLIC KEY-----`;

const EC_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggNiqrI56o41IUych
r8FzVPdIl2JOpe5Z3dEPmteeAUKhRANCAARff6F0jzBSAw8m4ihw4V0HGH5Vmnoa
eVqpGooaLVZJFyCDX5Ityga7dcQ/rdzrm1Vb3nZfD2UaIXkHdDnqx2yw
-----END PRIVATE KEY-----`;

module.exports = { EC_PUBLIC_KEY_PEM, EC_PRIVATE_KEY_PEM };
