"""The signature-scheme registry: verify across Ed25519 / ECDSA / RSA."""

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from approvo.crypto.algorithms import (
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PSS_SHA256,
    get_scheme,
    keyid_for,
    known_schemes,
)


def _spki(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def test_known_schemes_stable():
    assert ED25519 in known_schemes()
    assert ECDSA_P256_SHA256 in known_schemes()


def test_ed25519_roundtrip():
    sk = ed25519.Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes_raw()
    msg = b"hello approvo"
    sig = sk.sign(msg)
    get_scheme(ED25519).verify(raw, sig, msg)
    with pytest.raises(Exception):  # noqa: B017
        get_scheme(ED25519).verify(raw, sig, b"tampered")


def test_ecdsa_p256_roundtrip():
    sk = ec.generate_private_key(ec.SECP256R1())
    raw = _spki(sk.public_key())
    msg = b"release 1.4.0"
    sig = sk.sign(msg, ec.ECDSA(hashes.SHA256()))  # DER-encoded, like KMS emits
    get_scheme(ECDSA_P256_SHA256).verify(raw, sig, msg)
    with pytest.raises(Exception):  # noqa: B017
        get_scheme(ECDSA_P256_SHA256).verify(raw, sig, b"other")


def test_ecdsa_p384_roundtrip():
    sk = ec.generate_private_key(ec.SECP384R1())
    raw = _spki(sk.public_key())
    msg = b"x" * 100
    sig = sk.sign(msg, ec.ECDSA(hashes.SHA384()))
    get_scheme(ECDSA_P384_SHA384).verify(raw, sig, msg)


def test_rsa_pss_roundtrip():
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raw = _spki(sk.public_key())
    msg = b"checkpoint bytes"
    sig = sk.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    get_scheme(RSA_PSS_SHA256).verify(raw, sig, msg)


def test_keyid_is_hash_of_public_bytes():
    sk = ed25519.Ed25519PrivateKey.generate()
    raw = sk.public_key().public_bytes_raw()
    assert keyid_for(raw) == keyid_for(raw)
    assert len(keyid_for(raw)) == 64


def test_unknown_scheme_raises():
    from approvo.errors import UnsupportedAlgorithmError

    with pytest.raises(UnsupportedAlgorithmError):
        get_scheme("rot13")
