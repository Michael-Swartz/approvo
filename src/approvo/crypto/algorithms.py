"""Signature-scheme registry.

Every place approvo verifies a signature dispatches through here on a
``scheme`` string, so adding a new algorithm (for a KMS that only offers
P-384, say) is a registry entry, not a change to the verifier, the
checkpoint code, or the service.

A scheme entry knows three things:

- ``public_raw(key)`` — the canonical wire bytes for a public key of this
  scheme. Ed25519 uses the 32-byte raw form (so historical key ids do not
  change); everything else uses DER ``SubjectPublicKeyInfo``.
- ``load_public(raw)`` — reconstruct a ``cryptography`` public-key object
  from those bytes.
- ``verify(raw, signature, message)`` — raise
  :class:`cryptography.exceptions.InvalidSignature` on failure.

Signature encodings match what mainstream KMS/HSM back ends emit: raw
64-byte for Ed25519, ASN.1/DER for ECDSA, PKCS#1 v1.5 / PSS octet strings
for RSA.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

ED25519 = "ed25519"
ECDSA_P256_SHA256 = "ecdsa-p256-sha256"
ECDSA_P384_SHA384 = "ecdsa-p384-sha384"
RSA_PSS_SHA256 = "rsa-pss-sha256"
RSA_PKCS1_SHA256 = "rsa-pkcs1-sha256"


@dataclass(frozen=True)
class Scheme:
    name: str
    public_raw: Callable[[object], bytes]
    load_public: Callable[[bytes], object]
    verify: Callable[[bytes, bytes, bytes], None]


def _spki(key: object) -> bytes:
    return key.public_bytes(  # type: ignore[attr-defined]
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# --- Ed25519 -------------------------------------------------------------- #


def _ed_public_raw(key: object) -> bytes:
    return key.public_bytes_raw()  # type: ignore[attr-defined]


def _ed_load(raw: bytes) -> object:
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


def _ed_verify(raw: bytes, sig: bytes, msg: bytes) -> None:
    ed25519.Ed25519PublicKey.from_public_bytes(raw).verify(sig, msg)


# --- ECDSA -------------------------------------------------------------- #


def _ec_verifier(hash_alg: hashes.HashAlgorithm):
    def _verify(raw: bytes, sig: bytes, msg: bytes) -> None:
        key = serialization.load_der_public_key(raw)
        digest = hashlib.new(hash_alg.name, msg).digest()
        key.verify(sig, digest, ec.ECDSA(Prehashed(hash_alg)))  # type: ignore[attr-defined]

    return _verify


# --- RSA -------------------------------------------------------------- #


def _rsa_pss_verify(raw: bytes, sig: bytes, msg: bytes) -> None:
    key = serialization.load_der_public_key(raw)
    key.verify(  # type: ignore[attr-defined]
        sig,
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )


def _rsa_pkcs1_verify(raw: bytes, sig: bytes, msg: bytes) -> None:
    key = serialization.load_der_public_key(raw)
    key.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[attr-defined]


_REGISTRY: dict[str, Scheme] = {
    ED25519: Scheme(ED25519, _ed_public_raw, _ed_load, _ed_verify),
    ECDSA_P256_SHA256: Scheme(
        ECDSA_P256_SHA256, _spki, serialization.load_der_public_key,
        _ec_verifier(hashes.SHA256()),
    ),
    ECDSA_P384_SHA384: Scheme(
        ECDSA_P384_SHA384, _spki, serialization.load_der_public_key,
        _ec_verifier(hashes.SHA384()),
    ),
    RSA_PSS_SHA256: Scheme(RSA_PSS_SHA256, _spki, serialization.load_der_public_key, _rsa_pss_verify),
    RSA_PKCS1_SHA256: Scheme(
        RSA_PKCS1_SHA256, _spki, serialization.load_der_public_key, _rsa_pkcs1_verify
    ),
}


def get_scheme(name: str) -> Scheme:
    try:
        return _REGISTRY[name]
    except KeyError:
        from ..errors import UnsupportedAlgorithmError

        raise UnsupportedAlgorithmError(
            f"unknown signature scheme {name!r}; known: {sorted(_REGISTRY)}"
        ) from None


def register_scheme(scheme: Scheme) -> None:
    """Add or replace a scheme. For niche KMS curves not shipped by default."""
    _REGISTRY[scheme.name] = scheme


def known_schemes() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def keyid_for(public_raw: bytes) -> str:
    """Key id = SHA-256 of the scheme's canonical public bytes."""
    return hashlib.sha256(public_raw).hexdigest()


def scheme_for_public_key(key: object) -> str:
    """Best-effort scheme name for a ``cryptography`` public-key object."""
    if isinstance(key, ed25519.Ed25519PublicKey):
        return ED25519
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"secp256r1": ECDSA_P256_SHA256, "secp384r1": ECDSA_P384_SHA384}.get(
            key.curve.name, ""
        )
    if isinstance(key, rsa.RSAPublicKey):
        return RSA_PSS_SHA256
    return ""
