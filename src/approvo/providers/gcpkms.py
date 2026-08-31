"""GCP Cloud KMS key provider.

    pip install 'approvo[gcpkms]'

Key references are ``gcpkms://`` + the full CryptoKeyVersion resource name::

    gcpkms://projects/P/locations/L/keyRings/approvo/cryptoKeys/org-approvals/cryptoKeyVersions/3

The ``google-cloud-kms`` client is imported lazily, so this module always
imports even without the SDK installed (you just can't construct the
provider). Auth uses Application Default Credentials — prefer Workload
Identity over service-account key files.

Supported KMS algorithms: ``EC_SIGN_P256_SHA256``, ``EC_SIGN_P384_SHA384``,
``RSA_SIGN_PSS_2048_SHA256`` … , ``RSA_SIGN_PKCS1_2048_SHA256`` … , and
``EC_SIGN_ED25519`` where available.
"""

from __future__ import annotations

import hashlib

from ..crypto.keyprovider import _BaseProvider, parse_key_ref
from ..crypto.signer import PublicKeyMaterial, Signer
from ..errors import KeyProviderError
from ._common import (
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PKCS1_SHA256,
    RSA_PSS_SHA256,
    RemoteSigner,
)

# CryptoKeyVersionAlgorithm name -> (approvo scheme, digest name or None for Ed25519)
_ALGO_MAP = {
    "EC_SIGN_P256_SHA256": (ECDSA_P256_SHA256, "sha256"),
    "EC_SIGN_P384_SHA384": (ECDSA_P384_SHA384, "sha384"),
    "EC_SIGN_ED25519": (ED25519, None),
    "RSA_SIGN_PSS_2048_SHA256": (RSA_PSS_SHA256, "sha256"),
    "RSA_SIGN_PSS_3072_SHA256": (RSA_PSS_SHA256, "sha256"),
    "RSA_SIGN_PSS_4096_SHA256": (RSA_PSS_SHA256, "sha256"),
    "RSA_SIGN_PKCS1_2048_SHA256": (RSA_PKCS1_SHA256, "sha256"),
    "RSA_SIGN_PKCS1_3072_SHA256": (RSA_PKCS1_SHA256, "sha256"),
    "RSA_SIGN_PKCS1_4096_SHA256": (RSA_PKCS1_SHA256, "sha256"),
}


def _load_client():
    try:
        from google.cloud import kms  # type: ignore
    except ImportError as e:  # pragma: no cover - exercised only without the SDK
        raise ImportError(
            "google-cloud-kms is required. Install with: pip install 'approvo[gcpkms]'"
        ) from e
    return kms


def _spki_from_pem(pem: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(pem.encode())
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _ed25519_raw_from_pem(pem: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(pem.encode())
    return key.public_bytes_raw()


class GcpKmsKeyProvider(_BaseProvider):
    schemes = ("gcpkms",)

    def __init__(self, client=None) -> None:
        kms = _load_client()
        self._kms = kms
        self._client = client or kms.KeyManagementServiceAsyncClient()

    @staticmethod
    def _name(key_ref: str) -> str:
        _, rest = parse_key_ref(key_ref)
        if not rest.startswith("projects/"):
            raise KeyProviderError(
                f"gcpkms ref must be a CryptoKeyVersion resource name, got {rest!r}"
            )
        return rest

    async def _describe(self, key_ref: str) -> tuple[str, str | None, str]:
        name = self._name(key_ref)
        resp = await self._client.get_public_key(request={"name": name})
        algo_name = self._kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm(resp.algorithm).name
        try:
            scheme, digest = _ALGO_MAP[algo_name]
        except KeyError:
            raise KeyProviderError(f"unsupported KMS algorithm {algo_name}") from None
        pem = resp.pem
        public = _ed25519_raw_from_pem(pem) if scheme == ED25519 else _spki_from_pem(pem)
        return scheme, digest, public.hex()

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial:
        scheme, _digest, public_hex = await self._describe(key_ref)
        return PublicKeyMaterial(scheme=scheme, public=bytes.fromhex(public_hex))

    async def get_signer(self, key_ref: str) -> Signer:
        name = self._name(key_ref)
        scheme, digest, public_hex = await self._describe(key_ref)
        client = self._client

        async def _raw_sign(data: bytes) -> bytes:
            if digest is None:  # Ed25519 signs the message directly
                req = {"name": name, "data": data}
            else:
                h = hashlib.new(digest, data).digest()
                req = {"name": name, "digest": {digest: h}}
            resp = await client.asymmetric_sign(request=req)
            return resp.signature

        return RemoteSigner(
            scheme=scheme, public=bytes.fromhex(public_hex),
            raw_sign=_raw_sign, key_ref=key_ref,
        )
