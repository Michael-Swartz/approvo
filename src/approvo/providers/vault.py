"""HashiCorp Vault (Transit secrets engine) key provider.

    pip install 'approvo[vault]'      # for a bundled hvac client

Key references are ``vault://<mount>/<key-name>``::

    vault://transit/approvo-org-approvals

Pass your own ``hvac.Client`` (its calls are synchronous and are run in a
worker thread), or let one be created from ``VAULT_ADDR`` / ``VAULT_TOKEN``.

Transit key types map as: ``ed25519`` → ``ed25519``,
``ecdsa-p256`` → ``ecdsa-p256-sha256``, ``ecdsa-p384`` → ``ecdsa-p384-sha384``,
``rsa-2048``/``rsa-3072``/``rsa-4096`` → ``rsa-pss-sha256``.
"""

from __future__ import annotations

import asyncio
import base64

from ..crypto.keyprovider import _BaseProvider, parse_key_ref
from ..crypto.signer import PublicKeyMaterial, Signer
from ..errors import KeyProviderError
from ._common import (
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PSS_SHA256,
    RemoteSigner,
)

_TYPE_MAP = {
    "ed25519": (ED25519, None, None),
    "ecdsa-p256": (ECDSA_P256_SHA256, "sha2-256", "sha256"),
    "ecdsa-p384": (ECDSA_P384_SHA384, "sha2-384", "sha384"),
    "rsa-2048": (RSA_PSS_SHA256, "sha2-256", "sha256"),
    "rsa-3072": (RSA_PSS_SHA256, "sha2-256", "sha256"),
    "rsa-4096": (RSA_PSS_SHA256, "sha2-256", "sha256"),
}


def _spki_from_pem(pem: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(pem.encode())
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _ed_raw_from_pem(pem: str) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_public_key(pem.encode()).public_bytes_raw()


def _load_hvac():
    try:
        import hvac  # type: ignore
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "hvac is required (or pass client=). Install with: pip install 'approvo[vault]'"
        ) from e
    return hvac


class VaultTransitKeyProvider(_BaseProvider):
    schemes = ("vault",)

    def __init__(self, client=None) -> None:
        if client is None:
            hvac = _load_hvac()
            client = hvac.Client()  # reads VAULT_ADDR / VAULT_TOKEN
        self._client = client

    @staticmethod
    def _parts(key_ref: str) -> tuple[str, str]:
        _, rest = parse_key_ref(key_ref)
        mount, _, name = rest.partition("/")
        if not name:
            raise KeyProviderError(f"vault ref must be '<mount>/<key>', got {rest!r}")
        return mount, name

    async def _read_key(self, key_ref: str) -> dict:
        mount, name = self._parts(key_ref)
        return await asyncio.to_thread(
            self._client.secrets.transit.read_key, name=name, mount_point=mount
        )

    async def _describe(self, key_ref: str):
        data = (await self._read_key(key_ref))["data"]
        ktype = data["type"]
        try:
            scheme, hash_algo, digest_name = _TYPE_MAP[ktype]
        except KeyError:
            raise KeyProviderError(f"unsupported transit key type {ktype!r}") from None
        latest = str(data["latest_version"])
        pem = data["keys"][latest]["public_key"]
        public = _ed_raw_from_pem(pem) if scheme == ED25519 else _spki_from_pem(pem)
        return scheme, hash_algo, digest_name, public

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial:
        scheme, _h, _d, public = await self._describe(key_ref)
        return PublicKeyMaterial(scheme=scheme, public=public)

    async def get_signer(self, key_ref: str) -> Signer:
        mount, name = self._parts(key_ref)
        scheme, hash_algo, _digest_name, public = await self._describe(key_ref)
        client = self._client

        async def _raw_sign(data: bytes) -> bytes:
            kwargs = {
                "name": name,
                "hash_input": base64.b64encode(data).decode(),
                "mount_point": mount,
            }
            if hash_algo is not None:
                kwargs["hash_algorithm"] = hash_algo
                kwargs["prehashed"] = False
            resp = await asyncio.to_thread(
                client.secrets.transit.sign_data, **kwargs
            )
            sig_field = resp["data"]["signature"]  # "vault:v1:<b64>"
            return base64.b64decode(sig_field.split(":", 2)[2])

        return RemoteSigner(scheme=scheme, public=public, raw_sign=_raw_sign, key_ref=key_ref)
