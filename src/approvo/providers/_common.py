"""Shared helpers for KMS/HSM key providers."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable

from ..crypto.algorithms import (
    ECDSA_P256_SHA256,
    ECDSA_P384_SHA384,
    ED25519,
    RSA_PKCS1_SHA256,
    RSA_PSS_SHA256,
    keyid_for,
)
from ..crypto.signer import PublicKeyMaterial, Signer


async def _maybe_await(value):
    if inspect.isawaitable(value):
        return await value
    return value


class RemoteSigner:
    """A :class:`~approvo.crypto.signer.Signer` whose ``sign`` is a network call.

    Constructed *primed*: the public key material is fetched by the
    provider before the signer is handed out, so ``key_id`` / ``algorithm``
    stay synchronous. ``_raw_sign`` does the remote call.
    """

    def __init__(
        self,
        *,
        scheme: str,
        public: bytes,
        raw_sign: Callable[[bytes], Awaitable[bytes] | bytes],
        key_ref: str,
    ) -> None:
        self.algorithm = scheme
        self._public = public
        self._raw_sign = raw_sign
        self.key_ref = key_ref

    def key_id(self) -> str:
        return keyid_for(self._public)

    async def sign(self, data: bytes) -> bytes:
        return await _maybe_await(self._raw_sign(data))

    def public_material(self) -> PublicKeyMaterial:
        return PublicKeyMaterial(scheme=self.algorithm, public=self._public)


def _missing(pkg: str, extra: str):
    def _raise(*_a, **_k):
        raise ImportError(
            f"{pkg} is required for this key provider. Install it with: "
            f"pip install 'approvo[{extra}]'"
        )

    return _raise


__all__ = [
    "ECDSA_P256_SHA256",
    "ECDSA_P384_SHA384",
    "ED25519",
    "RSA_PKCS1_SHA256",
    "RSA_PSS_SHA256",
    "RemoteSigner",
    "Signer",
    "_maybe_await",
    "_missing",
]
