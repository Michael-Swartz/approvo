"""Signers.

``Signer`` is the low-level "can produce one signature over bytes"
primitive. It is a :class:`~typing.Protocol`, so key custody is
pluggable:

- :class:`Ed25519Signer` holds a raw private key in process — fine for
  dev, CI, and tests.
- KMS / HSM / Vault back ends implement the same protocol against a
  network service so the private key never leaves the boundary. Those
  live behind a :class:`~approvo.crypto.keyprovider.KeyProvider` and are
  handed out already *primed* (public key fetched), so :meth:`Signer.key_id`
  and :meth:`Signer.algorithm` are synchronous.

:meth:`Signer.sign` may return ``bytes`` **or** an awaitable — a KMS call
is I/O. Use :func:`sign_with` to normalise both and get back
``(signature, keyid)``.
"""

from __future__ import annotations

import inspect
from collections.abc import Awaitable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .algorithms import ED25519, get_scheme, keyid_for
from .keys import KeyRef


@dataclass(frozen=True)
class PublicKeyMaterial:
    """A public key ready to drop into a :class:`~approvo.crypto.keys.KeyRef`."""

    scheme: str
    public: bytes  # canonical bytes for `scheme` (see approvo.crypto.algorithms)

    @property
    def keyid(self) -> str:
        return keyid_for(self.public)

    def to_key_ref(
        self,
        owner_id: str,
        *,
        not_before: str,
        not_after: str | None = None,
        key_use: str = "approver",
        log_ids: tuple[str, ...] | None = None,
    ) -> KeyRef:
        return KeyRef(
            keyid=self.keyid,
            scheme=self.scheme,
            public=self.public.hex(),
            owner_id=owner_id,
            not_before=not_before,
            not_after=not_after,
            key_use=key_use,
            log_ids=log_ids,
        )


@runtime_checkable
class Signer(Protocol):
    """Produces detached signatures. ``algorithm`` is a scheme id."""

    algorithm: str

    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> bytes | Awaitable[bytes]: ...

    def public_material(self) -> PublicKeyMaterial: ...


async def sign_with(signer: Signer, data: bytes) -> tuple[bytes, str]:
    """Sign *data*, awaiting the result if the signer is async.

    Returns ``(signature, keyid)`` — the keyid is captured here so an
    envelope records exactly which key/version produced the signature,
    which keeps historical signatures verifiable across key rotation.
    """
    result = signer.sign(data)
    if inspect.isawaitable(result):
        result = await result
    return result, signer.key_id()


def public_key_ref(
    signer: Signer,
    owner_id: str,
    *,
    not_before: str,
    not_after: str | None = None,
    key_use: str = "approver",
    log_ids: tuple[str, ...] | None = None,
) -> KeyRef:
    """Convenience: a ``KeyRef`` for *signer*'s public half."""
    return signer.public_material().to_key_ref(
        owner_id, not_before=not_before, not_after=not_after,
        key_use=key_use, log_ids=log_ids,
    )


class Ed25519Signer:
    """In-process Ed25519 signer backed by a raw 32-byte seed."""

    algorithm = ED25519

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self._public = private_key.public_key().public_bytes_raw()

    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, seed: bytes) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_file(cls, path: str | Path) -> Ed25519Signer:
        return cls.from_private_bytes(bytes.fromhex(Path(path).read_text().strip()))

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.touch(mode=0o600, exist_ok=True)
        p.write_text(self._key.private_bytes_raw().hex())

    def key_id(self) -> str:
        return keyid_for(self._public)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def public_material(self) -> PublicKeyMaterial:
        return PublicKeyMaterial(scheme=ED25519, public=self._public)

    # Backwards-compatible helper kept from the original API.
    def public_key_ref(
        self,
        owner_id: str,
        not_before: str,
        not_after: str | None = None,
        *,
        key_use: str = "approver",
        log_ids: tuple[str, ...] | None = None,
    ) -> KeyRef:
        return self.public_material().to_key_ref(
            owner_id, not_before=not_before, not_after=not_after,
            key_use=key_use, log_ids=log_ids,
        )


def _load_scheme_for(scheme: str):  # pragma: no cover - guard helper
    return get_scheme(scheme)
