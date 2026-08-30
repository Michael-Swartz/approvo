"""Signers.

``Signer`` is a protocol so key custody is pluggable: the shipped
:class:`Ed25519Signer` holds the private key in process (fine for dev,
CLIs, and CI runners with short-lived keys); production deployments can
implement the same three methods against AWS KMS, GCP KMS, or Vault
transit so the private key never leaves the HSM. approvo never requires
raw private key bytes anywhere else in its API surface.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .keys import KeyRef, keyid_for


@runtime_checkable
class Signer(Protocol):
    def key_id(self) -> str: ...

    def sign(self, data: bytes) -> bytes: ...

    def public_key_ref(self, owner_id: str, not_before: str,
                       not_after: str | None = None) -> KeyRef: ...


class Ed25519Signer:
    """In-process Ed25519 signer backed by a raw 32-byte seed."""

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

    def public_key_ref(self, owner_id: str, not_before: str,
                       not_after: str | None = None) -> KeyRef:
        return KeyRef(
            keyid=self.key_id(),
            scheme="ed25519",
            public=self._public.hex(),
            owner_id=owner_id,
            not_before=not_before,
            not_after=not_after,
        )
