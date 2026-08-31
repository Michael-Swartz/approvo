"""``KeyProvider`` — the KMS-agnostic signing backend.

A provider resolves an **opaque logical key reference** (a URI-ish
string) to a primed :class:`~approvo.crypto.signer.Signer` and to public
key material. approvo core ships local providers only; GCP KMS / AWS KMS
/ Vault / PKCS#11 back ends are thin optional packages
(:mod:`approvo.providers`) that implement this same protocol.

Key reference schemes are provider-defined, e.g.::

    memory://org-approvals
    file:///etc/approvo/org.key
    env://APPROVO_ORG_KEY
    gcpkms://projects/p/locations/l/keyRings/approvo/cryptoKeys/org/cryptoKeyVersions/3
    awskms://arn:aws:kms:us-east-1:123:key/abc-123
    vault://transit/keys/approvo-org

Use :class:`CompositeKeyProvider` to route by scheme, so swapping KMS is a
config edit.

Validate any implementation with
:class:`approvo.testing.KeyProviderConformance`.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..errors import KeyProviderError
from .algorithms import ED25519
from .signer import Ed25519Signer, PublicKeyMaterial, Signer, sign_with


@dataclass(frozen=True)
class KeyDescriptor:
    key_ref: str
    public: PublicKeyMaterial
    label: str | None = None


def parse_key_ref(key_ref: str) -> tuple[str, str]:
    """``"gcpkms://projects/..."`` -> ``("gcpkms", "projects/...")``."""
    scheme, sep, rest = key_ref.partition("://")
    if not sep:
        raise KeyProviderError(f"malformed key reference {key_ref!r} (expected '<scheme>://...')")
    return scheme, rest


@runtime_checkable
class KeyProvider(Protocol):
    """Resolves logical key refs to signers and public keys."""

    schemes: tuple[str, ...]

    async def get_signer(self, key_ref: str) -> Signer:
        """A **primed** signer (``key_id()`` / ``algorithm`` usable synchronously)."""
        ...

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial: ...

    async def list_keys(self) -> list[KeyDescriptor]:
        """Optional. Providers that cannot enumerate raise ``NotImplementedError``."""
        ...

    async def self_test(self, key_ref: str) -> None:
        """Sign + verify a nonce, so a bad grant fails at startup not first use."""
        ...


class _BaseProvider:
    schemes: tuple[str, ...] = ()

    async def list_keys(self) -> list[KeyDescriptor]:
        raise NotImplementedError(f"{type(self).__name__} cannot enumerate keys")

    async def self_test(self, key_ref: str) -> None:
        from .algorithms import get_scheme

        signer = await self.get_signer(key_ref)  # type: ignore[attr-defined]
        nonce = secrets.token_bytes(32)
        sig, _ = await sign_with(signer, nonce)
        pub = signer.public_material()
        try:
            get_scheme(pub.scheme).verify(pub.public, sig, nonce)
        except Exception as e:
            raise KeyProviderError(f"self-test failed for {key_ref!r}: {e}") from e


class InMemoryKeyProvider(_BaseProvider):
    """``memory://<name>`` -> a generated Ed25519 key. Tests and local dev."""

    schemes = ("memory",)

    def __init__(self) -> None:
        self._keys: dict[str, Ed25519Signer] = {}

    def generate(self, name: str) -> str:
        self._keys[name] = Ed25519Signer.generate()
        return f"memory://{name}"

    def add(self, name: str, signer: Ed25519Signer) -> str:
        self._keys[name] = signer
        return f"memory://{name}"

    def _get(self, key_ref: str) -> Ed25519Signer:
        _, name = parse_key_ref(key_ref)
        try:
            return self._keys[name]
        except KeyError:
            raise KeyProviderError(f"no in-memory key {name!r}") from None

    async def get_signer(self, key_ref: str) -> Signer:
        return self._get(key_ref)

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial:
        return self._get(key_ref).public_material()

    async def list_keys(self) -> list[KeyDescriptor]:
        return [
            KeyDescriptor(f"memory://{n}", s.public_material(), label=n)
            for n, s in self._keys.items()
        ]


class LocalFileKeyProvider(_BaseProvider):
    """``file:///abs/path`` -> an Ed25519 seed (hex). Optionally rooted.

    With ``root`` set, ``file://name`` resolves to ``root/name.key`` and
    :meth:`ensure` will generate a missing key (0600) — handy for a
    single-node deployment that wants a persistent org key without a KMS.
    """

    schemes = ("file",)

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root is not None else None

    def _path(self, key_ref: str) -> Path:
        _, rest = parse_key_ref(key_ref)
        if rest.startswith("/"):
            return Path(rest)
        if self.root is None:
            raise KeyProviderError(
                f"relative key ref {key_ref!r} needs LocalFileKeyProvider(root=...)"
            )
        return self.root / f"{rest}.key"

    def ensure(self, key_ref: str) -> str:
        path = self._path(key_ref)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            Ed25519Signer.generate().save(path)
        return key_ref

    async def get_signer(self, key_ref: str) -> Signer:
        path = self._path(key_ref)
        if not path.exists():
            raise KeyProviderError(f"no key file at {path}")
        try:
            return Ed25519Signer.from_file(path)
        except (ValueError, OSError) as e:
            raise KeyProviderError(f"cannot load key {path}: {e}") from e

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial:
        return (await self.get_signer(key_ref)).public_material()


class EnvKeyProvider(_BaseProvider):
    """``env://VARNAME`` -> an Ed25519 seed (hex) from the environment."""

    schemes = ("env",)

    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self._environ = environ if environ is not None else os.environ

    def _seed(self, key_ref: str) -> bytes:
        _, var = parse_key_ref(key_ref)
        raw = self._environ.get(var)
        if not raw:
            raise KeyProviderError(f"environment variable {var!r} is unset or empty")
        try:
            return bytes.fromhex(raw.strip())
        except ValueError as e:
            raise KeyProviderError(f"{var!r} is not hex-encoded key material") from e

    async def get_signer(self, key_ref: str) -> Signer:
        return Ed25519Signer.from_private_bytes(self._seed(key_ref))

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial:
        return (await self.get_signer(key_ref)).public_material()


class CompositeKeyProvider(_BaseProvider):
    """Routes a key ref to the sub-provider that handles its scheme."""

    def __init__(self, providers: list[KeyProvider]) -> None:
        self._by_scheme: dict[str, KeyProvider] = {}
        for p in providers:
            for s in p.schemes:
                self._by_scheme[s] = p

    @property
    def schemes(self) -> tuple[str, ...]:  # type: ignore[override]
        return tuple(self._by_scheme)

    def _route(self, key_ref: str) -> KeyProvider:
        scheme, _ = parse_key_ref(key_ref)
        try:
            return self._by_scheme[scheme]
        except KeyError:
            raise KeyProviderError(
                f"no provider registered for scheme {scheme!r} "
                f"(have: {sorted(self._by_scheme)})"
            ) from None

    async def get_signer(self, key_ref: str) -> Signer:
        return await self._route(key_ref).get_signer(key_ref)

    async def get_public_key(self, key_ref: str) -> PublicKeyMaterial:
        return await self._route(key_ref).get_public_key(key_ref)

    async def self_test(self, key_ref: str) -> None:
        await self._route(key_ref).self_test(key_ref)

    async def list_keys(self) -> list[KeyDescriptor]:
        out: list[KeyDescriptor] = []
        for p in dict.fromkeys(self._by_scheme.values()):
            try:
                out.extend(await p.list_keys())
            except NotImplementedError:
                continue
        return out


DEFAULT_SCHEME = ED25519  # what the local providers generate
