"""``SigningService`` — resolver + provider + caches, in one object.

This is the single thing :class:`~approvo.service.ApprovalService` depends
on for server-side signing. Inject one and you get:

- ``sign_decision`` / ``sign_checkpoint`` — produce signed envelopes /
  checkpoints without the caller ever touching a key.
- ``trust`` — turn the keys this service signs with into
  :class:`~approvo.crypto.keys.KeyRef` entries for the
  :class:`~approvo.crypto.keys.KeyDirectory` (the verification trust
  root), so what you sign with is exactly what verifiers accept.
- ``self_test`` — sign+verify a nonce per configured key at startup.

Caches public keys (long TTL) and resolved signers (short TTL). Never
caches signatures.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from ..models import DECISION_PAYLOAD_TYPE, Checkpoint, Decision
from .envelope import wrap_async
from .keyprovider import KeyProvider
from .keys import KeyRef
from .resolver import KeyResolver, SigningContext, SigningPurpose
from .signer import PublicKeyMaterial, Signer

DEFAULT_PUBKEY_TTL = 3600.0
DEFAULT_SIGNER_TTL = 300.0


@dataclass(frozen=True)
class TrustSpec:
    """How to publish one signing key into the trust root."""

    key_ref: str
    owner_id: str
    key_use: str  # "decision_issuer" | "log"
    not_before: str
    not_after: str | None = None
    log_ids: tuple[str, ...] | None = None


class SigningService:
    def __init__(
        self,
        provider: KeyProvider,
        resolver: KeyResolver,
        *,
        pubkey_ttl: float = DEFAULT_PUBKEY_TTL,
        signer_ttl: float = DEFAULT_SIGNER_TTL,
        clock=time.monotonic,
    ) -> None:
        self.provider = provider
        self.resolver = resolver
        self._pubkey_ttl = pubkey_ttl
        self._signer_ttl = signer_ttl
        self._now = clock
        self._pub_cache: dict[str, tuple[float, PublicKeyMaterial]] = {}
        self._signer_cache: dict[str, tuple[float, Signer]] = {}

    # -- resolution ---------------------------------------------------- #

    async def key_ref_for(self, ctx: SigningContext) -> str:
        return await self.resolver.resolve(ctx)

    async def signer_for(self, ctx: SigningContext) -> Signer:
        key_ref = await self.resolver.resolve(ctx)
        hit = self._signer_cache.get(key_ref)
        if hit and self._now() - hit[0] < self._signer_ttl:
            return hit[1]
        signer = await self.provider.get_signer(key_ref)
        self._signer_cache[key_ref] = (self._now(), signer)
        return signer

    async def public_key(self, key_ref: str) -> PublicKeyMaterial:
        hit = self._pub_cache.get(key_ref)
        if hit and self._now() - hit[0] < self._pubkey_ttl:
            return hit[1]
        pub = await self.provider.get_public_key(key_ref)
        self._pub_cache[key_ref] = (self._now(), pub)
        return pub

    # -- signing ----------------------------------------------------- #

    async def sign_decision(self, decision: Decision, *, ctx: SigningContext) -> dict:
        signer = await self.signer_for(ctx)
        return await wrap_async(decision.to_dict(), DECISION_PAYLOAD_TYPE, [signer])

    async def sign_checkpoint(self, cp: Checkpoint) -> Checkpoint:
        from ..checkpoint import sign_checkpoint_async

        ctx = SigningContext(log_id=cp.log_id, purpose=SigningPurpose.CHECKPOINT)
        signer = await self.signer_for(ctx)
        return await sign_checkpoint_async(cp, signer)

    # -- trust root ------------------------------------------------- #

    async def trust(self, specs: list[TrustSpec]) -> list[KeyRef]:
        """Resolve each spec's public key into a :class:`KeyRef`."""
        out: list[KeyRef] = []
        for spec in specs:
            pub = await self.public_key(spec.key_ref)
            out.append(
                pub.to_key_ref(
                    spec.owner_id,
                    not_before=spec.not_before,
                    not_after=spec.not_after,
                    key_use=spec.key_use,
                    log_ids=spec.log_ids,
                )
            )
        return out

    async def trust_from_static(
        self,
        *,
        issuer_owner_id: str,
        log_owner_id: str,
        not_before: str,
        log_ids: tuple[str, ...] | None = None,
    ) -> list[KeyRef]:
        """Shortcut when the resolver is a :class:`StaticKeyResolver`:
        publish its DECISION key as ``decision_issuer`` and its CHECKPOINT
        key as ``log``."""
        from .resolver import StaticKeyResolver

        if not isinstance(self.resolver, StaticKeyResolver):
            raise TypeError("trust_from_static needs a StaticKeyResolver")
        purposes = self.resolver.purposes()
        specs: list[TrustSpec] = []
        if SigningPurpose.DECISION in purposes:
            specs.append(TrustSpec(
                purposes[SigningPurpose.DECISION], issuer_owner_id,
                "decision_issuer", not_before, log_ids=log_ids,
            ))
        if SigningPurpose.CHECKPOINT in purposes:
            specs.append(TrustSpec(
                purposes[SigningPurpose.CHECKPOINT], log_owner_id,
                "log", not_before, log_ids=log_ids,
            ))
        return await self.trust(specs)

    async def self_test(self, key_refs: list[str] | None = None) -> None:
        refs = key_refs
        if refs is None:
            from .resolver import StaticKeyResolver, TemplateKeyResolver

            if isinstance(self.resolver, StaticKeyResolver):
                refs = list(self.resolver.purposes().values())
            elif isinstance(self.resolver, TemplateKeyResolver):
                raise ValueError("pass key_refs explicitly for a TemplateKeyResolver")
            else:
                raise ValueError("pass key_refs explicitly for a custom resolver")
        for ref in refs:
            await self.provider.self_test(ref)

    def invalidate(self) -> None:
        self._pub_cache.clear()
        self._signer_cache.clear()
