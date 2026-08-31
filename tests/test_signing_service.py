"""SigningService: resolver + provider + caches + trust-root bootstrap."""

import pytest

from approvo.checkpoint import verify_checkpoint
from approvo.crypto.envelope import unwrap_payload
from approvo.crypto.keyprovider import CompositeKeyProvider, InMemoryKeyProvider
from approvo.crypto.keys import KeyDirectory
from approvo.crypto.resolver import (
    SigningContext,
    SigningPurpose,
    StaticKeyResolver,
    TemplateKeyResolver,
)
from approvo.crypto.signing import SigningService, TrustSpec
from approvo.crypto.verifier import verified_signatures
from approvo.errors import KeyResolutionError
from approvo.models import DECISION_PAYLOAD_TYPE, Checkpoint, Decision

pytestmark = pytest.mark.asyncio

NOW = "2026-08-30T12:00:00.000Z"


@pytest.fixture
def provider():
    p = InMemoryKeyProvider()
    p.generate("org-approvals")
    p.generate("org-log")
    return p


@pytest.fixture
def resolver():
    return StaticKeyResolver({
        SigningPurpose.DECISION: "memory://org-approvals",
        SigningPurpose.CHECKPOINT: "memory://org-log",
    })


@pytest.fixture
def signing(provider, resolver):
    return SigningService(provider, resolver)


def _decision(rid="sha256:req", approver="user:casey"):
    return Decision(
        request_id=rid, context_digest="sha256:ctx", verdict="approve",
        approver_id=approver, decided_at=NOW,
    )


async def test_sign_decision_produces_verifiable_envelope(signing):
    d = _decision()
    env = await signing.sign_decision(
        d, ctx=SigningContext(log_id="releases", purpose=SigningPurpose.DECISION)
    )
    assert env["payloadType"] == DECISION_PAYLOAD_TYPE
    assert unwrap_payload(env)["approver_id"] == "user:casey"

    key_dir = KeyDirectory(await signing.trust([
        TrustSpec("memory://org-approvals", "svc:approvo", "decision_issuer", NOW),
    ]))
    vs = verified_signatures(env, key_dir, at_time=NOW)
    assert [v.owner_id for v in vs] == ["svc:approvo"]
    assert vs[0].key_use == "decision_issuer"


async def test_sign_checkpoint(signing):
    cp = Checkpoint(tree_size=3, root_hash="sha256:" + "0" * 64,
                    published_at=NOW, log_id="releases")
    signed = await signing.sign_checkpoint(cp)
    assert len(signed.signatures) == 1

    key_dir = KeyDirectory(await signing.trust([
        TrustSpec("memory://org-log", "svc:approvo-log", "log", NOW),
    ]))
    assert verify_checkpoint(signed, key_dir) == ["svc:approvo-log"]


async def test_trust_from_static(signing):
    refs = await signing.trust_from_static(
        issuer_owner_id="svc:issuer", log_owner_id="svc:log",
        not_before=NOW, log_ids=("releases",),
    )
    uses = {k.key_use: k for k in refs}
    assert set(uses) == {"decision_issuer", "log"}
    assert uses["decision_issuer"].owner_id == "svc:issuer"
    assert uses["log"].log_ids == ("releases",)


async def test_signer_and_pubkey_cached(provider, resolver):
    calls = {"get_signer": 0, "get_public_key": 0}
    orig_signer, orig_pub = provider.get_signer, provider.get_public_key

    async def counted_signer(ref):
        calls["get_signer"] += 1
        return await orig_signer(ref)

    async def counted_pub(ref):
        calls["get_public_key"] += 1
        return await orig_pub(ref)

    provider.get_signer = counted_signer
    provider.get_public_key = counted_pub
    signing = SigningService(provider, resolver)

    ctx = SigningContext(log_id="r", purpose=SigningPurpose.DECISION)
    await signing.signer_for(ctx)
    await signing.signer_for(ctx)
    assert calls["get_signer"] == 1  # second call served from cache

    signing.invalidate()
    await signing.signer_for(ctx)
    assert calls["get_signer"] == 2  # cache cleared -> provider hit again


async def test_self_test_static(signing):
    await signing.self_test()  # signs+verifies a nonce per configured key


async def test_self_test_template_needs_explicit_refs(provider):
    tmpl = TemplateKeyResolver({
        SigningPurpose.DECISION: "memory://{log_id}-approvals",
    })
    svc = SigningService(provider, tmpl)
    with pytest.raises(ValueError, match="key_refs"):
        await svc.self_test()
    # explicit refs work
    provider.generate("releases-approvals")
    await svc.self_test(["memory://releases-approvals"])


async def test_resolver_missing_purpose():
    r = StaticKeyResolver({SigningPurpose.DECISION: "memory://x"})
    with pytest.raises(KeyResolutionError):
        await r.resolve(SigningContext(log_id="r", purpose=SigningPurpose.CHECKPOINT))


async def test_template_resolver_substitutes():
    r = TemplateKeyResolver({
        SigningPurpose.DECISION: "gcpkms://.../{log_id}-approvals/cryptoKeyVersions/1",
    })
    ref = await r.resolve(SigningContext(log_id="prod", purpose=SigningPurpose.DECISION))
    assert ref == "gcpkms://.../prod-approvals/cryptoKeyVersions/1"


async def test_composite_provider_with_signing_service(resolver):
    composite = CompositeKeyProvider([InMemoryKeyProvider()])
    # nothing generated -> resolution ok but provider lookup fails loudly
    svc = SigningService(composite, resolver)
    with pytest.raises(Exception):  # noqa: B017 - KeyProviderError
        await svc.signer_for(SigningContext(log_id="r", purpose=SigningPurpose.DECISION))
