"""Integration: ApprovalService driven by an org-level SigningService.

No per-approver keys, no per-call signer= argument. One custodial
decision-issuer key signs every decision; one log key signs checkpoints.
"""

import pytest

from approvo import (
    ApprovalService,
    Identity,
    InMemoryPolicyStore,
    KeyDirectory,
    Policy,
)
from approvo.clock import FixedClock
from approvo.crypto.keyprovider import InMemoryKeyProvider
from approvo.crypto.resolver import SigningPurpose, StaticKeyResolver
from approvo.crypto.signing import SigningService
from approvo.errors import SignatureInvalid
from tests.memory_stores import (
    MemoryEventStore,
    MemoryIdempotencyStore,
    MemoryProjectionStore,
)

pytestmark = pytest.mark.asyncio

T0 = "2026-08-30T12:00:00.000Z"
WINDOW_END = "2026-09-06T12:00:00.000Z"
NOT_BEFORE = "2026-01-01T00:00:00.000Z"


@pytest.fixture
def provider():
    p = InMemoryKeyProvider()
    p.generate("org-approvals")
    p.generate("org-log")
    return p


@pytest.fixture
def signing(provider):
    return SigningService(
        provider,
        StaticKeyResolver({
            SigningPurpose.DECISION: "memory://org-approvals",
            SigningPurpose.CHECKPOINT: "memory://org-log",
        }),
    )


@pytest.fixture
def identities():
    return {
        "user:casey": Identity("user:casey", ("release-manager",)),
        "user:jordan": Identity("user:jordan", ("qa",)),
        "user:riley": Identity("user:riley", ("sre",)),
    }


@pytest.fixture
def policy():
    return Policy(
        id="release-v1", kind="software-release",
        allowed_approvers=("role:release-manager", "role:qa", "role:sre"),
        threshold=2, required_subject_fields=("artifact_digest", "version"),
    )


@pytest.fixture
async def service(signing, identities, policy):
    events = MemoryEventStore(log_id="releases")
    key_dir = KeyDirectory(await signing.trust_from_static(
        issuer_owner_id="svc:approvo-issuer",
        log_owner_id="svc:approvo-log",
        not_before=NOT_BEFORE,
        log_ids=("releases",),
    ))
    return ApprovalService(
        events=events,
        key_dir=key_dir,
        identities=identities,
        policy_store=InMemoryPolicyStore([policy]),
        projections=MemoryProjectionStore(),
        idempotency=MemoryIdempotencyStore(),
        clock=FixedClock(T0),
        signing=signing,
    )


@pytest.fixture
async def request_id(service):
    req = await service.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "ab" * 32, "version": "1.4.0"},
        requested_by="user:riley",
        policy_id="release-v1",
        not_valid_after=WINDOW_END,
    )
    return req.request_id


async def test_custodial_approval_flow(service, request_id):
    r = await service.submit_decision(
        request_id=request_id, approver_id="user:casey", verdict="approve",
        authn={"method": "oidc", "sub": "casey@example.com", "jti": "a1"},
    )
    assert r.status == "pending"
    r = await service.submit_decision(
        request_id=request_id, approver_id="user:jordan", verdict="approve",
        authn={"method": "oidc", "sub": "jordan@example.com", "jti": "a2"},
    )
    assert r.status == "approved"
    assert r.policy_result.satisfied_by == ("user:casey", "user:jordan")


async def test_authn_is_recorded_in_the_ledger(service, request_id):
    await service.submit_decision(
        request_id=request_id, approver_id="user:casey", verdict="approve",
        authn={"method": "webauthn", "cred_id": "xyz"},
    )
    rec = await service.get_status(request_id)
    assert rec.decisions[0].authn == {"method": "webauthn", "cred_id": "xyz"}


async def test_verify_reports_decision_issuer_signature(service, request_id):
    await service.submit_decision(
        request_id=request_id, approver_id="user:casey", verdict="approve",
    )
    await service.checkpoint()
    report = await service.verify()
    assert report.ok, report.to_dict()
    assert any(
        "decision-issuer key" in c.description for c in report.checks if c.ok
    )


async def test_unknown_approver_rejected_under_custodial_signing(service, request_id):
    # decision_issuer signature is valid, but the named approver is not a
    # known identity -> not authorized.
    with pytest.raises(SignatureInvalid):
        await service.submit_decision(
            request_id=request_id, approver_id="user:stranger", verdict="approve",
        )


async def test_issuer_key_scoped_to_other_log_is_rejected(
    signing, identities, policy
):
    # trust an issuer key scoped to a DIFFERENT log than the service runs
    events = MemoryEventStore(log_id="releases")
    key_dir = KeyDirectory(await signing.trust_from_static(
        issuer_owner_id="svc:issuer", log_owner_id="svc:log",
        not_before=NOT_BEFORE, log_ids=("some-other-log",),
    ))
    svc = ApprovalService(
        events=events, key_dir=key_dir, identities=identities,
        policy_store=InMemoryPolicyStore([policy]),
        clock=FixedClock(T0), signing=signing,
    )
    req = await svc.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "cd" * 32, "version": "2.0.0"},
        requested_by="user:riley", policy_id="release-v1", not_valid_after=WINDOW_END,
    )
    with pytest.raises(SignatureInvalid):
        await svc.submit_decision(
            request_id=req.request_id, approver_id="user:casey", verdict="approve",
        )


async def test_submit_decision_without_signer_or_signing_service_errors(
    identities, policy
):
    svc = ApprovalService(
        events=MemoryEventStore(log_id="releases"),
        key_dir=KeyDirectory(),
        identities=identities,
        policy_store=InMemoryPolicyStore([policy]),
        clock=FixedClock(T0),
    )
    req = await svc.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "ef" * 32, "version": "3.0.0"},
        requested_by="user:riley", policy_id="release-v1", not_valid_after=WINDOW_END,
    )
    with pytest.raises(SignatureInvalid, match="signer"):
        await svc.submit_decision(
            request_id=req.request_id, approver_id="user:casey", verdict="approve",
        )
