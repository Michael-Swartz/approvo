"""End-to-end service behavior: approvals, idempotency, tamper detection."""

from __future__ import annotations

import pytest

from approvo import Ed25519Signer
from approvo.crypto.envelope import wrap
from approvo.errors import (
    IdempotencyConflict,
    PolicyMismatch,
    RequestNotFound,
    SignatureInvalid,
)
from approvo.models import DECISION_PAYLOAD_TYPE, Decision

# kept in step with tests/conftest.py
T_LATER = "2026-08-30T13:00:00.000Z"
WINDOW_END = "2026-09-06T12:00:00.000Z"

pytestmark = pytest.mark.asyncio


async def approve(service, request_id, who, signers, **kw):
    return await service.submit_decision(
        request_id=request_id, approver_id=who, verdict="approve",
        signer=signers[who], **kw,
    )


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


async def test_full_approval_flow(service, signers, request_id):
    assert (await service.get_status(request_id)).status == "pending"

    rec = await approve(service, request_id, "user:casey", signers)
    assert rec.status == "pending"  # 1 of 2

    rec = await approve(service, request_id, "user:jordan", signers)
    assert rec.status == "approved"
    assert rec.policy_result.satisfied_by == ("user:casey", "user:jordan")


async def test_reject_is_terminal(service, signers, request_id):
    await approve(service, request_id, "user:casey", signers)
    rec = await service.submit_decision(
        request_id=request_id, approver_id="user:jordan", verdict="reject",
        signer=signers["user:jordan"], comment="failed smoke test",
    )
    assert rec.status == "rejected"


async def test_projection_tracks_status(service, signers, request_id):
    await approve(service, request_id, "user:casey", signers)
    view = await service.get_view(request_id)
    assert view.status == "pending"
    assert view.approvals == 1
    assert "user:jordan" in view.pending_for

    await approve(service, request_id, "user:jordan", signers)
    view = await service.get_view(request_id)
    assert view.status == "approved"
    assert view.pending_for == ()


async def test_query_filters(service, signers, request_id):
    from approvo.models import RequestQuery

    page = await service.query(RequestQuery(status=("pending",)))
    assert [v.request_id for v in page.items] == [request_id]

    page = await service.query(RequestQuery(awaiting="user:casey"))
    assert [v.request_id for v in page.items] == [request_id]

    await approve(service, request_id, "user:casey", signers)
    await approve(service, request_id, "user:jordan", signers)
    page = await service.query(RequestQuery(status=("pending",)))
    assert page.items == ()


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #


async def test_create_request_is_idempotent(service, request_id):
    req2 = await service.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "ab" * 32, "version": "1.4.0"},
        requested_by="user:riley",
        policy_id="release-v1",
        not_valid_after=WINDOW_END,
    )
    assert req2.request_id == request_id
    page = await service.query()
    assert len(page.items) == 1  # no duplicate


async def test_nonce_distinguishes_intentional_duplicates(service, request_id):
    from approvo import new_nonce

    req2 = await service.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "ab" * 32, "version": "1.4.0"},
        requested_by="user:riley",
        policy_id="release-v1",
        not_valid_after=WINDOW_END,
        nonce=new_nonce(),
    )
    assert req2.request_id != request_id


async def test_decision_replay_is_idempotent(service, signers, request_id):
    for _ in range(3):
        await approve(service, request_id, "user:casey", signers,
                      idempotency_key="deploy-retry-1")
    rec = await service.get_status(request_id)
    assert len(rec.decisions) == 1  # one ledger entry despite three calls


async def test_idempotency_conflict_detected(service, signers, request_id):
    await approve(service, request_id, "user:casey", signers, idempotency_key="k1")
    with pytest.raises(IdempotencyConflict):
        await service.submit_decision(
            request_id=request_id, approver_id="user:casey", verdict="reject",
            signer=signers["user:casey"], idempotency_key="k1",
        )


# --------------------------------------------------------------------------- #
# Signature enforcement
# --------------------------------------------------------------------------- #


async def test_wrong_signer_rejected_before_persisting(service, signers, request_id):
    with pytest.raises(SignatureInvalid):
        await service.submit_decision(
            request_id=request_id, approver_id="user:casey", verdict="approve",
            signer=signers["user:jordan"],  # jordan's key, casey's name
        )
    assert len((await service.get_status(request_id)).decisions) == 0


async def test_unregistered_key_rejected(service, request_id):
    with pytest.raises(SignatureInvalid):
        await service.submit_decision(
            request_id=request_id, approver_id="user:casey", verdict="approve",
            signer=Ed25519Signer.generate(),
        )


async def test_unknown_request(service, signers):
    with pytest.raises(RequestNotFound):
        await service.submit_decision(
            request_id="sha256:" + "0" * 64, approver_id="user:casey",
            verdict="approve", signer=signers["user:casey"],
        )


# --------------------------------------------------------------------------- #
# Detached signing ceremony
# --------------------------------------------------------------------------- #


async def test_detached_signing_flow(service, signers, request_id):
    challenge = await service.prepare_decision(
        request_id=request_id, approver_id="user:casey", verdict="approve",
    )
    # client signs the PAE bytes it was handed
    import base64

    sig = signers["user:casey"].sign(base64.standard_b64decode(challenge.pae_b64))
    envelope = service.envelope_from_challenge(
        challenge,
        [{"keyid": signers["user:casey"].key_id(),
          "sig": base64.standard_b64encode(sig).decode()}],
    )
    rec = await service.submit_signed_decision(envelope)
    assert rec.policy_result.satisfied_by == ("user:casey",)


async def test_signed_decision_bound_to_request_body(service, signers, request_id):
    """A decision built for one request body must not apply to another."""
    other = await service.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "cd" * 32, "version": "9.9.9"},
        requested_by="user:riley", policy_id="release-v1",
        not_valid_after=WINDOW_END, nonce="other",
    )
    forged = Decision(
        request_id=request_id,
        context_digest=other.context_digest(),  # bound to the wrong body
        verdict="approve", approver_id="user:casey", decided_at=T_LATER,
    )
    envelope = wrap(forged.to_dict(), DECISION_PAYLOAD_TYPE, [signers["user:casey"]])
    with pytest.raises(SignatureInvalid):
        await service.submit_signed_decision(envelope)


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


async def test_verify_clean_ledger(service, signers, request_id):
    await approve(service, request_id, "user:casey", signers)
    await service.checkpoint()
    report = await service.verify()
    assert report.ok, report.to_dict()


async def test_verify_detects_swapped_subject(service, signers, request_id, events):
    await approve(service, request_id, "user:casey", signers)
    for entry in events._entries:
        if entry.event_type == "request.created":
            entry.payload["subject"]["version"] = "6.6.6"
    report = await service.verify()
    assert not report.ok
    assert any("hash chain" in c.description for c in report.failures)


async def test_verify_detects_forged_decision(service, signers, request_id, events):
    """An attacker with ledger write access but no approver key."""
    req = (await service.get_status(request_id)).request
    forged = Decision(
        request_id=request_id, context_digest=req.context_digest(),
        verdict="approve", approver_id="user:casey", decided_at=T_LATER,
    )
    evil = wrap(forged.to_dict(), DECISION_PAYLOAD_TYPE, [Ed25519Signer.generate()])
    prev = await events.head()
    from approvo.chain import next_entry

    await events.append(next_entry(
        prev, event_type="decision.recorded", payload=evil,
        at_time=T_LATER, request_id=request_id,
    ))

    assert (await service.get_status(request_id)).status == "pending"  # never counts
    report = await service.verify()
    assert any(not c.ok and "valid signature" in c.description for c in report.checks)


async def test_verify_with_pinned_checkpoint_detects_rewrite(service, signers, request_id, events):
    await approve(service, request_id, "user:casey", signers)
    pinned = await service.checkpoint()

    del events._entries[1]  # rewrite history
    events._by_request.clear()
    for e in events._entries:
        if e.request_id:
            events._by_request.setdefault(e.request_id, []).append(e.seq)

    report = await service.verify(trusted_checkpoint=pinned)
    assert not report.ok


# --------------------------------------------------------------------------- #
# Policy integrity
# --------------------------------------------------------------------------- #


async def test_policy_change_after_request_is_rejected(service, signers, request_id):
    # mutate the stored policy so its digest no longer matches the pin
    stored = service.policy_store.get("release-v1")
    service.policy_store._policies["release-v1"] = type(stored)(
        **{**stored.to_dict(), "threshold": 1}
    )
    with pytest.raises(PolicyMismatch):
        await service.get_status(request_id)


async def test_subject_missing_required_field_rejected(service):
    from approvo.errors import SubjectConstraintViolation

    with pytest.raises(SubjectConstraintViolation):
        await service.create_request(
            kind="software-release", subject={"version": "1.0.0"},  # no artifact_digest
            requested_by="user:riley", policy_id="release-v1",
            not_valid_after=WINDOW_END,
        )


# --------------------------------------------------------------------------- #
# Projection rebuild
# --------------------------------------------------------------------------- #


async def test_rebuild_projections_matches_ledger(service, signers, request_id):
    await approve(service, request_id, "user:casey", signers)
    await approve(service, request_id, "user:jordan", signers)

    await service.projections.clear()
    assert await service.get_view(request_id) is None

    n = await service.rebuild_projections()
    assert n == 1
    view = await service.get_view(request_id)
    assert view.status == "approved"
