from __future__ import annotations

import pytest

from approvo import (
    ApprovalService,
    Ed25519Signer,
    FixedClock,
    Identity,
    InMemoryPolicyStore,
    KeyDirectory,
    Policy,
)
from tests.memory_stores import (
    MemoryEventStore,
    MemoryIdempotencyStore,
    MemoryProjectionStore,
)

T0 = "2026-08-30T12:00:00.000Z"
T_LATER = "2026-08-30T13:00:00.000Z"
T_EXPIRED = "2026-09-30T12:00:00.000Z"
WINDOW_END = "2026-09-06T12:00:00.000Z"


@pytest.fixture
def signers() -> dict[str, Ed25519Signer]:
    return {
        "user:casey": Ed25519Signer.generate(),
        "user:jordan": Ed25519Signer.generate(),
        "user:riley": Ed25519Signer.generate(),
        "log:main": Ed25519Signer.generate(),
    }


@pytest.fixture
def key_dir(signers) -> KeyDirectory:
    kd = KeyDirectory()
    for owner, signer in signers.items():
        key_use = "log" if owner == "log:main" else "approver"
        kd.add(
            signer.public_key_ref(
                owner, not_before="2026-01-01T00:00:00.000Z", key_use=key_use
            )
        )
    return kd


@pytest.fixture
def identities() -> dict[str, Identity]:
    return {
        "user:casey": Identity("user:casey", ("release-manager",)),
        "user:jordan": Identity("user:jordan", ("qa",)),
        "user:riley": Identity("user:riley", ("sre",)),
    }


@pytest.fixture
def policy() -> Policy:
    return Policy(
        id="release-v1",
        kind="software-release",
        allowed_approvers=("role:release-manager", "role:qa", "role:sre"),
        threshold=2,
        required_subject_fields=("artifact_digest", "version"),
    )


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(T0)


@pytest.fixture
def events() -> MemoryEventStore:
    return MemoryEventStore(log_id="test")


@pytest.fixture
def service(signers, key_dir, identities, policy, clock, events) -> ApprovalService:
    return ApprovalService(
        events,
        key_dir,
        identities,
        InMemoryPolicyStore([policy]),
        projections=MemoryProjectionStore(),
        idempotency=MemoryIdempotencyStore(),
        clock=clock,
        log_signer=signers["log:main"],
    )


@pytest.fixture
async def request_id(service) -> str:
    req = await service.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "ab" * 32, "version": "1.4.0"},
        requested_by="user:riley",
        policy_id="release-v1",
        not_valid_after=WINDOW_END,
    )
    return req.request_id
