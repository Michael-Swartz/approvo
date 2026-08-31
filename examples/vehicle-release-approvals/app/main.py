"""FastAPI backend-for-frontend powering vehicle software release approvals.

approvo is a library, not a service — this app is the "your BFF" box from
the architecture diagram in the top-level README. It owns HTTP, auth
(simplified for this demo: an ``approver_id`` in the request body stands
in for whatever your real auth middleware verifies), and MongoDB. approvo
owns content-addressed requests, signed decisions, and the tamper-evident
ledger.

Run with MongoDB up (``docker compose up -d``) and:

    uvicorn app.main:app --reload

See the example README for the full walkthrough.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient

from approvo import ApprovalService, RequestQuery, to_rfc3339
from approvo.errors import (
    ApprovoError,
    ChallengeExpired,
    IdempotencyConflict,
    LedgerConflict,
    RequestNotFound,
    SignatureInvalid,
    SubjectConstraintViolation,
    UnknownPolicy,
)

from .config import settings
from .identities import RELEASE_POLICY_ID, build_bootstrap
from .mongo_stores import MongoEventStore, MongoIdempotencyStore, MongoProjectionStore
from .schemas import (
    CreateReleaseRequest,
    DecisionRequest,
    ReleaseCreatedResponse,
    ReleaseListItem,
    ReleaseListResponse,
    StatusResponse,
)

# Exceptions -> HTTP status codes, per the mapping documented in approvo.errors.
_ERROR_STATUS = {
    RequestNotFound: 404,
    UnknownPolicy: 404,
    SubjectConstraintViolation: 422,
    IdempotencyConflict: 409,
    ChallengeExpired: 410,
    SignatureInvalid: 400,
    LedgerConflict: 503,
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    client: AsyncIOMotorClient = AsyncIOMotorClient(settings.mongo_uri)
    db = client[settings.mongo_db]

    events = MongoEventStore(db, log_id=settings.log_id)
    projections = MongoProjectionStore(db, log_id=settings.log_id)
    idempotency = MongoIdempotencyStore(db, log_id=settings.log_id)
    await events.ensure_indexes()
    await projections.ensure_indexes()
    await idempotency.ensure_indexes()

    bootstrap = build_bootstrap()
    service = ApprovalService(
        events=events,
        key_dir=bootstrap.key_dir,
        identities=bootstrap.identities,
        policy_store=bootstrap.policy_store,
        projections=projections,
        idempotency=idempotency,
        log_signer=bootstrap.log_signer,
    )

    app.state.mongo_client = client
    app.state.service = service
    app.state.bootstrap = bootstrap
    try:
        yield
    finally:
        client.close()


app = FastAPI(
    title="Vehicle Software Release Approvals",
    description=(
        "End-to-end example: approvo (audit/signing/policy engine) + FastAPI (HTTP) "
        "+ MongoDB (storage) approving vehicle ECU firmware releases."
    ),
    version="0.1.0",
    lifespan=lifespan,
)


def get_service() -> ApprovalService:
    return app.state.service


@app.exception_handler(ApprovoError)
async def approvo_error_handler(request, exc: ApprovoError):
    status_code = _ERROR_STATUS.get(type(exc), 400)
    return JSONResponse(
        status_code=status_code, content={"detail": str(exc) or type(exc).__name__}
    )


@app.get("/identities")
async def list_identities():
    """Demo roster: which approvers exist and what role each holds.

    A real BFF would resolve this from your auth/HR system, not a static
    dict — this endpoint exists purely so the walkthrough in the README
    can look up approver ids without inspecting the source.
    """
    bootstrap = app.state.bootstrap
    return {
        identity_id: {"roles": list(identity.roles)}
        for identity_id, identity in bootstrap.identities.items()
    }


@app.post("/releases", response_model=ReleaseCreatedResponse, status_code=201)
async def create_release(
    body: CreateReleaseRequest, service: ApprovalService = Depends(get_service)
):
    """Open a release-approval request. Content-addressed: calling this twice
    with the same subject/requester/window returns the same request."""
    not_valid_after = to_rfc3339(
        datetime.now(timezone.utc) + timedelta(hours=body.approval_window_hours)
    )
    request = await service.create_request(
        kind="vehicle-software-release",
        subject=body.subject.model_dump(),
        requested_by=body.requested_by,
        policy_id=RELEASE_POLICY_ID,
        not_valid_after=not_valid_after,
    )
    return ReleaseCreatedResponse(
        request_id=request.request_id,
        kind=request.kind,
        subject=request.subject,
        requested_by=request.requested_by,
        policy_id=request.policy_id,
        created_at=request.created_at,
        not_valid_after=request.not_valid_after,
    )


@app.post("/releases/{request_id}/decisions", response_model=StatusResponse)
async def submit_decision(
    request_id: str, body: DecisionRequest, service: ApprovalService = Depends(get_service)
):
    """Record an approve/reject decision.

    This demo signs server-side (``submit_decision``) for simplicity: the
    approver's identity is only whatever the request body claims. A
    production deployment should keep signing keys on the approver's own
    device and use ``prepare_decision`` / ``submit_signed_decision``
    instead — see the "Detached signing" section of
    ``docs/getting-started.md`` in the main repo for that ceremony.
    """
    bootstrap = app.state.bootstrap
    signer = bootstrap.signers.get(body.approver_id)
    if signer is None:
        raise HTTPException(
            status_code=400,
            detail=f"unknown approver_id {body.approver_id!r}; see GET /identities",
        )
    record = await service.submit_decision(
        request_id=request_id,
        approver_id=body.approver_id,
        verdict=body.verdict,
        signer=signer,
        comment=body.comment,
    )
    return StatusResponse(
        request_id=record.request.request_id,
        status=record.status,
        satisfied_by=list(record.policy_result.satisfied_by),
        reasons=list(record.policy_result.reasons),
        subject=record.request.subject,
        requested_by=record.request.requested_by,
    )


@app.get("/releases/{request_id}", response_model=StatusResponse)
async def get_release_status(request_id: str, service: ApprovalService = Depends(get_service)):
    """Authoritative status, re-derived from the ledger every call. Gate on this."""
    record = await service.get_status(request_id)
    return StatusResponse(
        request_id=record.request.request_id,
        status=record.status,
        satisfied_by=list(record.policy_result.satisfied_by),
        reasons=list(record.policy_result.reasons),
        subject=record.request.subject,
        requested_by=record.request.requested_by,
    )


@app.get("/releases", response_model=ReleaseListResponse)
async def list_releases(
    status: list[str] | None = Query(default=None),
    awaiting: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
    service: ApprovalService = Depends(get_service),
):
    """List/filter releases for a UI. Reads the projection store — fast,
    but not authoritative; gate deploys on GET /releases/{id} instead."""
    page = await service.query(
        RequestQuery(
            status=tuple(status) if status else None,  # type: ignore[arg-type]
            awaiting=awaiting,
            limit=limit,
            cursor=cursor,
        )
    )
    return ReleaseListResponse(
        items=[
            ReleaseListItem(
                request_id=v.request_id,
                status=v.status,
                kind=v.kind,
                subject=v.subject,
                requested_by=v.requested_by,
                approvals=v.approvals,
                threshold=v.threshold,
                pending_for=list(v.pending_for),
                created_at=v.created_at,
                updated_at=v.updated_at,
            )
            for v in page.items
        ],
        next_cursor=page.next_cursor,
    )


@app.post("/checkpoint")
async def publish_checkpoint(service: ApprovalService = Depends(get_service)):
    """Publish a signed Merkle tree head over the current ledger."""
    cp = await service.checkpoint()
    return cp.to_dict()


@app.get("/verify")
async def verify_ledger(service: ApprovalService = Depends(get_service)):
    """Re-derive and re-check every entry in the ledger. Never trust storage."""
    report = await service.verify()
    return report.to_dict()
