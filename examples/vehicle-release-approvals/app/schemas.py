"""Pydantic request/response models for the HTTP API."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["approve", "reject"]


class ReleaseSubject(BaseModel):
    """Identifies exactly which vehicle software build is up for approval."""

    ecu: str = Field(..., description="Target ECU, e.g. 'brake-controller'")
    artifact_digest: str = Field(..., description="sha256 digest of the built firmware image")
    version: str = Field(..., description="Semantic version of the release, e.g. '3.2.1'")
    vehicle_platform: str = Field(..., description="Vehicle platform this build targets")


class CreateReleaseRequest(BaseModel):
    subject: ReleaseSubject
    requested_by: str = Field(..., description="Identity id of the requester, e.g. 'user:sam'")
    approval_window_hours: int = Field(
        168, gt=0, description="Hours the approval window stays open"
    )


class DecisionRequest(BaseModel):
    approver_id: str = Field(..., description="Identity id of the approver, e.g. 'user:priya'")
    verdict: Verdict
    comment: str = ""


class ReleaseCreatedResponse(BaseModel):
    request_id: str
    kind: str
    subject: dict
    requested_by: str
    policy_id: str
    created_at: str
    not_valid_after: str


class StatusResponse(BaseModel):
    request_id: str
    status: str
    satisfied_by: list[str]
    reasons: list[str]
    subject: dict
    requested_by: str


class ReleaseListItem(BaseModel):
    request_id: str
    status: str
    kind: str
    subject: dict
    requested_by: str
    approvals: int
    threshold: int
    pending_for: list[str]
    created_at: str
    updated_at: str


class ReleaseListResponse(BaseModel):
    items: list[ReleaseListItem]
    next_cursor: str | None = None
