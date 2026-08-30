"""Building read-model views from authoritative records.

Pure functions. The projection is a *rendering* of a
:class:`~approvo.models.Record`, so it can always be rebuilt and can never
disagree with the ledger for long — and if it does, the ledger wins.
"""

from __future__ import annotations

from .models import ApprovalRequest, Identity, Record, RequestView
from .policy.model import Policy


def eligible_approvers(
    request: ApprovalRequest, policy: Policy, identities: dict[str, Identity]
) -> list[str]:
    """Identity ids that could cast a counting vote on *request*."""
    out = []
    for ident in identities.values():
        if policy.separation_of_duties and ident.id == request.requested_by:
            continue
        if ident.id in policy.allowed_approvers or any(
            f"role:{r}" in policy.allowed_approvers for r in ident.roles
        ):
            out.append(ident.id)
    return sorted(out)


def build_view(
    record: Record,
    policy: Policy,
    identities: dict[str, Identity],
    *,
    last_seq: int,
    updated_at: str,
) -> RequestView:
    decided = {d.approver_id for d in record.decisions}
    eligible = eligible_approvers(record.request, policy, identities)
    return RequestView(
        request_id=record.request.request_id,
        kind=record.request.kind,
        status=record.status,
        requested_by=record.request.requested_by,
        policy_id=record.request.policy_id,
        subject=record.request.subject,
        created_at=record.request.created_at,
        not_valid_after=record.request.not_valid_after,
        updated_at=updated_at,
        approvals=len(record.policy_result.satisfied_by)
        if record.status != "rejected"
        else 0,
        threshold=policy.threshold,
        approvers=record.policy_result.satisfied_by,
        pending_for=tuple(a for a in eligible if a not in decided)
        if record.status == "pending"
        else (),
        last_seq=last_seq,
    )
