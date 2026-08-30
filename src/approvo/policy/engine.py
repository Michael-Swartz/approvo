"""Policy evaluation: a pure function from evidence to status.

``evaluate`` never trusts a stored status — it takes the request, the
*verified* decisions (signature checking happens in the service layer,
which only passes decisions whose envelopes verified for their claimed
approver), the pinned policy, and the identity roster, and derives the
status from scratch. Run it twice on the same inputs and you get the
same answer; that is what makes the audit trail reproducible.
"""

from __future__ import annotations

from datetime import timedelta

from ..clock import parse_rfc3339
from ..models import ApprovalRequest, Decision, Identity, PolicyResult
from .model import Policy


def _eligible(approver_id: str, policy: Policy, identities: dict[str, Identity]) -> bool:
    if approver_id in policy.allowed_approvers:
        return True
    ident = identities.get(approver_id)
    if ident is None:
        return False
    return any(f"role:{r}" in policy.allowed_approvers for r in ident.roles)


def _roles_satisfied(approver_ids: list[str], policy: Policy,
                     identities: dict[str, Identity]) -> bool:
    for required in policy.require_distinct_roles:
        holders = [
            a for a in approver_ids
            if a in identities and required in identities[a].roles
        ]
        if not holders:
            return False
    return True


def evaluate(
    request: ApprovalRequest,
    decisions: list[Decision],
    policy: Policy,
    identities: dict[str, Identity],
    at_time: str,
) -> PolicyResult:
    reasons: list[str] = []
    now = parse_rfc3339(at_time)

    deadline = min(
        parse_rfc3339(request.not_valid_after),
        parse_rfc3339(request.created_at) + timedelta(seconds=policy.max_age_seconds),
    )

    # Filter to decisions that actually count.
    context = request.context_digest()
    counted: list[Decision] = []
    for d in decisions:
        if d.context_digest != context:
            reasons.append(f"{d.approver_id}: ignored (bound to a different request body)")
            continue
        if not _eligible(d.approver_id, policy, identities):
            reasons.append(f"{d.approver_id}: ignored (not an allowed approver)")
            continue
        if policy.separation_of_duties and d.approver_id == request.requested_by:
            reasons.append(f"{d.approver_id}: ignored (separation of duties: requester)")
            continue
        if parse_rfc3339(d.decided_at) > deadline:
            reasons.append(f"{d.approver_id}: ignored (decided after the window closed)")
            continue
        counted.append(d)

    # One voice per approver: their latest decision wins, so re-submitting
    # the same verdict is idempotent and changing your mind is possible
    # while the request is still open.
    latest: dict[str, Decision] = {}
    for d in sorted(counted, key=lambda d: d.decided_at):
        latest[d.approver_id] = d

    rejecters = [a for a, d in latest.items() if d.verdict == "reject"]
    approvers = [a for a, d in latest.items() if d.verdict == "approve"]

    if policy.reject_is_terminal and rejecters:
        reasons.append(f"rejected by: {', '.join(sorted(rejecters))}")
        return PolicyResult("rejected", tuple(sorted(rejecters)), tuple(reasons))

    if len(approvers) >= policy.threshold and _roles_satisfied(approvers, policy, identities):
        reasons.append(
            f"threshold {policy.threshold} met by: {', '.join(sorted(approvers))}"
        )
        return PolicyResult("approved", tuple(sorted(approvers)), tuple(reasons))

    if now > deadline:
        reasons.append(f"window closed at {request.not_valid_after} without approval")
        return PolicyResult("expired", tuple(sorted(approvers)), tuple(reasons))

    reasons.append(
        f"{len(approvers)}/{policy.threshold} approvals"
        + (
            f"; roles still required: {list(policy.require_distinct_roles)}"
            if policy.require_distinct_roles and not _roles_satisfied(approvers, policy, identities)
            else ""
        )
    )
    return PolicyResult("pending", tuple(sorted(approvers)), tuple(reasons))
