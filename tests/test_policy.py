"""Policy engine unit tests: pure evaluation, no ledger."""

from approvo import Identity, Policy
from approvo.models import ApprovalRequest, Decision
from approvo.policy.engine import evaluate

T0 = "2026-08-30T12:00:00.000Z"
T1 = "2026-08-30T13:00:00.000Z"
WINDOW_END = "2026-09-06T12:00:00.000Z"
AFTER_WINDOW = "2026-09-30T12:00:00.000Z"

IDENTITIES = {
    "user:casey": Identity("user:casey", ("release-manager",)),
    "user:jordan": Identity("user:jordan", ("qa",)),
    "user:riley": Identity("user:riley", ("sre",)),
}


def make_policy(**overrides) -> Policy:
    defaults = {
        "id": "p",
        "kind": "software-release",
        "allowed_approvers": ("role:release-manager", "role:qa", "role:sre"),
        "threshold": 2,
    }
    return Policy(**{**defaults, **overrides})


def make_request(policy: Policy, requested_by="user:riley") -> ApprovalRequest:
    return ApprovalRequest(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "ab" * 32, "version": "1.4.0"},
        requested_by=requested_by,
        policy_id=policy.id,
        policy_digest=policy.digest,
        created_at=T0,
        not_valid_after=WINDOW_END,
    )


def decision(req, approver, verdict="approve", at=T1) -> Decision:
    return Decision(
        request_id=req.request_id,
        context_digest=req.context_digest(),
        verdict=verdict,
        approver_id=approver,
        decided_at=at,
    )


def test_threshold_met():
    policy = make_policy()
    req = make_request(policy)
    decisions = [decision(req, "user:casey"), decision(req, "user:jordan")]
    assert evaluate(req, decisions, policy, IDENTITIES, T1).status == "approved"


def test_threshold_not_met():
    policy = make_policy()
    req = make_request(policy)
    assert evaluate(req, [decision(req, "user:casey")], policy, IDENTITIES, T1).status == "pending"


def test_separation_of_duties():
    policy = make_policy()
    req = make_request(policy, requested_by="user:casey")
    decisions = [decision(req, "user:casey"), decision(req, "user:jordan")]
    result = evaluate(req, decisions, policy, IDENTITIES, T1)
    assert result.status == "pending"  # casey's self-approval didn't count
    assert "user:casey" not in result.satisfied_by


def test_self_approval_allowed_when_disabled():
    policy = make_policy(separation_of_duties=False)
    req = make_request(policy, requested_by="user:casey")
    decisions = [decision(req, "user:casey"), decision(req, "user:jordan")]
    assert evaluate(req, decisions, policy, IDENTITIES, T1).status == "approved"


def test_uneligible_approver_ignored():
    policy = make_policy(allowed_approvers=("role:qa",), threshold=1)
    req = make_request(policy)
    result = evaluate(req, [decision(req, "user:casey")], policy, IDENTITIES, T1)
    assert result.status == "pending"


def test_require_distinct_roles():
    policy = make_policy(require_distinct_roles=("qa", "sre"), threshold=2)
    req = make_request(policy, requested_by="user:casey")
    two_qa_like = [decision(req, "user:casey"), decision(req, "user:jordan")]
    assert evaluate(req, two_qa_like, policy, IDENTITIES, T1).status == "pending"  # no sre
    covered = [decision(req, "user:jordan"), decision(req, "user:riley")]
    assert evaluate(req, covered, policy, IDENTITIES, T1).status == "approved"


def test_latest_verdict_per_approver_wins():
    policy = make_policy(threshold=1, reject_is_terminal=True)
    req = make_request(policy)
    decisions = [
        decision(req, "user:jordan", "reject", at=T1),
        decision(req, "user:jordan", "approve", at="2026-08-30T14:00:00.000Z"),
    ]
    assert evaluate(req, decisions, policy, IDENTITIES, "2026-08-30T15:00:00.000Z").status == "approved"


def test_expiry():
    policy = make_policy()
    req = make_request(policy)
    result = evaluate(req, [decision(req, "user:casey")], policy, IDENTITIES, AFTER_WINDOW)
    assert result.status == "expired"


def test_late_decision_ignored():
    policy = make_policy(threshold=1)
    req = make_request(policy)
    late = [decision(req, "user:jordan", at=AFTER_WINDOW)]
    assert evaluate(req, late, policy, IDENTITIES, AFTER_WINDOW).status == "expired"


def test_decision_bound_to_other_request_ignored():
    policy = make_policy(threshold=1)
    req = make_request(policy)
    other = ApprovalRequest(
        kind="software-release",
        subject={"artifact_digest": "sha256:" + "cd" * 32, "version": "9.9.9"},
        requested_by="user:riley",
        policy_id=policy.id,
        policy_digest=policy.digest,
        created_at=T0,
        not_valid_after=WINDOW_END,
    )
    # request_id points at req but context_digest is other's — must not count
    d = Decision(
        request_id=req.request_id,
        context_digest=other.context_digest(),
        verdict="approve",
        approver_id="user:jordan",
        decided_at=T1,
    )
    assert evaluate(req, [d], policy, IDENTITIES, T1).status == "pending"
