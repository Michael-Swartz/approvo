# Policies

A policy is a frozen dataclass — plain data you can review, sign, store,
and diff. It is content-addressed: `policy.digest` is the canonical hash
of its fields, and every request pins that digest at creation.

## Fields

```python
from approvo import Policy

Policy(
    id="release-v1",
    kind="software-release",              # must equal the request's kind
    allowed_approvers=(                   # ids and/or "role:<name>"
        "role:release-manager",
        "role:qa",
        "user:security-oncall",
    ),
    threshold=2,                          # distinct counting approvals needed
    require_distinct_roles=("qa", "sre"), # approvals must cover each of these
    separation_of_duties=True,            # requester's own approval never counts
    reject_is_terminal=True,              # any counting reject => rejected
    max_age_seconds=7 * 24 * 3600,        # window from request creation
    required_subject_fields=("artifact_digest", "version"),
)
```

## How evaluation works

`approvo.policy.engine.evaluate(request, decisions, policy, identities,
at_time)` is a **pure function**. Given the same inputs it always returns
the same `PolicyResult`. The service passes it only decisions whose DSSE
envelope already verified for the approver they name.

A decision **counts** when all of these hold:

1. `decision.context_digest == request.context_digest()` — bound to this
   exact request body.
2. The approver is eligible: their id is in `allowed_approvers`, or they
   hold a role listed as `role:<name>`.
3. `separation_of_duties` is off, or the approver is not
   `request.requested_by`.
4. `decided_at` is at or before the window close
   (`min(not_valid_after, created_at + max_age_seconds)`).

Then:

- One voice per approver — their **latest** decision wins, so
  re-submitting the same verdict is idempotent and changing your mind
  before the window closes is allowed.
- If `reject_is_terminal` and any counting decision is `reject` →
  **`rejected`**.
- Else if counting approvals ≥ `threshold` **and** `require_distinct_roles`
  are all covered → **`approved`**.
- Else if `at_time` is past the window → **`expired`**.
- Else → **`pending`**, with `reasons` explaining what is outstanding.

## Examples

### Two-person rule

```python
Policy(id="two-person", kind="prod-change",
       allowed_approvers=("role:engineer",), threshold=2)
```

### One from each of two teams

```python
Policy(id="cross-team", kind="schema-migration",
       allowed_approvers=("role:dba", "role:app-owner"),
       threshold=2, require_distinct_roles=("dba", "app-owner"))
```

Two DBAs approving is still `pending` — the `app-owner` role is uncovered.

### Break-glass: single approver, short window

```python
Policy(id="break-glass", kind="incident-access",
       allowed_approvers=("role:incident-commander",),
       threshold=1, max_age_seconds=3600)
```

### Allow self-approval (e.g. personal-data export requests)

```python
Policy(id="self-serve", kind="data-export",
       allowed_approvers=("role:employee",), threshold=1,
       separation_of_duties=False)
```

## The policy store

`ApprovalService` takes a `PolicyStore` — anything with
`get(policy_id) -> Policy`. `InMemoryPolicyStore` ships for tests and
small deployments. Back it with a table, a config repo, a bundle from your
policy pipeline — whatever fits. The only rule: once a request has pinned
a digest, the policy it resolves to must keep hashing to that digest, or
`get_status` raises `PolicyMismatch`.

To change a policy for *new* requests, add a new version
(`release-v2`) rather than mutating `release-v1`. In-flight requests keep
evaluating against the rules they were opened under — which is usually
exactly what an auditor wants to see.

## Externalizing eligibility

If "who may approve" gets more complex than roles and ids (attribute
rules, org-chart lookups, time-of-day), compute the eligible set in your
BFF and express the policy as an explicit `allowed_approvers` list per
request kind, or wrap `evaluate` with your own pre-filter. approvo keeps
the *counting* logic — thresholds, distinct roles, separation of duties,
windows — because that is the part that has to be reproducible years
later. See [ADR-0005](adr/0005-declarative-policy-engine.md).
