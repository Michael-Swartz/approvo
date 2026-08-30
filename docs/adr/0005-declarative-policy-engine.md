# ADR-0005 — Policies are declarative data, evaluated by a pure function

**Status:** Accepted

## Context

Something has to decide whether the decisions on a request satisfy the
rules: how many approvals, from whom, covering which roles, within what
window, with the requester excluded. Options ranged from "a callback the
caller supplies" to "embed a policy language (Rego / CEL)".

The overriding constraint: an auditor must be able to re-derive *why* a
request was approved, years later, deterministically. That rules out
anything whose evaluation depends on external state at evaluation time.

## Decision

A `Policy` is a frozen dataclass of primitive fields:
`allowed_approvers`, `threshold`, `require_distinct_roles`,
`separation_of_duties`, `reject_is_terminal`, `max_age_seconds`,
`required_subject_fields`. It is content-addressed (`policy.digest`), and
each request pins that digest.

`approvo.policy.engine.evaluate(request, decisions, policy, identities,
at_time)` is a **pure function** returning a `PolicyResult{status,
satisfied_by, reasons}`. Same inputs, same output, forever. The `reasons`
list is a human-readable trace of what counted and what didn't.

The service refuses to evaluate a request against a policy whose current
digest doesn't match the pin (`PolicyMismatch`).

## What we did not do

- **No embedded policy language.** Rego/CEL are powerful but they are
  another dependency, another thing to sandbox, and another thing an
  auditor has to learn to trust. The 80% case — thresholds, roles,
  separation of duties, windows — is a dozen fields.
- **No caller callback as the primary interface.** It defeats
  reproducibility and auditability. Callers who genuinely need richer
  eligibility rules compute the eligible set upstream and pass it as an
  explicit `allowed_approvers` list, keeping the *counting* logic in
  approvo where it stays reproducible.

## Consequences

- Policy evaluation has no I/O, so `verify()` can re-run every historical
  decision offline.
- Policy changes are versioned by construction: mutate `release-v1` and
  in-flight requests raise `PolicyMismatch`; instead you add `release-v2`
  and old requests keep evaluating under the rules they were opened with.
- Genuinely complex org rules push work to the integrator. Accepted: those
  rules usually *shouldn't* be frozen into an audit artifact anyway.
- `require_distinct_roles` covers the common "one from team A, one from
  team B" case; anything more exotic is a new field or an upstream
  pre-filter.
