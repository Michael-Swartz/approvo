# ADR-0001 — Requests are content-addressed

**Status:** Accepted

## Context

approvo is called from a backend-for-frontend, over networks, often
behind at-least-once delivery (retried HTTP calls, queue redelivery,
users double-clicking). "Create an approval request" must be safe to
invoke more than once for the same logical intent without producing
duplicate approval workflows.

The obvious approach is a client-supplied idempotency key on
`create_request`. It works, but it pushes a correctness burden onto every
caller and every retry path, and a missing or mismatched key silently
produces a duplicate.

## Decision

A request's identity **is** its content. `request_id =
canonical_hash(identity_dict)` where `identity_dict` is `{schema, kind,
subject, requested_by, policy_id, policy_digest, not_valid_after,
nonce}` — deliberately **excluding** `created_at`.

`create_request` computes the id, looks for an existing
`request.created` event with that id, and returns the existing request if
found. No ledger write, no error.

To open a genuinely distinct request for an identical subject (a second
release attempt after the first expired, say), the caller passes a fresh
`nonce` (`approvo.new_nonce()` → 128 bits).

## Consequences

- Retrying `create_request` with the same arguments is inherently a
  no-op. No idempotency key, no caller burden.
- `request_id` is meaningful and portable: the same request created in two
  environments has the same id.
- `created_at` cannot participate in identity, so it is carried alongside
  and folded into `context_digest` (which decisions bind to) instead.
- Callers who *want* a duplicate must be explicit about it. This is a
  feature — accidental duplicates are the common bug.
- The lookup is one indexed read on `(log_id, request_id)`, not a scan.
