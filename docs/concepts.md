# Concepts

approvo has a small number of moving parts. This page explains each one by
the attack it defends against.

## The request

An `ApprovalRequest` describes *what is being approved*: a `kind`
(`"software-release"`, `"db-migration"`, anything), a `subject` (a
kind-specific JSON object), who asked, which policy governs it, and a
window (`not_valid_after`).

Its `request_id` is the canonical hash of its identity-bearing fields —
**not** including `created_at`. Two `create_request` calls with the same
arguments therefore produce the same id.

- **Attack: duplicate requests from retries.** A network blip makes your
  BFF call `create_request` twice. Without content-addressing you get two
  approval workflows for one release. With it, the second call returns the
  first request. ([ADR-0001](adr/0001-content-addressed-requests.md))
- **Attack: "that's not the request I approved".** See `context_digest`
  below.

## The decision

A `Decision` is an approver's `approve` or `reject`. It carries:

- `request_id` — which request,
- `context_digest` — the canonical hash of the **full** request body
  (including `created_at`) as the approver saw it,
- `verdict`, `approver_id`, `decided_at`, an optional `comment`,
- `idempotency_key`.

It travels as a **DSSE envelope**: the canonical decision bytes plus one
or more detached signatures over the
[PAE](https://github.com/secure-systems-lab/dsse) of the payload type and
body.

- **Attack: forge an approval.** Without a signature, anyone with write
  access to your database inserts a `decision.recorded` row and the
  release ships. With one, the forged decision fails signature
  verification, never counts toward status, and `verify()` flags it.
- **Attack: bait-and-switch.** Casey approves version 1.4.0. An attacker
  edits the request's subject to 6.6.6 and ships that. The decision's
  `context_digest` no longer matches the request body, so the approval
  stops counting and `verify()` reports it.
- **Attack: replay a decision onto another request.** The envelope's
  `context_digest` is bound to one specific request body; it will not
  satisfy any other.
- **Attack: a compromised BFF signs for everyone.** Use [detached
  signing](getting-started.md#detached-signing-recommended-for-production):
  `prepare_decision` hands the client the bytes to sign, and the private
  key never reaches your server.
  ([ADR-0002](adr/0002-dsse-ed25519-detached-signing.md))

## The key directory

`KeyDirectory` maps a keyid to a `KeyRef`: a public key, its owner, and a
validity window (`not_before` / `not_after` / `revoked_at`). It is the
**trust root** at verification time.

A signature counts only if its keyid resolves to a key that was valid **at
the decision's timestamp** — not at verification time. An approval signed
with a then-valid key that was later rotated or revoked stays valid;
`revoked_at` only invalidates signatures dated *after* the revocation.

- **Attack: use a stolen, since-revoked key.** Revoke it in the directory
  with a `revoked_at` timestamp; every decision dated after that stops
  counting.
- **Attack: tamper with the directory itself.** approvo cannot help here —
  see [Security model](security.md). Protect `keys.json` like the ledger.

## The policy

A `Policy` is **data, not code**: `allowed_approvers` (ids and/or
`role:<name>`), `threshold`, optional `require_distinct_roles`,
`separation_of_duties`, `reject_is_terminal`, `max_age_seconds`,
`required_subject_fields`. It is content-addressed too.

A request pins `policy_digest` at creation. Evaluation refuses to run
against a policy whose current hash does not match the pin
(`PolicyMismatch`).

- **Attack: weaken the policy after the fact.** Drop the threshold from 2
  to 1, or add yourself to `allowed_approvers`, then point to an
  already-approved request. The pinned digest no longer matches, so
  `get_status` and `verify` both refuse. ([ADR-0005](adr/0005-declarative-policy-engine.md))
- **Attack: approve outside the mandate.** `evaluate` is a pure function
  that only counts decisions from eligible approvers, inside the window,
  bound to the right request body. See [Policies](policies.md).

## The ledger

Every state change is a `LedgerEntry` appended to an **append-only,
hash-chained** log: `request.created`, `decision.recorded`,
`status.changed`, `checkpoint.published`. Each entry's `entry_hash` covers
all its content; each entry's `prev_hash` is the previous entry's
`entry_hash`.

- **Attack: edit a past entry.** Its `entry_hash` no longer reproduces.
- **Attack: edit it *and* recompute its hash.** The next entry's
  `prev_hash` now points at the old hash — chain broken.
- **Attack: delete, insert, or reorder.** Sequence numbers are contiguous
  from zero and the chain links break.
- **Attack: two BFF instances append at once.** The store's uniqueness
  constraint on `(log_id, seq)` lets exactly one win; the loser retries
  against the new head. ([ADR-0008](adr/0008-one-chain-per-log.md))

The ledger is the **only** source of truth. `get_status` replays a
request's events and re-runs the policy on every call.

## Checkpoints

A `Checkpoint` is a signed tree head: "as of `tree_size` entries the
[Merkle](https://www.rfc-editor.org/rfc/rfc6962) root was `root_hash`",
signed by the log key. Publish them regularly and pin the latest one
somewhere the ledger operator cannot write.

- **Attack: rebuild the entire ledger consistently.** The hash chain
  alone only proves *internal* consistency — a `TRUNCATE` + re-insert
  produces a perfectly self-consistent lie. A pinned checkpoint doesn't
  reproduce against the rebuilt log, so `verify(trusted_checkpoint=…)`
  proves the fork. ([ADR-0003](adr/0003-hash-chain-merkle-checkpoints.md))

## Records vs. views

Two read models, deliberately separate:

| | `Record` (`get_status`) | `RequestView` (`get_view` / `query`) |
|---|---|---|
| Source | replayed from the ledger | projection store |
| Cost | `O(decisions)` | one indexed row read |
| Freshness | always exact | eventually consistent |
| Use for | **gating decisions** | list / filter / search UIs |
| If lost | n/a | `rebuild_projections()` |

Gating on a `RequestView` is a security bug. ([ADR-0009](adr/0009-projections-not-authoritative.md))

## Idempotency

- **Requests**: content-addressed, so retries are inherently safe.
- **Decisions**: `reserve` an idempotency key, do the append, `complete`
  it with the result. Concurrent retries see `won=False` and replay the
  stored response. A key reused with a different fingerprint raises
  `IdempotencyConflict`. ([ADR-0007](adr/0007-idempotency.md))

## Time

Timestamps are RFC 3339 UTC strings, produced by an injectable `Clock`.
Policy evaluation (window expiry, key validity) uses these. approvo trusts
the clock you give it; a trusted external time source (RFC 3161) is a
future extension. Until then, frequent externally-pinned checkpoints bound
how far a colluding operator could backdate. See [Security
model](security.md).
