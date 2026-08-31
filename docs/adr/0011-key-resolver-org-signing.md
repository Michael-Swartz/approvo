# ADR-0011 — `KeyResolver` and the org-level signing model

**Status:** Accepted

## Context

Teams asked for "one org signing key that signs all approvals" — they do
not want every approver to generate, store, and register a key. But
approvo still needs to know *which* key signs a given decision or
checkpoint, and that choice can range from "always the same key" to "one
per tenant / environment / team."

## Decision

A **`KeyResolver`** maps a signing purpose plus context to a logical key
reference:

```python
async def resolve(ctx: SigningContext) -> str   # -> key_ref for a KeyProvider
```

`SigningContext` carries `log_id`, `purpose` (`DECISION` | `CHECKPOINT`),
and optionally `kind` / `policy_id` / `approver_id`.

Shipped resolvers:

- **`StaticKeyResolver`** — one key ref per purpose. This is the
  "org key signs everything" case.
- **`TemplateKeyResolver`** — substitute `{log_id}` / `{purpose}` / … into
  a reference template. One key per environment or tenant.
- Anything else: implement the one method.

**`SigningService`** ties resolver + provider + caches together and is the
single object `ApprovalService` depends on for server-side signing:

- `sign_decision(decision, ctx)` → a DSSE envelope,
- `sign_checkpoint(cp)` → a signed checkpoint,
- `trust(...)` / `trust_from_static(...)` → turn the keys it signs with
  into `KeyRef` entries for the `KeyDirectory`, so what you sign with is
  exactly what verifiers accept,
- `self_test()` → sign + verify a nonce per configured key at startup.

`ApprovalService` gains a `signing=` parameter. When present,
`submit_decision` needs no `signer=` argument and `checkpoint()` needs no
`log_signer`. An explicit `signer=` on `submit_decision` still wins when
given (per-person keys, or the detached ceremony, are untouched).

## Consequences

- Onboarding an approver becomes "add them to the identity roster" — no
  key ceremony.
- One custodial key is a concentrated target. It is a `KeyProvider` ref,
  so it belongs in a KMS/HSM with tight IAM and audit logging, and it is
  scoped with `KeyRef.log_ids`.
- The resolver is a clean extension point for per-tenant / per-team keys
  without touching the ledger, policy engine, or verification.
- Checkpoint keys (`key_use == "log"`) and decision keys
  (`key_use == "decision_issuer"`) are distinct entries in the trust
  root; an approver key can never stand in for either.
