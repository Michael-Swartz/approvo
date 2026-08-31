# ADR-0012 — Custodial attribution and the `decision_issuer` verification rule

**Status:** Accepted

## Context

When one org/custodial key signs every decision
([ADR-0011](0011-key-resolver-org-signing.md)), the signature alone no
longer says *who* approved — only "the server signed this." approvo still
has to record who, tie it to the signature, and let verification express
the weaker trust model honestly.

## Decision

### Attribution rides inside the signed payload

`Decision.approver_id` is already part of the canonical bytes the key
signs. A new optional `Decision.authn` field — also signed — carries the
server's evidence that it authenticated that person: e.g.
`{"method": "oidc", "iss": ..., "sub": ..., "jti": ...}` or a WebAuthn
assertion reference. approvo does **not** interpret `authn`; it binds it
into the signature and surfaces it in the ledger for an auditor to
cross-check against the IdP's logs. `authn` is omitted from `to_dict()`
when unset, so existing decisions and their hashes are unaffected.

### `key_use` on trust-root keys

`KeyRef` gains `key_use` ∈ {`approver`, `decision_issuer`, `log`,
`oidc_issuer`} and optional `log_ids` scoping. A decision is **authorized**
if either:

1. an `approver` key whose `owner_id` equals `decision.approver_id`
   signed it (the per-person model — unchanged), or
2. a `decision_issuer` key scoped to this `log_id` signed it **and**
   `decision.approver_id` is a known identity. Whether that identity is
   *eligible* remains the policy engine's decision.

Checkpoints require `key_use == "log"` scoped to the log. An `approver`
key can no longer be silently used to sign checkpoints.

`verify()` reports which path each decision took ("own key" vs
"decision-issuer key"), so the trust model is visible in the report.

### The trade-off, stated

Under custodial signing you are trusting the server's authentication in
place of the approver's private key. A compromised backend can forge
approvals for any known identity. This is acceptable for internal tooling;
for gates on production, use per-person keys or the detached ceremony.
`SECURITY.md` says so plainly.

## Consequences

- The audit trail records *and signs over* both the identity and the
  authentication evidence, so a custodial approval is still
  non-repudiable **by the server** and traceable to a person.
- Verification of an export with an empty identity roster does not fail a
  `decision_issuer` signature on "unknown identity" grounds — it can't
  check, and says so, rather than crying tamper.
- Two new key roles to manage and scope. Operators who only use per-person
  keys are unaffected; `key_use` defaults to `approver`.
