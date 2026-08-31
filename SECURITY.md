# Security model

## What approvo makes tamper-evident

Given an intact **key directory** (the trust root) and, ideally, an
externally **pinned checkpoint**, `ApprovalService.verify()` detects all
of the following — regardless of what happens to the ledger storage:

1. **Forged approvals.** A decision counts only if its DSSE envelope
   verifies against a key registered to the claimed approver that was
   valid (not before / after / revoked) at the decision's timestamp.
2. **Content swaps.** Decisions bind to `context_digest` — the canonical
   hash of the full request body the approver saw. Change one byte of the
   subject and every existing approval stops counting.
3. **History rewrites.** Entries are hash-chained; edits, deletions,
   insertions, and reordering break the chain. Wholesale rebuilds diverge
   from signed Merkle checkpoints, and anyone holding a previously pinned
   checkpoint can prove the fork
   (`verify(trusted_checkpoint=...)`).
4. **Policy swaps.** Requests pin `policy_digest` at creation; evaluation
   refuses to run against a policy that no longer hashes to the pin.
5. **Status fabrication.** Status is re-derived from the ledger on every
   read. A tampered `status.changed` event changes nothing.

## What approvo does NOT guarantee

Be honest with yourself about these before relying on it.

- **Availability / deletion of the whole store.** An attacker who destroys
  the ledger destroys the evidence. Tamper-*evidence* is not backup.
  Mirror the ledger.
- **A compromised key directory.** If an attacker can add their own key as
  `user:casey`, they can sign as Casey. Protect the key directory at least
  as well as the ledger; distribute it out of band; review changes to it.
- **A compromised approver key.** Signatures prove key possession, not
  human intent. Use short validity windows and revocation (`revoked_at`
  invalidates only signatures dated *after* revocation). For detached
  signing, keep client keys in an HSM or platform keystore.
- **Server-side / custodial signing key custody.** `submit_decision` has
  your backend hold the signing key — a per-person key, or (with a
  `SigningService`) one org `decision_issuer` key that signs for everyone.
  Either way a compromised backend can forge approvals for known
  identities. Mitigate: keep the key in a KMS/HSM with tight IAM and
  audit logging, scope it with `KeyRef.log_ids`, and record `Decision.authn`
  so approvals can be cross-checked against your IdP. For anything that
  gates production, use per-person keys or `prepare_decision` +
  `submit_signed_decision` (detached signing), where the private key never
  reaches your backend.
- **Trusted time.** Timestamps come from the injected `Clock`. A malicious
  operator colluding with a key holder could backdate a decision. An
  RFC 3161 timestamp source is a planned extension; until then, frequent
  externally-pinned checkpoints bound the backdating window.
- **Confidentiality.** The ledger is plaintext by design (auditability).
  Don't put secrets in subjects or comments.
- **A dishonest verifier.** Run `verify()` from infrastructure the ledger
  operator does not control, with an independently obtained key directory
  and a pinned checkpoint. Verification you can't trust is theater.

## Operational recommendations

- Publish a checkpoint after every batch of activity (or on a schedule)
  and pin the latest checkpoint somewhere the ledger operator cannot
  write: a different repo, CI variables, a customer's vault.
- Keep the log signing key on separate infrastructure from approver keys.
- Deny `UPDATE` and `DELETE` on the ledger table/collection to the
  application's database credential.
- Gate deploys on `status == "approved"` **and** a subject match **and**
  `verify().raise_for_failures()` — all three.
- Partition logs by `log_id` so no single hash chain is a global write
  bottleneck.

## Reporting a vulnerability

Open a GitHub security advisory on this repository, or email the address
in `pyproject.toml`. Please do not open public issues for suspected
vulnerabilities.
