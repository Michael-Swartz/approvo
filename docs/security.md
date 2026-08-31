# Security model

Mirrors [`SECURITY.md`](https://github.com/Michael-Swartz/approvo/blob/main/SECURITY.md)
in the repo. Read it before you rely on approvo for anything that matters.

## What approvo makes tamper-evident

Given an intact **key directory** and, ideally, an externally **pinned
checkpoint**, `verify()` detects all of the following no matter what
happens to the ledger storage:

1. **Forged approvals** — a decision counts only if its DSSE envelope
   verifies against either a key registered to the claimed approver or an
   authorized `decision_issuer` key for this `log_id`, valid at the
   decision's timestamp.
2. **Content swaps** — decisions bind to `context_digest`; change a byte
   of the request and every approval stops counting.
3. **History rewrites** — hash-chained entries; edits, deletions,
   insertions, reordering all break the chain, and wholesale rebuilds
   diverge from signed checkpoints.
4. **Policy swaps** — requests pin `policy_digest`; evaluation refuses a
   policy that no longer hashes to the pin.
5. **Status fabrication** — status is re-derived on every read; a tampered
   `status.changed` event changes nothing.

## What approvo does NOT protect against

- **Destruction of the store.** Tamper-*evidence* is not backup. An
  attacker who drops the ledger destroys the evidence. Mirror it.
- **A compromised key directory.** If an attacker can register their key
  as `user:casey`, they can sign as Casey. Protect the directory at least
  as well as the ledger; distribute it out of band; review changes to it.
- **A compromised approver key.** Signatures prove key possession, not
  human intent. Use short validity windows, `revoked_at`, and — for
  detached signing — client-side keys in an HSM or platform keystore.
- **Trusted time.** Timestamps come from the injected `Clock`. A malicious
  operator colluding with a key holder could backdate a decision. An
  RFC 3161 timestamp source is a planned extension; until then, frequent
  externally-pinned checkpoints bound the backdating window.
- **Confidentiality.** The ledger is plaintext by design. Keep secrets out
  of subjects and comments.
- **A dishonest verifier.** Run `verify()` on infrastructure the ledger
  operator does not control, with an out-of-band key directory and a
  pinned checkpoint.
- **Server-side / custodial signing key custody.** `submit_decision` has
  your backend hold the signing key — either a per-person key or, with a
  `SigningService`, one org `decision_issuer` key that signs for everyone.
  Either way a compromised backend can forge approvals for known
  identities. Use `prepare_decision` + `submit_signed_decision` for
  anything that gates production.

## Operational checklist

- Publish a checkpoint after every batch of activity and on a schedule;
  pin the latest one where the operator cannot write it.
- Keep the log signing key on separate infrastructure from approver keys.
- Deny `UPDATE`/`DELETE` on the ledger table to the application
  credential.
- Gate deploys on `status == "approved"` **and** a subject match **and**
  `verify().raise_for_failures()` — all three.
- Partition logs by `log_id` so no single chain is a global write
  bottleneck.

## Reporting a vulnerability

Open a GitHub security advisory on the repository, or email the address in
`pyproject.toml`. Please don't file public issues for suspected
vulnerabilities.
