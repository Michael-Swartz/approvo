# Architecture Decision Records

Each ADR captures one decision: the context, the options weighed, the
choice, and the consequences we accepted. They are immutable once
`Accepted` — a reversal gets a new ADR that supersedes the old one.

| # | Decision | Status |
|---|---|---|
| [0001](0001-content-addressed-requests.md) | Requests are content-addressed | Accepted |
| [0002](0002-dsse-ed25519-detached-signing.md) | DSSE envelopes, Ed25519, detached signing ceremony | Accepted |
| [0003](0003-hash-chain-merkle-checkpoints.md) | Hash-chained ledger + signed Merkle checkpoints | Accepted |
| [0004](0004-datastore-agnostic.md) | Ship store protocols + a conformance suite, not adapters | Accepted |
| [0005](0005-declarative-policy-engine.md) | Policies are declarative data, evaluated by a pure function | Accepted |
| [0006](0006-canonical-json.md) | Canonical JSON (RFC 8785 subset) for all hashing and signing | Accepted |
| [0007](0007-idempotency.md) | Reserve-then-complete idempotency for mutations | Accepted |
| [0008](0008-one-chain-per-log.md) | One hash chain per `log_id`; partition to scale writes | Accepted |
| [0009](0009-projections-not-authoritative.md) | Projections are rebuildable and never gate a decision | Accepted |
| [0010](0010-key-provider-interface.md) | KMS-agnostic `KeyProvider`; no bundled KMS in core | Accepted |
| [0011](0011-key-resolver-org-signing.md) | `KeyResolver` + `SigningService` for org-level signing | Accepted |
| [0012](0012-custodial-attribution.md) | Custodial attribution & the `decision_issuer` verify rule | Accepted |

## Reference implementations we studied

- **[in-toto](https://in-toto.io/)** — supply-chain layouts: steps,
  functionaries, key thresholds, expiry. The closest existing analogue to
  approval policies.
- **[The Update Framework](https://theupdateframework.io/)** — threshold
  signing, key roles, metadata expiry, key validity windows.
- **[DSSE](https://github.com/secure-systems-lab/dsse)** — the signing
  envelope format used by in-toto and Sigstore.
- **[Certificate Transparency / RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)**
  — Merkle logs, signed tree heads, inclusion and consistency proofs.
- **[Sigstore](https://www.sigstore.dev/)** — if you want hosted
  transparency infrastructure rather than a library.
- **[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785)** — JSON
  canonicalization.
