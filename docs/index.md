# approvo

**Auditable, tamper-evident, idempotent approvals — built for software
releases, usable for anything.**

approvo is a **library** that turns "I approved this" into a tamper-evident,
cryptographically verifiable fact. Embed it in your backend-for-frontend and
give every approval a signed, auditable record that can be
**cryptographically re-verified later** — on a laptop, with no access to
your infrastructure and no trust in whoever operated it.

A "yes" in approvo is not a row someone could edit. It is an
signature-verified statement, bound to the exact content that was approved,
chained into an append-only ledger whose integrity anyone can check.

## Where it sits

```
Your BFF  ──▶  approvo  ──▶  your datastore (you implement 3 protocols)
(auth, HTTP,   (this
 the DB conn)   library)
```

approvo never opens a connection, runs a migration, or owns a
transaction. See [Storage](storage.md) for what you implement and why.

## The guarantees

| Guarantee | Mechanism |
|---|---|
| Non-repudiation | Every decision is a signed [DSSE envelope](https://github.com/secure-systems-lab/dsse) |
| Server can't forge approvals | Detached signing — the approver's client signs, your BFF relays |
| No bait-and-switch | Each decision embeds the hash of the exact request the approver saw |
| Tamper-evidence | Hash-chained append-only ledger + signed Merkle checkpoints |
| Policy integrity | Requests pin the content hash of the policy in force at creation |
| Reproducibility | Status is re-derived from the ledger on every read, never from a column |
| Idempotency | Requests are content-addressed; decisions use reserve-then-complete |
| Scales | Every read is `O(decisions for this request)`, never `O(ledger)` |

## Start here

- **[Installation](installation.md)** — `pip install approvo`, one
  dependency, Python ≥ 3.11.
- **[Getting started](getting-started.md)** — approve a release, gate a
  deploy, in one file.
- **[Concepts](concepts.md)** — how the tamper-evidence model works,
  attack by attack.
- **[Storage](storage.md)** — implement the store protocols against your
  database and validate with the conformance suite.
- **[Security model](security.md)** — what approvo does *not* protect
  against. Read this before trusting it.
- **[API reference](reference/index.md)** — every public symbol, from
  docstrings.
- **[FAQ](faq.md)** · **[ADRs](adr/index.md)** — common questions and the
  reasoning behind each design choice.

## Project

- **Source:** [github.com/Michael-Swartz/approvo](https://github.com/Michael-Swartz/approvo)
- **License:** Apache-2.0
- **Status:** alpha — the wire format is versioned by `schema` strings and
  covered by golden tests, but the API may still shift before 1.0.
- **Contributing:** see [Contributing](contributing.md).

## Design lineage

approvo borrows from systems that got this right:
[in-toto](https://in-toto.io/) (step / functionary / threshold layouts),
[TUF](https://theupdateframework.io/) (key validity windows, thresholds),
[DSSE](https://github.com/secure-systems-lab/dsse) (the signing envelope),
[Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
(Merkle logs, signed tree heads, consistency proofs).
