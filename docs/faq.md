# FAQ

### Is approvo a service I run?

No. It is a library you import into your backend. There is no daemon, no
HTTP server, no container to deploy, and no database that belongs to
approvo. Your backend-for-frontend owns the transport, authentication,
and the datastore connection; approvo is the logic in between.

### Why doesn't it ship a Postgres / Mongo adapter?

Because a bundled adapter would fight your migration tool, your
connection pool, and your transaction boundaries — and it would rot,
because the maintainers don't run every database in anger. See
[Storage](storage.md) for what you implement instead, or
[ADR-0004](adr/0004-datastore-agnostic.md) for the full reasoning.

### Can I use it for things that aren't software releases?

Yes. `kind` is a free string and `subject` is an arbitrary JSON object.
Change approvals, data-export requests, privileged-access grants,
financial sign-offs, content publication — anything that needs "N of these
people said yes, provably". Releases are the design target, not the limit.

### What stops the server from forging an approval?

If you use the [detached signing ceremony](getting-started.md#detached-signing-recommended-for-production)
(`prepare_decision` + `submit_signed_decision`), the approver's private
key never reaches your backend. The server produces the bytes to sign and
only ever handles the signature plus the already-registered key material in
your `KeyDirectory`, so a fully compromised backend still cannot
manufacture a valid approval.

`submit_decision` (server-side signing) is offered for internal tooling
where that trade-off is acceptable, and its risk is documented.

### What happens if someone edits the database directly?

`verify()` catches it. Editing an entry breaks its `entry_hash`; fixing
that breaks the next entry's `prev_hash`; deleting or reordering breaks
the sequence; rebuilding the whole table diverges from the last signed
Merkle checkpoint you pinned somewhere they can't reach. See
[Concepts](concepts.md#the-ledger) and [Verification](verification.md).

### Does approvo prevent tampering, or just detect it?

Detect. Tamper-*evidence*, not tamper-*prevention*. Pair it with revoked
`UPDATE`/`DELETE` grants on the ledger table and off-site mirroring. An
attacker who can destroy the whole store destroys the evidence — that's
what backups are for. [Security model](security.md) is explicit about the
boundaries.

### How does it scale? Won't a hash chain serialise all writes?

Within one `log_id`, yes — a chain is totally ordered. So you partition:
one `log_id` per tenant, environment, team, or service. Each is an
independent chain with its own checkpoints and its own `verify()`. Reads
are always `O(decisions for this request)` via the indexed
`events_for_request`, never `O(ledger)`. See
[ADR-0008](adr/0008-one-chain-per-log.md).

### Why can't I put floats in a subject?

Canonical serialization ([ADR-0006](adr/0006-canonical-json.md)) rejects
them, because there is no cross-language, cross-version float
representation stable enough to hash and sign against. Use integers, or
strings for decimals (`"19.99"`).

### Can I change a policy after requests are open against it?

Not in place — the request pins `policy_digest` and `get_status` raises
`PolicyMismatch` if it no longer matches. Add a new version (`release-v2`)
instead. In-flight requests keep evaluating under the rules they were
opened with, which is usually what an auditor wants. See
[Policies](policies.md).

### Is the audit trail confidential?

No. The ledger is plaintext by design, so it stays greppable and
auditable. Keep secrets out of `subject` and `comment` fields.

### How do I trust `verify()` if the operator runs it?

You don't — run it yourself, on infrastructure the operator doesn't
control, with a key directory you obtained out of band and a checkpoint
you pinned. `verify()` works against any `EventStore`, including a
minimal read-only one you wrap around rows from a database dump. See
[Verification](verification.md#verifying-off-your-infrastructure).

### What's the relationship to in-toto / TUF / Sigstore?

approvo borrows their ideas — in-toto's step/functionary/threshold model,
TUF's key validity windows, DSSE's envelope, Certificate Transparency's
Merkle log — and packages them as a small embeddable library for
approvals specifically. If you want hosted transparency infrastructure
rather than a library, use Sigstore. See the
[ADR overview](adr/index.md#reference-implementations-we-studied).

### What license?

Apache-2.0.
