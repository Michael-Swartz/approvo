# approvo

**Auditable, tamper-evident, idempotent approvals — built for software
releases, usable for anything.**

[![CI](https://github.com/Michael-Swartz/approvo/actions/workflows/ci.yml/badge.svg)](https://github.com/Michael-Swartz/approvo/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-github%20pages-blue)](https://michael-swartz.github.io/approvo/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

approvo is a **library** that turns "I approved this" into a tamper-evident,
cryptographically verifiable fact. Embed it in your backend-for-frontend
and give every approval a signed, auditable record that can be
**re-verified later** — on a laptop, by anyone, without access to your
infrastructure.

A "yes" in approvo is not a row someone could edit. It is an
Ed25519-signed statement, bound to the exact content that was approved,
chained into an append-only ledger whose integrity anyone can check — on a
laptop, without access to your infrastructure.

```
pip install approvo
```

Only runtime dependency: [`cryptography`](https://cryptography.io/).
Python ≥ 3.11.

## What you plug it into

```
┌────────────────┐     approvo (this library)      ┌──────────────────┐
│  Your BFF      │  create_request / prepare_      │  Your datastore  │
│  (FastAPI,     │─▶ decision / submit_signed_ ───▶│  Postgres, Mongo │
│   Flask, ...)  │   decision / get_status         │  Dynamo, ...     │
│                │◀─ Record / RequestView ─────────│  (you implement  │
│  owns auth,    │                                 │   3 protocols)   │
│  HTTP, the DB  │                                 └──────────────────┘
│  connection    │
└────────────────┘
```

approvo never opens a connection, runs a migration, or owns a
transaction. You implement three small async protocols
([`approvo.stores.base`](src/approvo/stores/base.py)) over the database
you already run, and prove your implementation correct with the shipped
conformance suite ([`approvo.testing`](src/approvo/testing.py)). See
[docs/storage.md](docs/storage.md) for why it's split into three, and
[ADR-0004](docs/adr/0004-datastore-agnostic.md) for the full reasoning.

## The guarantees

| Guarantee | Mechanism |
|---|---|
| Non-repudiation | Every decision is an Ed25519-signed [DSSE envelope](https://github.com/secure-systems-lab/dsse) |
| Server can't forge approvals | Detached signing: the approver's client signs; your BFF relays bytes it never holds a key for |
| No bait-and-switch | Each decision embeds the hash of the exact request the approver saw |
| Tamper-evidence | Hash-chained append-only ledger + signed Merkle checkpoints |
| Policy integrity | Requests pin the content hash of the policy in force at creation |
| Reproducibility | Status is always **re-derived** from the ledger, never read from a status column |
| Idempotency | Requests are content-addressed; decisions use reserve-then-complete on an idempotency key |
| Scales | Every read is `O(decisions for this request)`, never `O(ledger)` |

## Shape of the API

Pseudocode below — `Pg*Store` stand in for your own implementation of the
three storage protocols; see the runnable example in
[Getting started](https://michael-swartz.github.io/approvo/getting-started/).

```python
from datetime import datetime, timedelta, timezone
from approvo import (
    ApprovalService, Ed25519Signer, Identity, InMemoryPolicyStore,
    KeyDirectory, Policy, to_rfc3339,
)
# approvo ships no database adapters — implement these three protocols
# (approvo.stores.base) over your own datastore; see docs/storage.md.
# from myapp.approvo_stores import PgEventStore, PgProjectionStore, PgIdempotencyStore

now = to_rfc3339(datetime.now(timezone.utc))
casey, jordan, log_key = (Ed25519Signer.generate() for _ in range(3))

keys = KeyDirectory()
keys.add(casey.public_key_ref("user:casey", not_before=now))
keys.add(jordan.public_key_ref("user:jordan", not_before=now))
keys.add(log_key.public_key_ref("log:main", not_before=now, key_use="log"))

svc = ApprovalService(
    events=PgEventStore(pg_pool, log_id="releases"),
    key_dir=keys,
    identities={
        "user:casey": Identity("user:casey", ("release-manager",)),
        "user:jordan": Identity("user:jordan", ("qa",)),
    },
    policy_store=InMemoryPolicyStore([Policy(
        id="release-v1", kind="software-release",
        allowed_approvers=("role:release-manager", "role:qa"),
        threshold=2,
        required_subject_fields=("artifact_digest", "version"),
    )]),
    projections=PgProjectionStore(pg_pool, log_id="releases"),
    idempotency=PgIdempotencyStore(pg_pool, log_id="releases"),
    log_signer=log_key,
)

# --- open a request (content-addressed: retrying is a no-op) --------------
req = await svc.create_request(
    kind="software-release",
    subject={"artifact_digest": "sha256:ab…", "version": "1.4.0"},
    requested_by="user:riley",
    policy_id="release-v1",
    not_valid_after=to_rfc3339(datetime.now(timezone.utc) + timedelta(days=7)),
)

# --- approvers sign off -------------------------------------------------- #
# detached (recommended): server never holds the key
challenge = await svc.prepare_decision(
    request_id=req.request_id, approver_id="user:casey", verdict="approve",
)
#   ... hand `challenge.pae_b64` to casey's client, get back a signature ...
envelope = svc.envelope_from_challenge(challenge, [{"keyid": ..., "sig": ...}])
record = await svc.submit_signed_decision(envelope)

# or server-side signing, for internal tools where that trade-off is fine
record = await svc.submit_decision(
    request_id=req.request_id, approver_id="user:jordan",
    verdict="approve", signer=jordan,
)
assert record.status == "approved"

# --- gate a deploy on it ---------------------------------------------------
record = await svc.get_status(req.request_id)          # re-derived every call
assert record.status == "approved"
assert record.request.subject["artifact_digest"] == digest_being_deployed
await svc.checkpoint()
(await svc.verify(trusted_checkpoint=pinned)).raise_for_failures()
```

Full walkthrough: **[Getting started](https://michael-swartz.github.io/approvo/getting-started/)**.

## Signing: three ways, one ledger

| Approach | Who holds the key | Server can forge? |
|---|---|---|
| Detached ceremony (`prepare_decision` + `submit_signed_decision`) | the approver's client | no |
| Per-person `Signer` (`submit_decision(signer=…)`) | wherever you keep it | only if that store is compromised |
| **Org / custodial** (`ApprovalService(signing=…)`) | your backend, via a KMS | yes (mitigable) — no approver key management |

Org-level signing decouples from any specific KMS: implement or import a
`KeyProvider` (schemes for `gcpkms://`, `awskms://`, `vault://`, plus
local `file://` / `env://` / `memory://`), a `KeyResolver` (which key
signs what), and hand both to a `SigningService`:

```python
from approvo.crypto import SigningService, StaticKeyResolver, SigningPurpose, CompositeKeyProvider, LocalFileKeyProvider
from approvo.providers.gcpkms import GcpKmsKeyProvider   # pip install 'approvo[gcpkms]'

signing = SigningService(
    CompositeKeyProvider([GcpKmsKeyProvider(), LocalFileKeyProvider(root="/etc/approvo")]),
    StaticKeyResolver({
        SigningPurpose.DECISION:   "gcpkms://.../cryptoKeys/org-approvals/cryptoKeyVersions/3",
        SigningPurpose.CHECKPOINT: "gcpkms://.../cryptoKeys/org-log/cryptoKeyVersions/1",
    }),
)
await signing.self_test()
key_dir.extend(await signing.trust_from_static(
    issuer_owner_id="svc:approvo", log_owner_id="svc:approvo-log",
    not_before=now, log_ids=("releases",),
))

svc = ApprovalService(events=…, key_dir=key_dir, identities=…, policy_store=…, signing=signing)
await svc.submit_decision(                        # no signer= — the org key signs
    request_id=rid, approver_id="user:casey", verdict="approve",
    authn={"method": "oidc", "sub": "casey", "jti": "…"},   # bound into the signature
)
```

A custodial decision counts if a `decision_issuer` key scoped to this log
signed it **and** the named approver is a known, eligible identity — you
trade the approver's private key for the server's authentication. Full
guide: **[Signing](https://michael-swartz.github.io/approvo/signing/)**.
KMS providers are validated by `approvo.testing.KeyProviderConformance`.

## Reads: authoritative vs. projected

Two read paths, and mixing them up is a security bug:

- **`get_status(request_id) -> Record`** replays that request's events and
  re-runs the policy. Slower, always correct. **Gate on this.**
- **`get_view` / `query` -> `RequestView`** hit the projection store: a
  denormalized, rebuildable cache for list and search screens. Fast,
  eventually consistent, **never** the basis for a decision.

Lose the projection store and nothing is lost —
`svc.rebuild_projections()` regenerates it from the ledger.

## Implementing a store

```python
class PostgresEventStore:
    log_id: str

    async def head(self) -> LedgerEntry | None: ...
    async def append(self, entry: LedgerEntry) -> None:
        # MUST be atomic on (log_id, seq); raise LedgerConflict if taken.
        # A UNIQUE constraint is the entire concurrency-control story.
    async def get_by_seq(self, seq: int) -> LedgerEntry | None: ...
    async def events_for_request(self, request_id: str) -> list[LedgerEntry]:
        # MUST be indexed on (log_id, request_id, seq)
    async def scan(self, start=0, limit=None): ...          # async iterator
    async def leaf_hashes(self, up_to=None) -> list[str]: ...
    async def latest_checkpoint(self) -> Checkpoint | None: ...
```

Then, in your test suite:

```python
from approvo.testing import EventStoreConformance

class TestPostgresEventStore(EventStoreConformance):
    @pytest.fixture
    async def event_store(self):
        store = PostgresEventStore(pool, log_id="test")
        await truncate(pool)
        yield store
```

If the conformance suite passes against your store, approvo's guarantees
hold on your datastore. See
[Storage](https://michael-swartz.github.io/approvo/storage/).

## What tamper-evidence means here

Edit any recorded byte and `verify()` fails, precisely:

- **Edit an entry** → its `entry_hash` no longer reproduces.
- **Edit an entry and fix its hash** → the next entry's `prev_hash` breaks.
- **Delete / insert / reorder entries** → sequence and chain break.
- **Rebuild the whole ledger** → the Merkle root no longer matches any
  signed checkpoint; anyone holding a pinned checkpoint can prove the fork.
- **Forge a decision without the approver's key** → the DSSE signature
  fails; the decision never counts toward status even before `verify` runs.
- **Swap the subject after approval** → the decision's `context_digest` no
  longer matches; the approval stops counting.

Threat model and limits: **[SECURITY.md](SECURITY.md)**.

## Documentation

Full docs: **<https://michael-swartz.github.io/approvo/>**

- [Getting started](https://michael-swartz.github.io/approvo/getting-started/)
- [Concepts](https://michael-swartz.github.io/approvo/concepts/) — the tamper-evidence model, attack by attack
- [Policies](https://michael-swartz.github.io/approvo/policies/)
- [Storage](https://michael-swartz.github.io/approvo/storage/) — implementing the store protocols
- [Verification](https://michael-swartz.github.io/approvo/verification/)
- [Security model](https://michael-swartz.github.io/approvo/security/)
- [Architecture Decision Records](https://michael-swartz.github.io/approvo/adr/)

## Prior art

approvo borrows from systems that got this right:
[in-toto](https://in-toto.io/) (step / functionary / threshold layouts),
[TUF](https://theupdateframework.io/) (key validity windows, thresholds),
[DSSE](https://github.com/secure-systems-lab/dsse) (the signing envelope),
[Certificate Transparency / RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)
(Merkle logs, signed tree heads, consistency). If you want hosted
transparency infrastructure rather than a library, look at
[Sigstore](https://www.sigstore.dev/).

## Development

```console
python -m venv .venv && .venv/bin/pip install -e '.[dev,docs]'
.venv/bin/pytest
.venv/bin/mkdocs serve      # docs at http://127.0.0.1:8000
```

## License

Apache-2.0 — see [LICENSE](LICENSE).
