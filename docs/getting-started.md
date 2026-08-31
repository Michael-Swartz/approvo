# Getting started

## Install

```console
pip install approvo
```

Python ≥ 3.11. The only runtime dependency is
[`cryptography`](https://cryptography.io/). Add `approvo[dev]` if you are
going to run the store [conformance suite](storage.md).

## The mental model in one paragraph

You hold three things: a **key directory** (public keys of everyone who
may sign, plus a log key), an **identity roster** (ids and roles), and a
set of **policies** (declarative rules). You inject those plus your
**stores** into an `ApprovalService`. Callers `create_request`, approvers
sign `Decision`s, and anything that needs to trust an approval calls
`get_status`, which re-derives the answer from the ledger every time.

## A complete example

`ApprovalService` is async and needs three stores implementing the
protocols in `approvo.stores.base`. approvo ships no database adapters —
see [Storage](storage.md) for the contract. The toy stores below hold
everything in a dict/list; they exist purely to make this example
runnable and are **not** something approvo ships or something you should
deploy — implement the same handful of methods over your own database.

```python
import asyncio
from datetime import datetime, timedelta, timezone

from approvo import (
    ApprovalService, Checkpoint, Ed25519Signer, Identity, InMemoryPolicyStore,
    KeyDirectory, Policy, RequestQuery, to_rfc3339,
)
from approvo.errors import IdempotencyConflict, LedgerConflict
from approvo.models import Page
from approvo.stores.base import Reservation

# --- toy stores, for this example only; see storage.md for the real thing


class ToyEventStore:
    def __init__(self, log_id: str = "default") -> None:
        self.log_id = log_id
        self._entries = []

    async def head(self):
        return self._entries[-1] if self._entries else None

    async def append(self, entry) -> None:
        if entry.seq != len(self._entries):
            raise LedgerConflict(f"seq {entry.seq} already taken")
        self._entries.append(entry)

    async def get_by_seq(self, seq: int):
        return self._entries[seq] if 0 <= seq < len(self._entries) else None

    async def events_for_request(self, request_id: str):
        return [e for e in self._entries if e.request_id == request_id]

    async def scan(self, start: int = 0, limit=None):
        stop = len(self._entries) if limit is None else min(start + limit, len(self._entries))
        for entry in self._entries[start:stop]:
            yield entry

    async def leaf_hashes(self, up_to=None):
        hashes = [e.entry_hash for e in self._entries]
        return hashes if up_to is None else hashes[:up_to]

    async def latest_checkpoint(self):
        for entry in reversed(self._entries):
            if entry.event_type == "checkpoint.published":
                return Checkpoint.from_dict(entry.payload)
        return None


class ToyProjectionStore:
    def __init__(self) -> None:
        self._views = {}

    async def upsert(self, view) -> None:
        current = self._views.get(view.request_id)
        if current is not None and current.last_seq > view.last_seq:
            return
        self._views[view.request_id] = view

    async def get(self, request_id: str):
        return self._views.get(request_id)

    async def query(self, query):
        items = [v for v in self._views.values() if not query.status or v.status in query.status]
        return Page(items=tuple(items))

    async def clear(self) -> None:
        self._views.clear()


class ToyIdempotencyStore:
    def __init__(self) -> None:
        self._data = {}

    async def reserve(self, key: str, fingerprint: str):
        existing = self._data.get(key)
        if existing is None:
            self._data[key] = {"fingerprint": fingerprint, "response": None}
            return Reservation(won=True, fingerprint=fingerprint)
        if existing["fingerprint"] != fingerprint:
            raise IdempotencyConflict(key)
        return Reservation(won=False, fingerprint=fingerprint, response=existing["response"])

    async def complete(self, key: str, response: dict) -> None:
        self._data[key]["response"] = response

    async def release(self, key: str) -> None:
        self._data.pop(key, None)


async def main() -> None:
    now = to_rfc3339(datetime.now(timezone.utc))

    # 1. keys — approvers sign decisions, the log key signs checkpoints
    casey = Ed25519Signer.generate()
    jordan = Ed25519Signer.generate()
    log_key = Ed25519Signer.generate()

    keys = KeyDirectory()
    keys.add(casey.public_key_ref("user:casey", not_before=now))
    keys.add(jordan.public_key_ref("user:jordan", not_before=now))
    keys.add(log_key.public_key_ref("log:main", not_before=now, key_use="log"))

    # 2. identities — ids and the roles policies match against
    identities = {
        "user:casey": Identity("user:casey", ("release-manager",)),
        "user:jordan": Identity("user:jordan", ("qa",)),
        "user:riley": Identity("user:riley", ("sre",)),
    }

    # 3. policy — 2 approvals from release-manager or qa; requester can't
    #    self-approve; subject must carry an artifact digest and a version
    policy = Policy(
        id="release-v1",
        kind="software-release",
        allowed_approvers=("role:release-manager", "role:qa"),
        threshold=2,
        required_subject_fields=("artifact_digest", "version"),
    )

    # 4. the service — inject stores + trust config
    svc = ApprovalService(
        events=ToyEventStore(log_id="releases"),
        key_dir=keys,
        identities=identities,
        policy_store=InMemoryPolicyStore([policy]),
        projections=ToyProjectionStore(),
        idempotency=ToyIdempotencyStore(),
        log_signer=log_key,
    )

    # 5. open a request
    req = await svc.create_request(
        kind="software-release",
        subject={"artifact_digest": "sha256:ab12", "version": "1.4.0"},
        requested_by="user:riley",
        policy_id="release-v1",
        not_valid_after=to_rfc3339(datetime.now(timezone.utc) + timedelta(days=7)),
    )
    print("request:", req.request_id)

    # 6. approvers decide (server-side signing shown; see below for detached)
    await svc.submit_decision(
        request_id=req.request_id, approver_id="user:casey",
        verdict="approve", signer=casey,
    )
    record = await svc.submit_decision(
        request_id=req.request_id, approver_id="user:jordan",
        verdict="approve", signer=jordan,
    )
    print("status:", record.status)                       # approved

    # 7. list requests for a UI (projection store — fast, not authoritative)
    page = await svc.query(RequestQuery(status=("approved",)))
    print([v.request_id for v in page.items])

    # 8. checkpoint + verify the whole ledger
    await svc.checkpoint()
    report = await svc.verify()
    assert report.ok, report.to_dict()
    print(f"verified: {len(report.checks)} checks passed")


asyncio.run(main())
```

## Idempotency, for free

`create_request` is **content-addressed**: the `request_id` is the hash of
the identity-bearing fields. Call it twice with the same arguments and you
get the same request back — no duplicate, no second ledger entry, no
idempotency key required. To open a genuinely separate request for the
same subject, pass a fresh `nonce=new_nonce()`.

`submit_decision` / `submit_signed_decision` use **reserve-then-complete**
on an idempotency key (default: `f"{request_id}:{approver_id}:{verdict}"`).
Retried calls — from a flaky network, an at-least-once queue, an impatient
user — collapse to one ledger append. Reusing a key with a *different*
verdict raises `IdempotencyConflict`. See
[ADR-0007](adr/0007-idempotency.md).

## Detached signing (recommended for production)

`submit_decision` has the service hold the approver's private key. That is
fine for internal tooling, but it means a compromised BFF can manufacture
approvals. For anything that gates production, keep signing on the
approver's side:

```python
# server: produce the exact bytes to sign
challenge = await svc.prepare_decision(
    request_id=req.request_id, approver_id="user:casey", verdict="approve",
)

# client (browser, CLI, HSM agent): sign challenge.pae_b64
import base64
sig = casey.sign(base64.b64decode(challenge.pae_b64))
signatures = [{
    "keyid": casey.key_id(),
    "sig": base64.b64encode(sig).decode(),
}]

# server: assemble the envelope and submit; the challenge is never trusted,
# everything is re-derived and re-verified from the envelope
envelope = svc.envelope_from_challenge(challenge, signatures)
record = await svc.submit_signed_decision(envelope)
```

[ADR-0002](adr/0002-dsse-ed25519-detached-signing.md) covers the trade-off.

## Gating a deploy

The gate every consumer should run:

```python
record = await svc.get_status(request_id)              # re-derived, not cached
assert record.status == "approved"
assert record.request.subject["artifact_digest"] == digest_being_deployed
(await svc.verify(trusted_checkpoint=pinned)).raise_for_failures()
```

Line 2 stops you deploying artifact B on an approval for artifact A. Line
3 proves nobody rewrote history since the checkpoint you pinned somewhere
the ledger operator can't reach. More in [Verification](verification.md).

## Next

- [Concepts](concepts.md) — what each guarantee actually defends against.
- [Storage](storage.md) — wire it to Postgres / Mongo / whatever you run.
- [Security model](security.md) — the limits.
