# Verification

`await service.verify(...)` re-derives everything and returns a
`VerificationReport` — a list of `Check(ok, description)` plus the
`seq` range it covered. It never trusts a stored status, a `status.changed`
event, or a projection.

```python
report = await svc.verify(trusted_checkpoint=pinned)
if not report.ok:
    for c in report.failures:
        log.error("approvo verify: %s", c.description)
    raise RuntimeError("approval ledger failed verification")
```

`report.raise_for_failures()` does the raise for you.

## What it checks

1. **Chain integrity** over the scanned segment: sequence numbers
   contiguous, every `prev_hash` matching, every `entry_hash`
   reproducing.
2. **The published checkpoint** (if any): its signature verifies against
   the key directory, and the Merkle root over the first `tree_size`
   leaves reproduces `root_hash`.
3. **Consistency with a pinned checkpoint** (if you pass
   `trusted_checkpoint`): the current log's first `tree_size` leaves
   reproduce the pinned root — i.e. the log is an *extension* of what you
   trusted, not a rewrite.
4. **Every decision**: its DSSE signature is authorized for the approver it
   names — either by that approver's own key or by a `decision_issuer` key
   scoped to this `log_id` — using a key valid at `decided_at`, and its
   `context_digest` matches the request it points at.
5. **Every request's status is reproducible**: re-running the policy
   engine yields the status recorded in the last `status.changed` event
   (or, for a still-pending request, the absence of one), allowing for
   `expired` since windows close with the passage of time. If the policy
   set is not available (verifying with only a key directory), this check
   is reported as skipped rather than passed.

## Incremental verification

On a large ledger, verifying from seq 0 every time is wasteful. Pin a
checkpoint, then verify only what came after it:

```python
report = await svc.verify(trusted_checkpoint=pinned, from_seq=pinned.tree_size)
```

The chain check picks up from `from_seq` using the stored entry's
`prev_hash` as its anchor.

## Where to run it

Verification you cannot trust is theater. Run `verify()`:

- from infrastructure the ledger operator does **not** control,
- with a key directory obtained **out of band** (not from the same
  database),
- against a checkpoint **pinned** somewhere the operator cannot write — a
  separate repo, CI secrets, a colleague's machine, a customer's vault.

## Pinning checkpoints

```python
cp = await svc.checkpoint()                 # signs + appends a checkpoint
publish_somewhere_immutable(cp.to_dict())   # git commit, CI var, S3 Object Lock…
```

Publish on a schedule and after every batch of activity. The gap between
your newest pinned checkpoint and now is the window in which a colluding
operator could rewrite history undetected; frequent pins keep it small.

## Verifying off your infrastructure

`verify()` runs against any `EventStore`. To check a ledger you pulled out
of your database as a list of rows, wrap the list in a minimal read-only
`EventStore` and verify — you don't need your production store's write
path for this, just enough to satisfy the protocol:

```python
from approvo import ApprovalService, InMemoryPolicyStore, KeyDirectory, LedgerEntry
from approvo.models import Checkpoint
from approvo.stores.base import EventStore


class ListEventStore(EventStore):
    """Read-only EventStore over a list already in hand. No writes, no locking."""

    def __init__(self, entries: list[LedgerEntry], log_id: str = "default") -> None:
        self.log_id = log_id
        self._entries = entries

    async def head(self):
        return self._entries[-1] if self._entries else None

    async def append(self, entry) -> None:
        raise NotImplementedError("read-only: this store is for verification only")

    async def get_by_seq(self, seq: int):
        return self._entries[seq] if 0 <= seq < len(self._entries) else None

    async def events_for_request(self, request_id: str):
        return [e for e in self._entries if e.request_id == request_id]

    async def scan(self, start: int = 0, limit: int | None = None):
        stop = len(self._entries) if limit is None else min(start + limit, len(self._entries))
        for entry in self._entries[start:stop]:
            yield entry

    async def leaf_hashes(self, up_to: int | None = None):
        hashes = [e.entry_hash for e in self._entries]
        return hashes if up_to is None else hashes[:up_to]

    async def latest_checkpoint(self):
        for entry in reversed(self._entries):
            if entry.event_type == "checkpoint.published":
                return Checkpoint.from_dict(entry.payload)
        return None


entries = [LedgerEntry.from_dict(row) for row in exported_rows]
svc = ApprovalService(
    events=ListEventStore(entries, log_id="releases"),
    key_dir=KeyDirectory.load("keys-from-out-of-band.json"),
    identities={}, policy_store=InMemoryPolicyStore([]),
)
report = await svc.verify(trusted_checkpoint=pinned)
```

This deliberately skips every integrity check on load — handing
`verify()` a tampered ledger is exactly how you find out it is tampered.

