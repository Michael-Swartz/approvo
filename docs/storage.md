# Storage

approvo ships **no database adapters**. It defines three async protocols
in `approvo.stores.base` and a conformance suite in `approvo.testing`. You
implement the protocols over the database you already run, run the suite,
and inject the result. [ADR-0004](adr/0004-datastore-agnostic.md) explains
the reasoning; the short version is that a bundled adapter would fight
your migration tool, your pool, and your transaction boundaries, and would
rot.

## The three stores

| Store | Trust level | Lose it and… |
|---|---|---|
| `EventStore` | **source of truth** | you have lost the approvals |
| `ProjectionStore` | rebuildable cache | run `rebuild_projections()` |
| `IdempotencyStore` | short-lived coordination | in-flight retries may double-append |

All three are scoped to a `log_id`. One log is one hash chain, hence one
write-serialization point — [partition](adr/0008-one-chain-per-log.md) by
tenant, team, or environment.

> **Why three protocols, not one?** Each has a different failure mode, and
> collapsing them would hide that. Lose the `EventStore` and you have lost
> the approvals — it's the source of truth. Lose the `ProjectionStore` and
> you call `rebuild_projections()` — it's a disposable cache; skip it
> entirely with `NullProjectionStore` if you don't need list screens. Lose
> the `IdempotencyStore` and in-flight retries might double-append — it's
> short-lived coordination, not data. One interface would either force
> every implementer to build idempotency/projection machinery they don't
> need, or blur which failures actually matter. See
> [ADR-0004](adr/0004-datastore-agnostic.md) for the full design rationale
> and [the conformance suite](#the-conformance-suite) to validate your
> implementation.

## `EventStore`

```python
class EventStore(Protocol):
    log_id: str

    async def head(self) -> LedgerEntry | None: ...
    async def append(self, entry: LedgerEntry) -> None: ...
    async def get_by_seq(self, seq: int) -> LedgerEntry | None: ...
    async def events_for_request(self, request_id: str) -> list[LedgerEntry]: ...
    def scan(self, start: int = 0, limit: int | None = None) -> AsyncIterator[LedgerEntry]: ...
    async def leaf_hashes(self, up_to: int | None = None) -> list[str]: ...
    async def latest_checkpoint(self) -> Checkpoint | None: ...
```

Requirements (each has a conformance test):

1. **`append` MUST be atomic on `(log_id, seq)`.** Use a native unique
   constraint / unique index / conditional write. Do **not** read-then-
   write — it races and the race silently forks the chain. On a taken
   sequence number, raise `approvo.errors.LedgerConflict`; the service
   catches it and retries against the new head (full-jitter backoff, then
   `ConcurrencyExhausted`).
2. **Entries MUST NOT be mutable.** Deny `UPDATE`/`DELETE` to the app
   credential. approvo detects tampering regardless, but prevention beats
   detection.
3. **`events_for_request` MUST be indexed** on `(log_id, request_id,
   seq)`. It is on the hot path of every status read.
4. **Reads MUST return `seq` order**; `scan` MUST stream (server-side
   cursor), because `verify()` walks the whole log.
5. **Writes SHOULD be durable before returning.** A rolled-back append
   leaves a gap that `verify()` correctly reports as tampering.

`LedgerEntry` serializes with `.to_dict()` / `.from_dict()` to plain
JSON-compatible types. Store `entry.to_dict()` as a JSON/JSONB column or
document; keep `seq`, `request_id`, `event_type`, and `entry_hash` as
separate indexed columns for query performance.

## `ProjectionStore`

```python
class ProjectionStore(Protocol):
    async def upsert(self, view: RequestView) -> None: ...
    async def get(self, request_id: str) -> RequestView | None: ...
    async def query(self, query: RequestQuery) -> Page[RequestView]: ...
    async def clear(self) -> None: ...
```

Requirements:

1. **`upsert` MUST NOT move a view backwards** — apply only when the
   incoming `last_seq` ≥ the stored one. A conditional update does it.
2. **`query` SHOULD use keyset pagination**, encoding its cursor in the
   opaque `next_cursor` string. `RequestQuery` filters combine with AND;
   an unsupported filter SHOULD raise, not be silently ignored (returning
   unfiltered rows to an approvals screen is a security problem).

Don't need list screens? Use `NullProjectionStore` and skip the table
entirely. ([ADR-0009](adr/0009-projections-not-authoritative.md))

## `IdempotencyStore`

```python
class IdempotencyStore(Protocol):
    async def reserve(self, key: str, fingerprint: str) -> Reservation: ...
    async def complete(self, key: str, response: dict) -> None: ...
    async def release(self, key: str) -> None: ...
```

Requirements:

1. **`reserve` MUST be atomic** — return `won=True` to exactly one
   concurrent caller (insert-if-absent / conditional put). Others get
   `won=False` plus the stored fingerprint and, once the winner calls
   `complete`, the response.
2. **A key reused with a different fingerprint MUST raise**
   `IdempotencyConflict`.
3. Rows MAY be TTL-expired. Pick a window well beyond your clients' retry
   budget — expiring early turns a replay into a real second append.

## The conformance suite

```python
# tests/test_my_stores.py
import pytest
from approvo.testing import (
    EventStoreConformance, ProjectionStoreConformance, IdempotencyStoreConformance,
)
from myapp.approvo_stores import (
    PgEventStore, PgProjectionStore, PgIdempotencyStore,
)


class TestPgEventStore(EventStoreConformance):
    @pytest.fixture
    async def event_store(self, pg_pool):
        await pg_pool.execute("TRUNCATE approvo_ledger")
        yield PgEventStore(pg_pool, log_id="test")


class TestPgProjectionStore(ProjectionStoreConformance):
    @pytest.fixture
    async def projection_store(self, pg_pool):
        await pg_pool.execute("TRUNCATE approvo_request_view")
        yield PgProjectionStore(pg_pool, log_id="test")


class TestPgIdempotencyStore(IdempotencyStoreConformance):
    @pytest.fixture
    async def idempotency_store(self, pg_pool):
        await pg_pool.execute("TRUNCATE approvo_idempotency")
        yield PgIdempotencyStore(pg_pool, log_id="test")
```

The suite includes concurrency tests (`asyncio.gather` of eight competing
`append`s / `reserve`s expecting exactly one winner). Those exercise real
parallelism only against a real datastore over a pool — they pass
trivially against a single-connection store, which is why you run this
against the thing you actually deploy.

Requires `pytest` + `pytest-asyncio` (`pip install approvo[dev]`). Tests
are marked `@pytest.mark.asyncio`, so they work with or without
`asyncio_mode = "auto"`.

## Reference schema sketches

Not shipped as code — adapt to your migration tool.

### PostgreSQL

```sql
CREATE TABLE approvo_ledger (
    log_id      text        NOT NULL,
    seq         bigint      NOT NULL,
    entry_hash  text        NOT NULL,
    prev_hash   text        NOT NULL,
    event_type  text        NOT NULL,
    request_id  text,
    recorded_at timestamptz NOT NULL,
    entry       jsonb       NOT NULL,
    PRIMARY KEY (log_id, seq)                       -- the concurrency control
);
CREATE INDEX ON approvo_ledger (log_id, request_id, seq)
    WHERE request_id IS NOT NULL;                   -- the hot-path index
CREATE INDEX ON approvo_ledger (log_id, seq DESC)
    WHERE event_type = 'checkpoint.published';
-- then: REVOKE UPDATE, DELETE ON approvo_ledger FROM <app_role>;
```

### MongoDB

```js
db.approvo_ledger.createIndex({ log_id: 1, seq: 1 }, { unique: true })   // concurrency control
db.approvo_ledger.createIndex(
    { log_id: 1, request_id: 1, seq: 1 },
    { partialFilterExpression: { request_id: { $type: "string" } } })    // hot-path index
db.approvo_ledger.createIndex({ log_id: 1, event_type: 1, seq: -1 })
// grant the app role insert + find only; use majority write concern
```

Map `DuplicateKeyError` / `UniqueViolationError` → `LedgerConflict` in
your `append`.

## Runnable example

A complete MongoDB implementation of all three stores — plus a FastAPI
service and a scripted end-to-end walkthrough — lives in
[`examples/vehicle-release-approvals/`](https://github.com/Michael-Swartz/approvo/tree/main/examples/vehicle-release-approvals)
in the repository. It passes the conformance suite above against a real
`mongod` and is a good starting point for adapting to your own datastore.

