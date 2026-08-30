"""Storage protocols — the contract between approvo and your database.

approvo ships **no database adapters**. It does not open connections,
manage pools, run migrations, or own transactions — your service already
does all of that, with its own conventions, and a library that duplicates
them just fights you. Instead approvo defines three protocols; you
implement them over whatever you already run, in whatever style your
codebase uses.

To check your implementation is correct, run the conformance suite in
:mod:`approvo.testing` against it. That suite is the executable version
of every MUST below — if it passes, approvo's guarantees hold on your
datastore.

Three stores, three very different trust levels:

:class:`EventStore`
    **The source of truth.** Append-only, hash-chained.

:class:`ProjectionStore`
    **A rebuildable cache.** Powers list/filter/search screens. Losing it
    is a non-event: rebuild from the event store. Never gate on it.

:class:`IdempotencyStore`
    **Short-lived coordination.** Reserve-then-complete, so concurrent
    retries of one logical call collapse to a single ledger append.

All methods are ``async``. A store over a synchronous driver may satisfy
the protocol with non-awaiting ``async def`` bodies, but do not do that on
a request path — it will block the event loop.

Every store is scoped to a ``log_id``. One log is one hash chain, and
therefore one write-serialization point: partition by tenant, team, or
environment to keep chains short and writes parallel (see ADR-0008).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..models import Checkpoint, LedgerEntry, Page, RequestQuery, RequestView


@dataclass(frozen=True)
class Reservation:
    """Result of :meth:`IdempotencyStore.reserve`.

    ``won`` is True for the single caller that acquired the slot and must
    do the work. Everyone else gets ``won=False`` plus, once the winner has
    called :meth:`IdempotencyStore.complete`, the stored ``response``.
    """

    won: bool
    fingerprint: str
    response: dict | None = None


@runtime_checkable
class EventStore(Protocol):
    """Append-only, hash-chained event log. The source of truth.

    Implementation requirements:

    1. **Appends MUST be atomic on ``(log_id, seq)``.** Use a unique
       constraint, unique index, or conditional write — whatever your
       datastore offers natively. Do *not* emulate it with a read
       followed by a write; that races, and the race silently forks the
       chain. When the sequence number is already taken, raise
       :class:`~approvo.errors.LedgerConflict`; the service catches it and
       retries against the new head.
    2. **Entries MUST NOT be mutable.** Deny UPDATE and DELETE to the
       application's credentials. approvo detects tampering either way,
       but detection is a worse outcome than prevention.
    3. **``events_for_request`` MUST be indexed** on
       ``(log_id, request_id, seq)``. It is on the hot path of every
       status read; a scan here makes approvo O(ledger) per request and
       it will not scale.
    4. **Reads MUST return entries in ``seq`` order**, and ``scan`` MUST
       stream rather than materialize — verification walks the whole log.
    5. **Writes SHOULD be durable before returning.** With an
       asynchronously-replicated store, a rolled-back append leaves a gap
       that verification will correctly report as tampering.
    """

    log_id: str

    async def head(self) -> LedgerEntry | None:
        """Highest-``seq`` entry, or None for an empty log."""
        ...

    async def append(self, entry: LedgerEntry) -> None:
        """Insert *entry*, atomically failing if its ``seq`` is taken.

        Raises:
            ~approvo.errors.LedgerConflict: ``entry.seq`` already exists.
        """
        ...

    async def get_by_seq(self, seq: int) -> LedgerEntry | None: ...

    async def events_for_request(self, request_id: str) -> list[LedgerEntry]:
        """All events for one request, in ``seq`` order. Must be indexed."""
        ...

    def scan(self, start: int = 0, limit: int | None = None) -> AsyncIterator[LedgerEntry]:
        """Stream entries from *start* in ``seq`` order.

        Note this returns an async iterator directly rather than being an
        ``async def`` — implement it with ``async def`` + ``yield``.
        """
        ...

    async def leaf_hashes(self, up_to: int | None = None) -> list[str]:
        """``entry_hash`` values in ``seq`` order, for Merkle computation.

        ``up_to`` is exclusive: pass a checkpoint's ``tree_size`` to get
        exactly the leaves that checkpoint committed to.
        """
        ...

    async def latest_checkpoint(self) -> Checkpoint | None:
        """Most recent published checkpoint, or None."""
        ...


@runtime_checkable
class ProjectionStore(Protocol):
    """Denormalized read model. Rebuildable; never authoritative.

    Implementation requirements:

    1. **``upsert`` MUST NOT move a view backwards.** Apply only when the
       incoming ``last_seq`` is greater than or equal to the stored one,
       so out-of-order or replayed projections cannot resurrect stale
       state. A conditional update is the usual mechanism.
    2. **``query`` SHOULD use keyset pagination**, not offsets, and encode
       whatever it needs in the opaque ``next_cursor`` string.
    3. Filters in :class:`~approvo.models.RequestQuery` combine with AND.
       Unsupported filters SHOULD raise rather than be ignored — silently
       returning unfiltered rows to an approvals UI is a security problem,
       not a cosmetic one.
    """

    async def upsert(self, view: RequestView) -> None: ...

    async def get(self, request_id: str) -> RequestView | None: ...

    async def query(self, query: RequestQuery) -> Page[RequestView]: ...

    async def clear(self) -> None:
        """Drop all views for this log. Called before a full rebuild."""
        ...


@runtime_checkable
class IdempotencyStore(Protocol):
    """Reserve-then-complete coordination for retried mutations.

    Implementation requirements:

    1. **``reserve`` MUST be atomic**, returning ``won=True`` to exactly
       one concurrent caller — an insert-if-absent, conditional put, or
       equivalent.
    2. **A key reused with a different fingerprint MUST raise**
       :class:`~approvo.errors.IdempotencyConflict`. That is a caller bug
       (the same key meaning two different things), not a retry.
    3. Rows MAY be expired on a TTL. Choose a window comfortably longer
       than your clients' retry budget; expiring early turns a replay into
       a duplicate append attempt, which the ledger will accept as a
       genuine second decision.
    """

    async def reserve(self, key: str, fingerprint: str) -> Reservation:
        """Atomically claim *key* for this caller."""
        ...

    async def complete(self, key: str, response: dict) -> None:
        """Record the winner's result so later retries can replay it."""
        ...

    async def release(self, key: str) -> None:
        """Drop a reservation whose work failed, so a retry can proceed."""
        ...


class NullProjectionStore:
    """No-op projections, for callers that only ever read by id.

    Perfectly reasonable: projections exist to power list screens. If your
    BFF only ever fetches one request at a time, skip them entirely and
    save yourself a table.
    """

    async def upsert(self, view: RequestView) -> None:
        return None

    async def get(self, request_id: str) -> RequestView | None:
        return None

    async def query(self, query: RequestQuery) -> Page[RequestView]:
        return Page(items=())

    async def clear(self) -> None:
        return None
