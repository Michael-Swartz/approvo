"""In-memory stores used only by approvo's own test suite.

approvo ships no database adapters and no in-memory reference
implementation — see ``approvo.stores.base`` for the generic, storage-agnostic
protocols you implement over your own database. These classes exist purely so
approvo's tests (including the conformance suite in ``approvo.testing``) have
something concrete to run against; they are not part of the public API and
must not be imported from application code.

Implements the full async protocol with an ``asyncio.Lock`` standing in
for the database's unique constraint. Single-process only — two workers
sharing one of these share nothing.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from approvo.errors import IdempotencyConflict, LedgerConflict
from approvo.models import Checkpoint, LedgerEntry, Page, RequestQuery, RequestView
from approvo.stores.base import Reservation


class MemoryEventStore:
    def __init__(self, log_id: str = "default") -> None:
        self.log_id = log_id
        self._entries: list[LedgerEntry] = []
        self._by_request: dict[str, list[int]] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def from_entries(
        cls, entries: list[LedgerEntry], log_id: str = "default"
    ) -> MemoryEventStore:
        """Load entries verbatim, skipping every integrity check.

        For feeding a batch of entries you already have in memory — e.g.
        rows read straight from your own datastore — into
        :meth:`ApprovalService.verify`. It does not re-chain or validate on
        load; that is ``verify()``'s job, and handing it a tampered ledger
        is exactly how you find that out.
        """
        store = cls(log_id=log_id)
        store._entries = list(entries)
        for entry in store._entries:
            if entry.request_id:
                store._by_request.setdefault(entry.request_id, []).append(entry.seq)
        return store

    async def head(self) -> LedgerEntry | None:
        return self._entries[-1] if self._entries else None

    async def append(self, entry: LedgerEntry) -> None:
        async with self._lock:
            if entry.seq != len(self._entries):
                raise LedgerConflict(
                    f"seq {entry.seq} is not the next sequence ({len(self._entries)})"
                )
            self._entries.append(entry)
            if entry.request_id:
                self._by_request.setdefault(entry.request_id, []).append(entry.seq)

    async def get_by_seq(self, seq: int) -> LedgerEntry | None:
        return self._entries[seq] if 0 <= seq < len(self._entries) else None

    async def events_for_request(self, request_id: str) -> list[LedgerEntry]:
        return [self._entries[s] for s in self._by_request.get(request_id, ())]

    async def scan(self, start: int = 0, limit: int | None = None) -> AsyncIterator[LedgerEntry]:
        stop = len(self._entries) if limit is None else min(start + limit, len(self._entries))
        for entry in self._entries[start:stop]:
            yield entry

    async def leaf_hashes(self, up_to: int | None = None) -> list[str]:
        hashes = [e.entry_hash for e in self._entries]
        return hashes if up_to is None else hashes[:up_to]

    async def latest_checkpoint(self) -> Checkpoint | None:
        for entry in reversed(self._entries):
            if entry.event_type == "checkpoint.published":
                return Checkpoint.from_dict(entry.payload)
        return None


class MemoryProjectionStore:
    def __init__(self) -> None:
        self._views: dict[str, RequestView] = {}

    async def upsert(self, view: RequestView) -> None:
        current = self._views.get(view.request_id)
        if current is not None and current.last_seq > view.last_seq:
            return  # never move a view backwards
        self._views[view.request_id] = view

    async def get(self, request_id: str) -> RequestView | None:
        return self._views.get(request_id)

    async def query(self, query: RequestQuery) -> Page[RequestView]:
        items = sorted(self._views.values(), key=lambda v: v.created_at, reverse=True)
        if query.status:
            items = [v for v in items if v.status in query.status]
        if query.kind:
            items = [v for v in items if v.kind == query.kind]
        if query.requested_by:
            items = [v for v in items if v.requested_by == query.requested_by]
        if query.awaiting:
            items = [v for v in items if query.awaiting in v.pending_for]
        if query.subject_match:
            items = [
                v for v in items
                if all(v.subject.get(k) == val for k, val in query.subject_match.items())
            ]
        offset = int(query.cursor) if query.cursor else 0
        window = items[offset : offset + query.limit]
        next_cursor = (
            str(offset + query.limit) if offset + query.limit < len(items) else None
        )
        return Page(items=tuple(window), next_cursor=next_cursor)

    async def clear(self) -> None:
        self._views.clear()


class MemoryIdempotencyStore:
    def __init__(self) -> None:
        self._data: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def reserve(self, key: str, fingerprint: str) -> Reservation:
        async with self._lock:
            existing = self._data.get(key)
            if existing is None:
                self._data[key] = {"fingerprint": fingerprint, "response": None}
                return Reservation(won=True, fingerprint=fingerprint)
            if existing["fingerprint"] != fingerprint:
                raise IdempotencyConflict(key)
            return Reservation(
                won=False, fingerprint=fingerprint, response=existing["response"]
            )

    async def complete(self, key: str, response: dict) -> None:
        async with self._lock:
            self._data[key]["response"] = response

    async def release(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)
