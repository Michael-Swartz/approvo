"""MongoDB implementations of approvo's storage protocols.

approvo ships no database adapters (see ``approvo.stores.base`` and
``docs/storage.md`` in the main repo) — these three classes are what you
must write for any datastore. They mirror the reference schema sketch in
``docs/storage.md`` and satisfy approvo's conformance suite
(``approvo.testing``); see ``tests/test_mongo_stores.py`` for that.

Each store is scoped to a single ``log_id`` (one hash chain). Collections
are shared across logs; every document carries a ``log_id`` field and,
for the ledger, encodes ``(log_id, seq)`` into ``_id`` so MongoDB's
built-in unique index on ``_id`` gives us the atomic append the
``EventStore`` contract requires — no separate unique index needed.
"""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator

from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError

from approvo.errors import IdempotencyConflict, LedgerConflict
from approvo.models import Checkpoint, LedgerEntry, Page, RequestQuery, RequestView
from approvo.stores.base import Reservation


class MongoEventStore:
    """Append-only, hash-chained ledger backed by a MongoDB collection.

    Atomicity on ``(log_id, seq)`` comes from encoding both into ``_id``:
    a second writer for the same slot hits MongoDB's ``_id`` unique index
    and gets ``DuplicateKeyError``, which we translate to
    ``LedgerConflict`` per the ``EventStore`` contract.
    """

    def __init__(self, db: AsyncIOMotorDatabase, log_id: str) -> None:
        self.log_id = log_id
        self._col = db["approvo_ledger"]

    async def ensure_indexes(self) -> None:
        await self._col.create_index([("log_id", ASCENDING), ("seq", DESCENDING)])
        await self._col.create_index(
            [("log_id", ASCENDING), ("request_id", ASCENDING), ("seq", ASCENDING)]
        )
        await self._col.create_index(
            [("log_id", ASCENDING), ("event_type", ASCENDING), ("seq", DESCENDING)]
        )

    @staticmethod
    def _doc_id(log_id: str, seq: int) -> str:
        return f"{log_id}:{seq}"

    def _to_entry(self, doc: dict) -> LedgerEntry:
        return LedgerEntry(
            seq=doc["seq"],
            recorded_at=doc["recorded_at"],
            prev_hash=doc["prev_hash"],
            event_type=doc["event_type"],
            request_id=doc.get("request_id"),
            payload=doc["payload"],
            entry_hash=doc["entry_hash"],
        )

    async def head(self) -> LedgerEntry | None:
        doc = await self._col.find_one({"log_id": self.log_id}, sort=[("seq", DESCENDING)])
        return self._to_entry(doc) if doc else None

    async def append(self, entry: LedgerEntry) -> None:
        doc = {
            "_id": self._doc_id(self.log_id, entry.seq),
            "log_id": self.log_id,
            **entry.core_dict(),
            "entry_hash": entry.entry_hash,
        }
        try:
            await self._col.insert_one(doc)
        except DuplicateKeyError as e:
            raise LedgerConflict(f"seq {entry.seq} already taken in log {self.log_id!r}") from e

    async def get_by_seq(self, seq: int) -> LedgerEntry | None:
        doc = await self._col.find_one({"_id": self._doc_id(self.log_id, seq)})
        return self._to_entry(doc) if doc else None

    async def events_for_request(self, request_id: str) -> list[LedgerEntry]:
        cursor = self._col.find(
            {"log_id": self.log_id, "request_id": request_id}
        ).sort("seq", ASCENDING)
        return [self._to_entry(doc) async for doc in cursor]

    async def scan(self, start: int = 0, limit: int | None = None) -> AsyncIterator[LedgerEntry]:
        cursor = self._col.find(
            {"log_id": self.log_id, "seq": {"$gte": start}}
        ).sort("seq", ASCENDING)
        if limit is not None:
            cursor = cursor.limit(limit)
        async for doc in cursor:
            yield self._to_entry(doc)

    async def leaf_hashes(self, up_to: int | None = None) -> list[str]:
        query: dict = {"log_id": self.log_id}
        if up_to is not None:
            query["seq"] = {"$lt": up_to}
        cursor = self._col.find(query, {"entry_hash": 1}).sort("seq", ASCENDING)
        return [doc["entry_hash"] async for doc in cursor]

    async def latest_checkpoint(self) -> Checkpoint | None:
        doc = await self._col.find_one(
            {"log_id": self.log_id, "event_type": "checkpoint.published"},
            sort=[("seq", DESCENDING)],
        )
        return Checkpoint.from_dict(doc["payload"]) if doc else None


class MongoProjectionStore:
    """Denormalized read model, rebuildable from the ledger at any time.

    ``upsert`` must never move a view backwards (an out-of-order or
    replayed projection cannot resurrect stale state). We express that as
    a conditional update (``last_seq <= incoming.last_seq``) with
    ``upsert=True``; when the condition fails on an existing document,
    MongoDB raises a duplicate-key error on ``_id`` instead of inserting,
    which we simply swallow — the newer view already stored wins.
    """

    def __init__(self, db: AsyncIOMotorDatabase, log_id: str) -> None:
        self.log_id = log_id
        self._col = db["approvo_projections"]

    async def ensure_indexes(self) -> None:
        await self._col.create_index([("log_id", ASCENDING), ("status", ASCENDING)])
        await self._col.create_index([("log_id", ASCENDING), ("kind", ASCENDING)])
        await self._col.create_index([("log_id", ASCENDING), ("requested_by", ASCENDING)])
        await self._col.create_index([("log_id", ASCENDING), ("pending_for", ASCENDING)])
        await self._col.create_index(
            [("log_id", ASCENDING), ("created_at", ASCENDING), ("_id", ASCENDING)]
        )

    def _doc_id(self, request_id: str) -> str:
        return f"{self.log_id}:{request_id}"

    def _to_view(self, doc: dict) -> RequestView:
        return RequestView(
            request_id=doc["request_id"],
            kind=doc["kind"],
            status=doc["status"],
            requested_by=doc["requested_by"],
            policy_id=doc["policy_id"],
            subject=doc["subject"],
            created_at=doc["created_at"],
            not_valid_after=doc["not_valid_after"],
            updated_at=doc["updated_at"],
            approvals=doc["approvals"],
            threshold=doc["threshold"],
            approvers=tuple(doc.get("approvers", ())),
            pending_for=tuple(doc.get("pending_for", ())),
            last_seq=doc.get("last_seq", 0),
        )

    async def upsert(self, view: RequestView) -> None:
        doc_id = self._doc_id(view.request_id)
        update = {
            "$set": {
                "log_id": self.log_id,
                **view.to_dict(),
            }
        }
        try:
            await self._col.update_one(
                {"_id": doc_id, "last_seq": {"$lte": view.last_seq}},
                update,
                upsert=True,
            )
        except DuplicateKeyError:
            # A view with a higher (or equal) last_seq is already stored;
            # this upsert is stale (out-of-order or replayed) and must not
            # move the projection backwards. Safe to ignore.
            pass

    async def get(self, request_id: str) -> RequestView | None:
        doc = await self._col.find_one({"_id": self._doc_id(request_id)})
        return self._to_view(doc) if doc else None

    async def query(self, query: RequestQuery) -> Page[RequestView]:
        mongo_query: dict = {"log_id": self.log_id}
        if query.status:
            mongo_query["status"] = {"$in": list(query.status)}
        if query.kind is not None:
            mongo_query["kind"] = query.kind
        if query.requested_by is not None:
            mongo_query["requested_by"] = query.requested_by
        if query.awaiting is not None:
            mongo_query["pending_for"] = query.awaiting
        if query.subject_match is not None:
            for field, value in query.subject_match.items():
                mongo_query[f"subject.{field}"] = value

        if query.cursor:
            after_created_at, after_id = json.loads(
                base64.urlsafe_b64decode(query.cursor.encode()).decode()
            )
            mongo_query["$or"] = [
                {"created_at": {"$gt": after_created_at}},
                {"created_at": after_created_at, "_id": {"$gt": after_id}},
            ]

        limit = query.limit
        cursor = (
            self._col.find(mongo_query)
            .sort([("created_at", ASCENDING), ("_id", ASCENDING)])
            .limit(limit + 1)
        )
        docs = [doc async for doc in cursor]

        next_cursor = None
        if len(docs) > limit:
            docs = docs[:limit]
            last = docs[-1]
            next_cursor = base64.urlsafe_b64encode(
                json.dumps([last["created_at"], last["_id"]]).encode()
            ).decode()

        return Page(items=tuple(self._to_view(d) for d in docs), next_cursor=next_cursor)

    async def clear(self) -> None:
        await self._col.delete_many({"log_id": self.log_id})


class MongoIdempotencyStore:
    """Reserve-then-complete coordination for retried decision submissions."""

    def __init__(self, db: AsyncIOMotorDatabase, log_id: str) -> None:
        self.log_id = log_id
        self._col = db["approvo_idempotency"]

    async def ensure_indexes(self) -> None:
        # _id already gives us the uniqueness reserve() needs; nothing extra
        # is required, but a TTL index is recommended in production so
        # reservations expire well after your clients' retry budget:
        # await self._col.create_index("created_at", expireAfterSeconds=86400)
        pass

    def _doc_id(self, key: str) -> str:
        return f"{self.log_id}:{key}"

    async def reserve(self, key: str, fingerprint: str) -> Reservation:
        doc_id = self._doc_id(key)
        try:
            await self._col.insert_one(
                {"_id": doc_id, "fingerprint": fingerprint, "response": None}
            )
            return Reservation(won=True, fingerprint=fingerprint)
        except DuplicateKeyError:
            existing = await self._col.find_one({"_id": doc_id})
            if existing["fingerprint"] != fingerprint:
                raise IdempotencyConflict(key) from None
            return Reservation(won=False, fingerprint=fingerprint, response=existing["response"])

    async def complete(self, key: str, response: dict) -> None:
        await self._col.update_one({"_id": self._doc_id(key)}, {"$set": {"response": response}})

    async def release(self, key: str) -> None:
        await self._col.delete_one({"_id": self._doc_id(key)})
