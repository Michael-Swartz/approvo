# Vehicle software release approvals — a worked example

A runnable, end-to-end example of using [approvo](../../README.md) as the
approval engine behind a small **FastAPI** backend-for-frontend, backed by
**MongoDB**. It models a real workflow: before a vehicle ECU firmware
build can be released, it needs sign-off from a safety engineer *and* QA.

This is what the architecture diagram in the top-level README looks like
with the boxes filled in:

```
┌────────────────┐     approvo (library)           ┌──────────────────┐
│  FastAPI app   │  create_request / submit_        │  MongoDB         │
│  (this example)│─▶ decision / get_status / query ─▶│  (this example)  │
│                │◀─ Record / RequestView ──────────│                  │
└────────────────┘                                  └──────────────────┘
```

approvo itself never touches a socket or a database connection — this
example is the code you write to plug it into a real stack. The three
storage classes in [`app/mongo_stores.py`](app/mongo_stores.py) are the
whole adapter; everything else (hashing, signing, policy evaluation, the
ledger) comes from the library.

## What this demonstrates

- **Content-addressed requests** — opening the same release request twice
  returns the same request, no duplicates.
- **A real policy** — two approvals required, from two *different* roles
  (`safety-engineer` and `qa`); the requester can't approve their own
  release (separation of duties, on by default).
- **A tamper-evident ledger in MongoDB** — every request and decision is
  an immutable, hash-chained document; `GET /verify` re-derives and
  checks the whole chain.
- **Fast, rebuildable list views** — `GET /releases` reads a MongoDB
  projection collection, never the ledger directly.
- **Idempotent decision submission** — retried decision calls collapse to
  one ledger entry instead of appending duplicates.

It intentionally simplifies one thing: decisions are signed **server-side**
(`ApprovalService.submit_decision`) using per-demo-approver keys generated
at startup, so the HTTP API stays simple (`POST` an `approver_id` and a
`verdict`). A production deployment gating real releases should use
**detached signing** instead — the approver's own device signs, and the
server never holds their private key — see
[`docs/getting-started.md`](../../docs/getting-started.md#detached-signing-recommended-for-production)
and [`docs/signing.md`](../../docs/signing.md) in the main repo.

## Layout

```
examples/vehicle-release-approvals/
├── app/
│   ├── main.py          # FastAPI app: routes, lifespan, error mapping
│   ├── mongo_stores.py  # MongoDB EventStore / ProjectionStore / IdempotencyStore
│   ├── identities.py    # demo keys, identities, and the release policy
│   ├── schemas.py       # request/response models
│   └── config.py        # env-driven settings
├── scripts/
│   └── demo.py          # scripted walkthrough of the whole flow, via HTTP
├── docker-compose.yml   # MongoDB only — the app itself runs locally
├── requirements.txt
└── .env.example
```

## Running it

Requires Python ≥ 3.11 and Docker (for MongoDB only — the app runs
locally with plain `python`/`uvicorn`, not in a container).

```console
# from the repository root: install approvo itself, editable
pip install -e .

# from this directory: install the example's own dependencies
cd examples/vehicle-release-approvals
pip install -r requirements.txt

# bring up MongoDB
docker compose up -d

# configure (defaults already match docker-compose.yml)
cp .env.example .env

# run the API
uvicorn app.main:app --reload
```

In another terminal, run the scripted walkthrough:

```console
python scripts/demo.py
```

Expected output (ids/hashes will differ):

```
known approvers: {'user:priya': {'roles': ['safety-engineer']}, ...}
created release request: 3f9c...
status after 1st approval: pending ['1/2 approvals; roles still required: ...']
status after 2nd approval: approved ['threshold 2 met by: user:noah, user:priya']
gate check passed: approved
approved releases: ['3f9c...']
published checkpoint over 4 ledger entries
ledger verified: True - 4 checks passed
```

Or drive it by hand with `curl`:

```console
curl -s localhost:8000/identities | python -m json.tool

curl -s -X POST localhost:8000/releases \
  -H 'content-type: application/json' \
  -d '{
        "subject": {
          "ecu": "brake-controller",
          "artifact_digest": "sha256:ab...",
          "version": "3.2.1",
          "vehicle_platform": "model-x"
        },
        "requested_by": "user:sam",
        "approval_window_hours": 168
      }'
# => {"request_id": "...", ...}

curl -s -X POST localhost:8000/releases/<request_id>/decisions \
  -H 'content-type: application/json' \
  -d '{"approver_id": "user:priya", "verdict": "approve"}'

curl -s -X POST localhost:8000/releases/<request_id>/decisions \
  -H 'content-type: application/json' \
  -d '{"approver_id": "user:noah", "verdict": "approve"}'

curl -s localhost:8000/releases/<request_id>   # authoritative status — gate on this
curl -s localhost:8000/releases                # projection-backed list, for a UI
```

## API

| Method | Path                          | Purpose                                              |
| ------ | ----------------------------- | ----------------------------------------------------- |
| GET    | `/identities`                 | Demo roster of known approvers and their roles         |
| POST   | `/releases`                   | Open a release-approval request (idempotent)           |
| POST   | `/releases/{id}/decisions`    | Submit an approve/reject decision                      |
| GET    | `/releases/{id}`              | Authoritative status, re-derived from the ledger        |
| GET    | `/releases`                   | List/filter releases (projection store, for a UI)      |
| POST   | `/checkpoint`                 | Publish a signed Merkle tree head over the ledger       |
| GET    | `/verify`                     | Re-derive and check the entire ledger for tampering     |

Interactive docs (Swagger UI) are available at `/docs` once the app is
running.

## Why MongoDB here

approvo ships no database adapters by design (see
[ADR-0004](../../docs/adr/0004-datastore-agnostic.md) and
[`docs/storage.md`](../../docs/storage.md)) — you implement the three
protocols in `approvo.stores.base` over whatever you run. This example
follows the MongoDB schema sketch in `docs/storage.md` closely:

- The ledger's `(log_id, seq)` uniqueness — the anti-fork guarantee — is
  enforced by MongoDB's own unique index on `_id`, encoding both fields
  into the document id.
- Projection upserts use a conditional update (`last_seq <= incoming`)
  with `upsert=True`, so an out-of-order or replayed projection can never
  move a view backwards.
- Idempotency reservations are a plain insert-if-absent on `_id`.

## Testing the stores against approvo's own conformance suite

approvo ships a conformance suite (`approvo.testing`) that exercises every
`MUST` in the storage contract, including concurrent-writer races. You can
point it at these MongoDB stores directly:

```python
import pytest
from motor.motor_asyncio import AsyncIOMotorClient
from approvo.testing import EventStoreConformance, ProjectionStoreConformance

from app.mongo_stores import MongoEventStore, MongoProjectionStore


class TestMongoEventStore(EventStoreConformance):
    @pytest.fixture
    async def event_store(self):
        db = AsyncIOMotorClient("mongodb://localhost:27017")["approvo_test"]
        store = MongoEventStore(db, log_id="test")
        await store.ensure_indexes()
        yield store
        await db["approvo_ledger"].delete_many({"log_id": "test"})


class TestMongoProjectionStore(ProjectionStoreConformance):
    @pytest.fixture
    async def projection_store(self):
        db = AsyncIOMotorClient("mongodb://localhost:27017")["approvo_test"]
        store = MongoProjectionStore(db, log_id="test")
        await store.ensure_indexes()
        yield store
        await store.clear()
```

Run against the MongoDB brought up by `docker compose up -d` in this
directory.
