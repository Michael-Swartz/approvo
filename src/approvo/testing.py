"""Conformance suite for store implementations.

approvo ships no database adapters, so this module is how you find out
whether *yours* is correct. Every MUST in :mod:`approvo.stores.base` has a
test here. If these pass against your store, approvo's tamper-evidence and
idempotency guarantees hold on your datastore.

Subclass the suite and supply a fixture yielding a **fresh, empty** store::

    import pytest
    from approvo.testing import EventStoreConformance

    class TestMyEventStore(EventStoreConformance):
        @pytest.fixture
        async def event_store(self):
            store = MyEventStore(pool, log_id="test")
            await store.truncate()          # your own reset helper
            yield store

Then just run pytest. The suites are ``EventStoreConformance``,
``ProjectionStoreConformance``, ``IdempotencyStoreConformance``, and
``KeyProviderConformance`` (for KMS/HSM signing back ends).

Requires ``pytest`` and ``pytest-asyncio`` (``pip install 'approvo[dev]'``).
Tests are explicitly marked ``@pytest.mark.asyncio``, so they work whether
or not your project sets ``asyncio_mode = "auto"``.

The concurrency tests here exercise real parallelism only if your store
talks to a real datastore over a pool. They will pass trivially against a
single-connection or in-process store — that is expected, and it is why
you should run this against the thing you actually deploy.
"""

from __future__ import annotations

import asyncio

import pytest

from .canonical import ZERO_HASH
from .chain import next_entry
from .crypto.algorithms import get_scheme, known_schemes
from .crypto.keyprovider import KeyProvider
from .crypto.signer import sign_with
from .errors import IdempotencyConflict, KeyProviderError, LedgerConflict
from .models import Checkpoint, LedgerEntry, RequestQuery, RequestView

T0 = "2026-08-30T12:00:00.000Z"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def make_entry(
    seq: int,
    *,
    prev: LedgerEntry | None = None,
    event_type: str = "request.created",
    request_id: str | None = None,
    payload: dict | None = None,
    at_time: str = T0,
) -> LedgerEntry:
    """Build a sealed entry suitable for appending at *seq*."""
    if prev is not None:
        return next_entry(
            prev,
            event_type=event_type,
            payload=payload if payload is not None else {"n": seq},
            at_time=at_time,
            request_id=request_id,
        )
    return LedgerEntry(
        seq=seq,
        recorded_at=at_time,
        prev_hash=ZERO_HASH,
        event_type=event_type,  # type: ignore[arg-type]
        request_id=request_id,
        payload=payload if payload is not None else {"n": seq},
    ).sealed()


async def append_chain(store, count: int, *, request_id: str | None = None) -> list[LedgerEntry]:
    """Append *count* correctly-chained entries and return them."""
    entries: list[LedgerEntry] = []
    prev = await store.head()
    for i in range(count):
        entry = make_entry(
            (prev.seq + 1) if prev else 0, prev=prev, request_id=request_id
        )
        await store.append(entry)
        entries.append(entry)
        prev = entry
    return entries


def make_view(request_id: str, **overrides) -> RequestView:
    defaults = {
        "request_id": request_id,
        "kind": "software-release",
        "status": "pending",
        "requested_by": "user:riley",
        "policy_id": "release-v1",
        "subject": {"artifact_digest": "sha256:ab", "version": "1.4.0"},
        "created_at": T0,
        "not_valid_after": "2026-09-06T12:00:00.000Z",
        "updated_at": T0,
        "approvals": 0,
        "threshold": 2,
        "approvers": (),
        "pending_for": ("user:casey", "user:jordan"),
        "last_seq": 0,
    }
    return RequestView(**{**defaults, **overrides})  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# EventStore
# --------------------------------------------------------------------------- #


class EventStoreConformance:
    """Subclass and provide an ``event_store`` fixture yielding an empty store."""

    @pytest.mark.asyncio
    async def test_empty_head_is_none(self, event_store):
        assert await event_store.head() is None

    @pytest.mark.asyncio
    async def test_append_then_head(self, event_store):
        entry = make_entry(0)
        await event_store.append(entry)
        head = await event_store.head()
        assert head is not None
        assert head.entry_hash == entry.entry_hash
        assert head.seq == 0

    @pytest.mark.asyncio
    async def test_head_tracks_highest_seq(self, event_store):
        entries = await append_chain(event_store, 5)
        head = await event_store.head()
        assert head.seq == 4
        assert head.entry_hash == entries[-1].entry_hash

    @pytest.mark.asyncio
    async def test_duplicate_seq_raises_conflict(self, event_store):
        await event_store.append(make_entry(0))
        with pytest.raises(LedgerConflict):
            await event_store.append(make_entry(0, payload={"different": True}))

    @pytest.mark.asyncio
    async def test_conflicting_append_does_not_overwrite(self, event_store):
        original = make_entry(0)
        await event_store.append(original)
        with pytest.raises(LedgerConflict):
            await event_store.append(make_entry(0, payload={"evil": True}))
        stored = await event_store.get_by_seq(0)
        assert stored.entry_hash == original.entry_hash
        assert stored.payload == original.payload

    @pytest.mark.asyncio
    async def test_get_by_seq(self, event_store):
        entries = await append_chain(event_store, 3)
        assert (await event_store.get_by_seq(1)).entry_hash == entries[1].entry_hash
        assert await event_store.get_by_seq(99) is None

    @pytest.mark.asyncio
    async def test_payload_roundtrips_faithfully(self, event_store):
        payload = {
            "nested": {"a": [1, 2, {"b": None}], "unicode": "héllo — ✅"},
            "empty_dict": {},
            "empty_list": [],
            "bool": True,
            "int": -17,
        }
        entry = make_entry(0, payload=payload)
        await event_store.append(entry)
        stored = await event_store.get_by_seq(0)
        assert stored.payload == payload
        # the hash must survive the storage round trip, or verification breaks
        assert stored.entry_hash == entry.entry_hash
        assert stored.sealed().entry_hash == entry.entry_hash

    @pytest.mark.asyncio
    async def test_events_for_request_filters_and_orders(self, event_store):
        prev = None
        wanted, other = "sha256:aaa", "sha256:bbb"
        expected = []
        for i in range(6):
            rid = wanted if i % 2 == 0 else other
            entry = make_entry((prev.seq + 1) if prev else 0, prev=prev, request_id=rid)
            await event_store.append(entry)
            if rid == wanted:
                expected.append(entry)
            prev = entry

        found = await event_store.events_for_request(wanted)
        assert [e.seq for e in found] == [e.seq for e in expected]
        assert all(e.request_id == wanted for e in found)

    @pytest.mark.asyncio
    async def test_events_for_unknown_request_is_empty(self, event_store):
        await append_chain(event_store, 3, request_id="sha256:aaa")
        assert await event_store.events_for_request("sha256:nope") == []

    @pytest.mark.asyncio
    async def test_entries_without_request_id_are_excluded(self, event_store):
        prev = None
        entry = make_entry(0, request_id="sha256:aaa")
        await event_store.append(entry)
        prev = entry
        await event_store.append(
            make_entry(1, prev=prev, event_type="checkpoint.published", request_id=None)
        )
        found = await event_store.events_for_request("sha256:aaa")
        assert [e.seq for e in found] == [0]

    @pytest.mark.asyncio
    async def test_scan_orders_and_respects_start(self, event_store):
        await append_chain(event_store, 5)
        seen = [e.seq async for e in event_store.scan()]
        assert seen == [0, 1, 2, 3, 4]
        seen = [e.seq async for e in event_store.scan(start=2)]
        assert seen == [2, 3, 4]

    @pytest.mark.asyncio
    async def test_scan_respects_limit(self, event_store):
        await append_chain(event_store, 5)
        seen = [e.seq async for e in event_store.scan(start=1, limit=2)]
        assert seen == [1, 2]

    @pytest.mark.asyncio
    async def test_scan_past_end_is_empty(self, event_store):
        await append_chain(event_store, 2)
        assert [e async for e in event_store.scan(start=99)] == []

    @pytest.mark.asyncio
    async def test_leaf_hashes_order_and_up_to_is_exclusive(self, event_store):
        entries = await append_chain(event_store, 5)
        assert await event_store.leaf_hashes() == [e.entry_hash for e in entries]
        assert await event_store.leaf_hashes(up_to=3) == [e.entry_hash for e in entries[:3]]
        assert await event_store.leaf_hashes(up_to=0) == []

    @pytest.mark.asyncio
    async def test_latest_checkpoint(self, event_store):
        assert await event_store.latest_checkpoint() is None
        prev = None
        for i, size in enumerate([1, 2]):
            cp = Checkpoint(
                tree_size=size,
                root_hash=f"sha256:{i:064x}",
                published_at=T0,
                log_id=event_store.log_id,
            )
            entry = make_entry(
                (prev.seq + 1) if prev else 0,
                prev=prev,
                event_type="checkpoint.published",
                payload=cp.to_dict(),
            )
            await event_store.append(entry)
            prev = entry
        latest = await event_store.latest_checkpoint()
        assert latest is not None
        assert latest.tree_size == 2

    @pytest.mark.asyncio
    async def test_concurrent_appends_yield_exactly_one_winner(self, event_store):
        """The core anti-fork guarantee: N writers, same seq, one survivor."""
        contenders = [make_entry(0, payload={"writer": i}) for i in range(8)]
        results = await asyncio.gather(
            *(event_store.append(e) for e in contenders), return_exceptions=True
        )
        succeeded = [r for r in results if not isinstance(r, Exception)]
        conflicts = [r for r in results if isinstance(r, LedgerConflict)]
        unexpected = [
            r for r in results if isinstance(r, Exception) and not isinstance(r, LedgerConflict)
        ]

        assert not unexpected, f"append raised non-LedgerConflict errors: {unexpected}"
        assert len(succeeded) == 1, "exactly one concurrent append must succeed"
        assert len(conflicts) == len(contenders) - 1

        head = await event_store.head()
        assert head.seq == 0
        assert head.entry_hash in {e.entry_hash for e in contenders}


# --------------------------------------------------------------------------- #
# ProjectionStore
# --------------------------------------------------------------------------- #


class ProjectionStoreConformance:
    """Subclass and provide a ``projection_store`` fixture yielding an empty store."""

    @pytest.mark.asyncio
    async def test_get_unknown_is_none(self, projection_store):
        assert await projection_store.get("sha256:nope") is None

    @pytest.mark.asyncio
    async def test_upsert_then_get(self, projection_store):
        view = make_view("sha256:aaa")
        await projection_store.upsert(view)
        stored = await projection_store.get("sha256:aaa")
        assert stored is not None
        assert stored.to_dict() == view.to_dict()

    @pytest.mark.asyncio
    async def test_upsert_updates_in_place(self, projection_store):
        await projection_store.upsert(make_view("sha256:aaa", last_seq=1))
        await projection_store.upsert(
            make_view("sha256:aaa", status="approved", approvals=2, last_seq=2)
        )
        stored = await projection_store.get("sha256:aaa")
        assert stored.status == "approved"
        assert stored.approvals == 2
        page = await projection_store.query(RequestQuery())
        assert len(page.items) == 1, "upsert must not create a duplicate row"

    @pytest.mark.asyncio
    async def test_upsert_never_moves_view_backwards(self, projection_store):
        await projection_store.upsert(
            make_view("sha256:aaa", status="approved", approvals=2, last_seq=5)
        )
        # a stale/replayed projection arrives late
        await projection_store.upsert(
            make_view("sha256:aaa", status="pending", approvals=0, last_seq=2)
        )
        stored = await projection_store.get("sha256:aaa")
        assert stored.status == "approved"
        assert stored.last_seq == 5

    @pytest.mark.asyncio
    async def test_query_filters_by_status(self, projection_store):
        await projection_store.upsert(make_view("sha256:a", status="pending"))
        await projection_store.upsert(make_view("sha256:b", status="approved"))
        page = await projection_store.query(RequestQuery(status=("approved",)))
        assert [v.request_id for v in page.items] == ["sha256:b"]

    @pytest.mark.asyncio
    async def test_query_filters_by_kind_and_requester(self, projection_store):
        await projection_store.upsert(make_view("sha256:a", kind="db-migration"))
        await projection_store.upsert(make_view("sha256:b", requested_by="user:sam"))
        assert [v.request_id for v in (
            await projection_store.query(RequestQuery(kind="db-migration"))
        ).items] == ["sha256:a"]
        assert [v.request_id for v in (
            await projection_store.query(RequestQuery(requested_by="user:sam"))
        ).items] == ["sha256:b"]

    @pytest.mark.asyncio
    async def test_query_filters_by_awaiting(self, projection_store):
        await projection_store.upsert(make_view("sha256:a", pending_for=("user:casey",)))
        await projection_store.upsert(make_view("sha256:b", pending_for=("user:jordan",)))
        page = await projection_store.query(RequestQuery(awaiting="user:jordan"))
        assert [v.request_id for v in page.items] == ["sha256:b"]

    @pytest.mark.asyncio
    async def test_query_filters_by_subject(self, projection_store):
        await projection_store.upsert(
            make_view("sha256:a", subject={"artifact_digest": "sha256:xx", "version": "1.0.0"})
        )
        await projection_store.upsert(
            make_view("sha256:b", subject={"artifact_digest": "sha256:yy", "version": "2.0.0"})
        )
        page = await projection_store.query(
            RequestQuery(subject_match={"artifact_digest": "sha256:yy"})
        )
        assert [v.request_id for v in page.items] == ["sha256:b"]

    @pytest.mark.asyncio
    async def test_query_filters_combine_with_and(self, projection_store):
        await projection_store.upsert(make_view("sha256:a", status="approved", kind="k1"))
        await projection_store.upsert(make_view("sha256:b", status="approved", kind="k2"))
        page = await projection_store.query(RequestQuery(status=("approved",), kind="k2"))
        assert [v.request_id for v in page.items] == ["sha256:b"]

    @pytest.mark.asyncio
    async def test_pagination_covers_every_item_exactly_once(self, projection_store):
        ids = [f"sha256:{i:03d}" for i in range(10)]
        for i, rid in enumerate(ids):
            await projection_store.upsert(
                make_view(rid, created_at=f"2026-08-{10 + i:02d}T12:00:00.000Z")
            )

        seen, cursor, pages = [], None, 0
        while True:
            page = await projection_store.query(RequestQuery(limit=3, cursor=cursor))
            seen.extend(v.request_id for v in page.items)
            pages += 1
            cursor = page.next_cursor
            if cursor is None:
                break
            assert pages < 20, "pagination did not terminate"

        assert sorted(seen) == sorted(ids)
        assert len(seen) == len(set(seen)), "an item appeared on two pages"

    @pytest.mark.asyncio
    async def test_clear(self, projection_store):
        await projection_store.upsert(make_view("sha256:a"))
        await projection_store.clear()
        assert await projection_store.get("sha256:a") is None
        assert (await projection_store.query(RequestQuery())).items == ()


# --------------------------------------------------------------------------- #
# IdempotencyStore
# --------------------------------------------------------------------------- #


class IdempotencyStoreConformance:
    """Subclass and provide an ``idempotency_store`` fixture yielding an empty store."""

    @pytest.mark.asyncio
    async def test_first_reserve_wins(self, idempotency_store):
        res = await idempotency_store.reserve("k1", "fp1")
        assert res.won is True

    @pytest.mark.asyncio
    async def test_second_reserve_loses(self, idempotency_store):
        await idempotency_store.reserve("k1", "fp1")
        res = await idempotency_store.reserve("k1", "fp1")
        assert res.won is False

    @pytest.mark.asyncio
    async def test_response_is_none_until_completed(self, idempotency_store):
        await idempotency_store.reserve("k1", "fp1")
        assert (await idempotency_store.reserve("k1", "fp1")).response is None
        await idempotency_store.complete("k1", {"request_id": "sha256:aaa"})
        assert (await idempotency_store.reserve("k1", "fp1")).response == {
            "request_id": "sha256:aaa"
        }

    @pytest.mark.asyncio
    async def test_fingerprint_mismatch_raises(self, idempotency_store):
        await idempotency_store.reserve("k1", "fp1")
        with pytest.raises(IdempotencyConflict):
            await idempotency_store.reserve("k1", "fp2")

    @pytest.mark.asyncio
    async def test_release_allows_rereserve(self, idempotency_store):
        await idempotency_store.reserve("k1", "fp1")
        await idempotency_store.release("k1")
        assert (await idempotency_store.reserve("k1", "fp1")).won is True

    @pytest.mark.asyncio
    async def test_distinct_keys_are_independent(self, idempotency_store):
        assert (await idempotency_store.reserve("k1", "fp1")).won is True
        assert (await idempotency_store.reserve("k2", "fp2")).won is True

    @pytest.mark.asyncio
    async def test_concurrent_reserve_yields_exactly_one_winner(self, idempotency_store):
        results = await asyncio.gather(
            *(idempotency_store.reserve("k1", "fp1") for _ in range(8)),
            return_exceptions=True,
        )
        errors = [r for r in results if isinstance(r, Exception)]
        assert not errors, f"reserve raised under concurrency: {errors}"
        assert sum(1 for r in results if r.won) == 1


# --------------------------------------------------------------------------- #
# KeyProvider
# --------------------------------------------------------------------------- #


class KeyProviderConformance:
    """Subclass and provide two fixtures:

    - ``key_provider`` — an instance of your
      :class:`~approvo.crypto.keyprovider.KeyProvider`.
    - ``key_ref`` — a reference string that provider can resolve to a
      working signing key.

    Example::

        class TestGcpKmsProvider(KeyProviderConformance):
            @pytest.fixture
            def key_provider(self):
                return GcpKmsKeyProvider()

            @pytest.fixture
            def key_ref(self):
                return "gcpkms://projects/…/cryptoKeyVersions/1"
    """

    @pytest.mark.asyncio
    async def test_is_a_key_provider(self, key_provider):
        assert isinstance(key_provider, KeyProvider)
        assert key_provider.schemes, "provider must declare at least one scheme"

    @pytest.mark.asyncio
    async def test_public_key_scheme_is_known(self, key_provider, key_ref):
        pub = await key_provider.get_public_key(key_ref)
        assert pub.scheme in known_schemes()
        assert isinstance(pub.public, bytes) and pub.public

    @pytest.mark.asyncio
    async def test_public_key_is_stable(self, key_provider, key_ref):
        a = await key_provider.get_public_key(key_ref)
        b = await key_provider.get_public_key(key_ref)
        assert a.public == b.public
        assert a.keyid == b.keyid

    @pytest.mark.asyncio
    async def test_signer_is_primed(self, key_provider, key_ref):
        signer = await key_provider.get_signer(key_ref)
        # metadata must be available without another round trip
        assert signer.algorithm in known_schemes()
        assert signer.key_id() == (await key_provider.get_public_key(key_ref)).keyid

    @pytest.mark.asyncio
    async def test_sign_then_verify(self, key_provider, key_ref):
        signer = await key_provider.get_signer(key_ref)
        pub = signer.public_material()
        message = b"approvo-conformance-" + b"x" * 64
        sig, keyid = await sign_with(signer, message)
        assert keyid == pub.keyid
        # must verify through the same scheme registry the library uses
        get_scheme(pub.scheme).verify(pub.public, sig, message)

    @pytest.mark.asyncio
    async def test_signature_does_not_verify_for_other_message(self, key_provider, key_ref):
        signer = await key_provider.get_signer(key_ref)
        pub = signer.public_material()
        sig, _ = await sign_with(signer, b"message-one")
        with pytest.raises(Exception):  # noqa: B017 - InvalidSignature or similar
            get_scheme(pub.scheme).verify(pub.public, sig, b"message-two")

    @pytest.mark.asyncio
    async def test_self_test_passes(self, key_provider, key_ref):
        await key_provider.self_test(key_ref)

    @pytest.mark.asyncio
    async def test_unknown_ref_raises_key_provider_error(self, key_provider):
        scheme = key_provider.schemes[0]
        with pytest.raises(KeyProviderError):
            await key_provider.get_signer(f"{scheme}://definitely-not-a-real-key-xyz")
