"""Run the shipped conformance suite against the in-memory reference stores.

If you write your own store (Postgres, Mongo, DynamoDB, ...), do exactly
this in your own test file with your own fixture. See
``approvo.stores.base`` and ``approvo.testing``.
"""

from __future__ import annotations

import pytest

from approvo.stores import (
    MemoryEventStore,
    MemoryIdempotencyStore,
    MemoryProjectionStore,
)
from approvo.testing import (
    EventStoreConformance,
    IdempotencyStoreConformance,
    ProjectionStoreConformance,
)


class TestMemoryEventStore(EventStoreConformance):
    @pytest.fixture
    def event_store(self) -> MemoryEventStore:
        return MemoryEventStore(log_id="conformance")


class TestMemoryProjectionStore(ProjectionStoreConformance):
    @pytest.fixture
    def projection_store(self) -> MemoryProjectionStore:
        return MemoryProjectionStore()


class TestMemoryIdempotencyStore(IdempotencyStoreConformance):
    @pytest.fixture
    def idempotency_store(self) -> MemoryIdempotencyStore:
        return MemoryIdempotencyStore()
