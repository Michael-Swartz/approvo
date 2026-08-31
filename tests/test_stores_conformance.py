"""Run the shipped conformance suite against the in-memory test stores.

If you write your own store (Postgres, Mongo, DynamoDB, ...), do exactly
this in your own test file with your own fixture. See
``approvo.stores.base`` and ``approvo.testing``.
"""

from __future__ import annotations

import pytest

from approvo.testing import (
    EventStoreConformance,
    IdempotencyStoreConformance,
    ProjectionStoreConformance,
)
from tests.memory_stores import (
    MemoryEventStore,
    MemoryIdempotencyStore,
    MemoryProjectionStore,
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
