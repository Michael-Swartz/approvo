"""Storage protocols and the in-memory reference implementation.

approvo ships no database adapters — see :mod:`approvo.stores.base` for
the contract you implement, and :mod:`approvo.testing` for the conformance
suite that proves your implementation satisfies it.
"""

from .base import (
    EventStore,
    IdempotencyStore,
    NullProjectionStore,
    ProjectionStore,
    Reservation,
)
from .memory import MemoryEventStore, MemoryIdempotencyStore, MemoryProjectionStore

__all__ = [
    "EventStore",
    "IdempotencyStore",
    "MemoryEventStore",
    "MemoryIdempotencyStore",
    "MemoryProjectionStore",
    "NullProjectionStore",
    "ProjectionStore",
    "Reservation",
]
