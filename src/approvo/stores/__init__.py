"""Storage protocols — the generic, database-agnostic contract.

approvo ships no database adapters and no in-memory reference
implementation — see :mod:`approvo.stores.base` for the contract you
implement over your own database, and :mod:`approvo.testing` for the
conformance suite that proves your implementation satisfies it.
"""

from .base import (
    EventStore,
    IdempotencyStore,
    NullProjectionStore,
    ProjectionStore,
    Reservation,
)

__all__ = [
    "EventStore",
    "IdempotencyStore",
    "NullProjectionStore",
    "ProjectionStore",
    "Reservation",
]
