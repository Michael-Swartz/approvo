# Stores

approvo ships no database adapters. You implement these three protocols
against your datastore and validate with the
[conformance suite](../storage.md#the-conformance-suite).

## Protocols

::: approvo.stores.base.EventStore

::: approvo.stores.base.ProjectionStore

::: approvo.stores.base.IdempotencyStore

::: approvo.stores.base.Reservation

::: approvo.stores.base.NullProjectionStore

## In-memory reference implementations

Usable in production for single-process or low-volume deployments;
primarily here as a worked example and for tests.

::: approvo.stores.memory.MemoryEventStore

::: approvo.stores.memory.MemoryProjectionStore

::: approvo.stores.memory.MemoryIdempotencyStore

## Conformance suite

::: approvo.testing
    options:
      members:
        - EventStoreConformance
        - ProjectionStoreConformance
        - IdempotencyStoreConformance
