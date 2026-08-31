# Stores

The three storage protocols you implement against your datastore; see
[Storage](../storage.md) for why there are three and how to validate an
implementation.

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
