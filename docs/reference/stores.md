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

## Conformance suite

::: approvo.testing
    options:
      members:
        - EventStoreConformance
        - ProjectionStoreConformance
        - IdempotencyStoreConformance
