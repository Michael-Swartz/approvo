# ADR-0004 — Ship store protocols and a conformance suite, not adapters

**Status:** Accepted

## Context

approvo is invoked from a backend-for-frontend that already owns a
database — Postgres, MongoDB, DynamoDB, CockroachDB, something. That
service has opinions approvo cannot share: which migration tool runs DDL,
how the connection pool is configured, where transaction boundaries sit,
what the naming conventions are, whether calls are sync or async.

We considered shipping `approvo.stores.postgres`, `approvo.stores.mongo`,
etc. We started to, and deleted them. A bundled adapter:

- imposes a driver dependency (`asyncpg`? `psycopg`? which version?),
- fights the host app's migrations and pool,
- has to guess at transaction semantics,
- accumulates per-database bug reports and feature requests,
- rots, because the maintainers don't run every database in anger.

## Decision

approvo ships **no database adapters**. It ships:

1. **Three protocols** in `approvo.stores.base` — `EventStore`,
   `ProjectionStore`, `IdempotencyStore` — each a handful of `async`
   methods, each with its invariants written down as MUST/SHOULD.
2. **A conformance suite** in `approvo.testing` —
   `EventStoreConformance`, `ProjectionStoreConformance`,
   `IdempotencyStoreConformance` — that is the executable form of those
   invariants, including concurrency tests (N racing `append`s / `reserve`s
   must yield exactly one winner).

You implement the protocols over your database, subclass the conformance
suites with a fixture yielding a fresh store, and run pytest. Green means
approvo's guarantees hold on your datastore.

approvo does **not** ship an in-memory reference implementation either.
Earlier versions did (`approvo.stores.memory`), but a store that is part
of the public API invites production use it was never hardened for — no
persistence, no multi-process coordination, silent data loss on restart —
and every doc example that imported it obscured how little code the
protocols actually require. The three protocols above are the only
storage-agnostic surface approvo ships; anything concrete lives either in
your own codebase or in the test suite that exercises it (see
[Storage](../storage.md) for a from-scratch worked example, and
`approvo.stores.base` for the full contract).

## Consequences

- Zero database dependencies in `approvo`'s dependency tree. The only
  runtime dependency stays `cryptography`.
- The integration burden is real: a first Postgres implementation is
  ~150 lines. The conformance suite makes it a bounded, verifiable task
  rather than a guess.
- The reference schema sketches in [Storage](../storage.md) are
  documentation, not code — they can't drift into being a
  half-maintained adapter.
- If a particular database's implementation turns out to be genuinely
  fiddly (a distinguished-name for conditional writes, say), that is a
  docs problem to solve in the open, not a matrix of adapters to
  maintain.
- A community adapter can live in its own package
  (`approvo-postgres`) without the core project owning its lifecycle.
- Docs and this library's own tests implement the protocols with small,
  local, dict/list-backed stores where a worked example is useful; those
  are illustrative code, not something you `import` from `approvo`.
