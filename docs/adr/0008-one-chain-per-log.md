# ADR-0008 — One hash chain per `log_id`; partition to scale writes

**Status:** Accepted

## Context

A hash chain is a totally ordered structure: entry N+1 contains the hash
of entry N. That makes every append a read-modify-write against the same
tail. A single global chain is therefore a single global write lock —
fine at approval volumes for one team, a bottleneck for a multi-tenant
platform.

## Decision

Every store is scoped to a `log_id`, chosen by the integrator. One
`log_id` is one independent hash chain with its own sequence space, its
own checkpoints, and its own `verify()`.

Partition along whatever boundary matches your write pattern and your
audit boundary:

- **per tenant** — a SaaS platform; tenant A's rewrite attempt is
  provable without involving tenant B's ledger.
- **per environment** — `releases-prod`, `releases-staging`.
- **per team or service** — keeps each chain short and each `verify()`
  fast.

`ApprovalService` is constructed per log. Cross-log queries (a global
"everything awaiting me" screen) are the [projection
store](0009-projections-not-authoritative.md)'s job, not the ledger's.

## Consequences

- Write throughput scales with partition count. Within a partition,
  concurrent appends are serialized by the `(log_id, seq)` uniqueness
  constraint and resolved by the service's retry loop.
- More partitions = more checkpoints to publish and pin, and more
  `verify()` runs to schedule. Operational cost is roughly linear in
  partition count.
- Choosing the partition key is a one-way door: moving a request between
  logs would break its chain position. Pick the boundary deliberately.
  When unsure, err toward *coarser* (fewer, longer chains) and split later
  by starting new logs.
- There is no ordering guarantee *across* logs. If you need a global order
  of events, that is a downstream concern (e.g. merge by `recorded_at`
  with ties broken by `log_id`), and it is not part of the tamper-evidence
  guarantee.
