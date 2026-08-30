# ADR-0009 — Projections are rebuildable and never gate a decision

**Status:** Accepted

## Context

A UI needs to list requests: "everything awaiting me", "rejected this
week", "pending for service X". Answering those from the ledger means, for
each request, loading its events and re-running the policy — fine for one
request, far too slow for a filtered list over thousands.

The temptation is to keep a `status` column and query that. The moment you
do, that column is a second source of truth that can disagree with the
ledger — through a bug, a race, or tampering — and now a deploy gate might
read the wrong one.

## Decision

Two explicitly separate read models:

| | `Record` — `get_status()` | `RequestView` — `get_view()` / `query()` |
|---|---|---|
| Source | replayed from the ledger, policy re-run | `ProjectionStore` row |
| Correctness | authoritative, always exact | eventually consistent |
| Cost | `O(decisions for this request)` | one indexed read |
| Gate on it? | **yes** | **never** |
| If lost | n/a | `rebuild_projections()` |

`RequestView` is a *rendering* of a `Record` (`approvo.projection.build_view`)
— denormalized fields plus `approvers`, `pending_for`, and a `last_seq`
watermark. The service upserts it after every mutation. `upsert` must
refuse to move a view backwards (`last_seq` guard), so a late or replayed
projection can't resurrect stale state.

The projection store is disposable. `rebuild_projections()` clears it and
regenerates every view from the ledger; run it after a schema change,
after a projection-store outage, or just to prove the read model still
agrees with the truth.

`NullProjectionStore` is provided for callers that only ever read by id
and don't want the table at all.

## Consequences

- List/filter/search is a single indexed query, and the ledger is never
  scanned to render a screen.
- There is a visible, bounded staleness window on `RequestView` between a
  mutation and its projection upsert. Documented; acceptable for UI.
- Gating logic must call `get_status`, not `get_view`. This is stated in
  the docstrings, the README, and [Concepts](../concepts.md); a linter
  rule in the host app is a reasonable belt-and-braces.
- Projection storage can be lost entirely with no impact on
  auditability — it is a cache, and it is treated like one.
