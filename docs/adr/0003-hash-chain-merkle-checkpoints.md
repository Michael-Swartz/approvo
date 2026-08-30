# ADR-0003 — Hash-chained ledger + signed Merkle checkpoints

**Status:** Accepted

## Context

The ledger lives in a database approvo does not control — the caller's
Postgres, Mongo, whatever. We need edits, deletions, insertions,
reordering, and wholesale replacement to be *detectable* by anyone with
the public trust material, without approvo owning the storage.

## Decision

### Per-entry hash chain

Each `LedgerEntry` has an `entry_hash = canonical_hash(core)` covering
`{seq, recorded_at, prev_hash, event_type, request_id, payload}`, and a
`prev_hash` equal to the previous entry's `entry_hash` (genesis:
all-zeroes). `verify_segment` walks entries checking: contiguous `seq`
from the expected start, each `prev_hash` matching, each `entry_hash`
reproducing.

This makes any *local* modification break the chain from that point
forward.

### Signed Merkle checkpoints

The chain alone only proves internal consistency: an operator who
`TRUNCATE`s and re-inserts a fabricated history produces a perfectly
self-consistent chain. So we add [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)-style
checkpoints: `Checkpoint{tree_size, root_hash, published_at,
prev_root_hash, signatures}` where `root_hash` is the Merkle root over all
`entry_hash` leaves, signed by a dedicated **log key** and appended to the
ledger as a `checkpoint.published` event.

Consumers pin a checkpoint somewhere the operator cannot write.
`verify(trusted_checkpoint=cp)` recomputes the Merkle root over the
current log's first `cp.tree_size` leaves and requires it to equal
`cp.root_hash` — proving the current log is an *extension* of the trusted
state, not a rewrite.

### Domain separation

Leaf hash = `SHA-256(0x00 ‖ leaf)`, node hash = `SHA-256(0x01 ‖ left ‖
right)`, per RFC 6962, so a leaf can never be reinterpreted as an internal
node.

## Alternatives considered

- **Full transparency log (Trillian / Rekor).** Strong, but it is
  infrastructure, not a library. approvo can *anchor* to Rekor later; it
  should not require it.
- **Blockchain.** No. The trust and cost model is wrong for
  intra-organisation approvals.
- **Sign every entry individually with the log key.** Equivalent tamper
  detection for edits, but no efficient proof that a *prefix* is
  unchanged, and no single value to pin. Merkle gives both.

## Consequences

- Tamper *evidence*, not tamper *prevention* — pair with revoked
  `UPDATE`/`DELETE` grants and off-site mirroring (see
  [Security model](../security.md)).
- Fork detection is only as good as checkpoint pinning discipline. The gap
  between the newest pinned checkpoint and now is the undetectable-rewrite
  window.
- `verify()` currently fetches the prefix leaves to check consistency.
  Bandwidth-optimized RFC 6962 consistency proofs (for verifiers that
  cannot fetch the prefix) are a compatible future addition.
- One chain per `log_id` — see [ADR-0008](0008-one-chain-per-log.md).
