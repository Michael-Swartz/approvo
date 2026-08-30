# ADR-0007 — Reserve-then-complete idempotency for mutations

**Status:** Accepted

## Context

`create_request` is handled by content-addressing
([ADR-0001](0001-content-addressed-requests.md)). Recording a **decision**
is not naturally idempotent: it appends to the ledger, and a naive retry
appends twice. Retries are guaranteed here — flaky networks, at-least-once
queues, impatient operators — and two BFF instances may process the same
retry concurrently.

## Decision

`IdempotencyStore` is a **reserve → complete** protocol:

```python
res = await store.reserve(key, fingerprint)   # atomic; exactly one caller gets won=True
if res.won:
    try:
        result = do_the_work()                # append to the ledger
    except Exception:
        await store.release(key)              # let a later retry try again
        raise
    await store.complete(key, {"request_id": ...})
else:
    # someone else is doing / did the work
    replay(res.response)                      # may be None if still in flight
```

- **key**: `decision.idempotency_key`, defaulting to
  `f"{request_id}:{approver_id}:{verdict}"`.
- **fingerprint**: `canonical_hash(decision.to_dict())`. Same key with a
  different fingerprint (e.g. same key, opposite verdict) raises
  `IdempotencyConflict` — that is a caller bug, not a retry.
- **won=False, response=None**: the winner is mid-flight. The service
  returns the current `get_status` rather than racing the append; the
  winner's write is the authoritative one.

The append itself has a second layer of protection: the `EventStore`'s
uniqueness constraint on `(log_id, seq)` means even if two reservations
somehow both proceed, only one row lands and the other retries against the
new head (`_append` does full-jitter backoff, then `ConcurrencyExhausted`).

## Alternatives considered

- **Single `put(key, response)` after the fact.** Doesn't help concurrent
  in-flight retries — both do the work before either records it.
- **Rely solely on `(log_id, seq)` uniqueness.** Prevents the double
  *row*, but both callers still construct and attempt the append, and
  neither gets a clean "your retry already succeeded" answer. The
  idempotency store gives callers a definitive replay.
- **Dedupe by scanning the ledger for an existing decision.** `O(ledger)`
  and racy.

## Consequences

- Integrators implement a small third store. The conformance suite pins
  its semantics, including the concurrent-`reserve`-one-winner test.
- Idempotency rows are disposable: TTL-expire them, but with a window
  comfortably longer than any client's retry budget — expiring early turns
  a replay into a genuine second append attempt.
- `release` on failure is important; skipping it wedges the key until TTL.
  The service always does it in a `finally`-style path.
