# ADR-0006 — Canonical JSON for all hashing and signing

**Status:** Accepted

## Context

Content-addressing, the hash chain, `context_digest`, `policy.digest`, and
DSSE payloads all hash structured data. If the byte representation of a
value isn't unique and stable, none of those work: a re-serialization that
reorders keys or changes number formatting silently invalidates every
signature.

## Decision

All hashing and signing is over **canonical bytes** produced by
`approvo.canonical.canonical_bytes`, a strict subset of
[RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785):

- UTF-8, object keys sorted, compact separators (`,` / `:`), no
  insignificant whitespace.
- Allowed types: `dict`, `list`, `str`, `int`, `bool`, `None`.
- **Floats are rejected** (`NotCanonicalizable`). There is no
  cross-language, cross-version float representation worth betting an
  audit trail on. Callers use integers or strings (e.g. decimal amounts
  as `"10.00"`).
- Dict keys must be strings.

Timestamps are RFC 3339 UTC strings (`...Z`) *before* they reach the
hasher, never `datetime` objects — so serialization can't vary.

Golden test vectors in `tests/test_canonical.py` pin exact bytes and
hashes; changing them is a wire-compatibility break that requires a schema
version bump, not a vector edit.

## Alternatives considered

- **Full RFC 8785**, including its number canonicalization. We keep the
  structural rules but drop float support entirely rather than depend on
  correct ECMAScript-style number formatting. Stricter, simpler, safer.
- **CBOR / Protocol Buffers.** Canonical forms exist, but JSON keeps the
  ledger greppable and human-auditable, which is worth a lot for this use
  case.
- **`json.dumps(sort_keys=True)` and hope.** That is essentially what we
  do — plus an explicit type check that rejects the values (`float`,
  non-str keys, arbitrary objects) where "and hope" would otherwise bite.

## Consequences

- Every hashed structure round-trips to identical bytes on any platform
  and Python version in support.
- Callers occasionally hit `NotCanonicalizable` for a float in a subject.
  The error names the path. This is a deliberate, early failure.
- `securesystemslib`'s canonical encoder (used by TUF/in-toto) would have
  worked too; we kept the dependency surface at one library
  (`cryptography`) and wrote ~40 lines instead.
