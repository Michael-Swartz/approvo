# ADR-0010 — A KMS-agnostic `KeyProvider` interface, no bundled KMS in core

**Status:** Accepted

## Context

Server-side signing needs keys that live somewhere real: GCP Cloud KMS,
AWS KMS, Azure Key Vault, HashiCorp Vault Transit, a PKCS#11 HSM, or —
for a single node — a file. We did not want:

- approvo core to depend on any cloud SDK,
- every call site to know which KMS is in play,
- a matrix of half-maintained adapters (the same reasoning as
  [ADR-0004](0004-datastore-agnostic.md) for datastores).

## Decision

Two layers.

**`Signer`** stays the low-level primitive: "produce one signature over
bytes." It gains an ``algorithm`` attribute (a scheme id) and its
``sign`` may now return an awaitable, because a KMS call is I/O.
:func:`approvo.crypto.sign_with` normalises sync/async and returns
``(signature, keyid)`` so an envelope records exactly which key/version
signed.

**`KeyProvider`** is the new KMS-agnostic backend. It resolves an opaque
URI-ish **key reference** (`gcpkms://…`, `awskms://…`, `vault://…`,
`file:///…`, `env://…`, `memory://…`) to a *primed* `Signer` (public key
already fetched, so ``key_id()`` is synchronous) and to
`PublicKeyMaterial`. `CompositeKeyProvider` routes by scheme, so swapping
KMS is a config edit.

Core ships `InMemoryKeyProvider`, `LocalFileKeyProvider`,
`EnvKeyProvider`, `CompositeKeyProvider`, and an algorithm registry
(`approvo.crypto.algorithms`) covering Ed25519, ECDSA P-256/P-384, and
RSA-PSS/PKCS1 — the schemes mainstream KMS offer. Cloud back ends
(`approvo.providers.gcpkms`, `.awskms`, `.vault`) are optional extras
whose SDK import is lazy, so the module imports without the SDK installed.

`approvo.testing.KeyProviderConformance` is the executable spec: sign +
verify a nonce through the same registry the library uses, public-key
stability, primed metadata, error contracts.

## Consequences

- Zero cloud dependencies in `approvo`'s tree; `cryptography` stays the
  only runtime requirement.
- Verification is unchanged in shape — it already dispatched per key; now
  it dispatches through the registry, so a new curve is a registry entry,
  not a verifier edit.
- Key rotation is safe: the concrete keyid/version is captured at signing
  time and stored in the envelope, so historical signatures keep
  verifying after `…/cryptoKeyVersions/3 → 4`.
- A community KMS adapter can live in its own package implementing the
  same protocol, validated by the same conformance suite.
