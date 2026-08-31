# ADR-0002 — DSSE envelopes, Ed25519, detached signing ceremony

**Status:** Accepted

## Context

A decision has to be non-repudiable: given the record, a third party must
be able to establish that a specific approver assented to a specific
request, and the approver must not be able to plausibly deny it.

Three sub-decisions: the signature primitive, the envelope format, and
*where the private key lives*.

## Decision

### Primitive: Ed25519

Small keys and signatures, fast, no parameter choices to get wrong, no
RNG dependence at signing time, ubiquitous library support. `cryptography`
provides it; that is approvo's only runtime dependency.

Other schemes (ECDSA P-256/P-384, RSA-PSS/PKCS1) are accommodated by the
`KeyRef.scheme` field and the `Signer` protocol; Ed25519 remains the
simplest local-signer path.

### Envelope: DSSE

[Dead Simple Signing Envelope](https://github.com/secure-systems-lab/dsse):
`{payloadType, payload (base64), signatures[]}`, with each signature over
the **PAE** (Pre-Authentication Encoding) of the payload type and body.
PAE prevents cross-protocol confusion where identical bytes are
reinterpreted under a different type.

We use DSSE rather than a bespoke format because it is the same envelope
in-toto and Sigstore use — reviewers and tooling already understand it —
and because "design your own signing envelope" is a well-known way to
introduce a vulnerability.

### Key custody: detached signing is the recommended path

Two APIs:

- `submit_decision(signer=...)` — the service signs. Simple, and fine for
  internal tooling where the BFF is already trusted with a lot. But the
  BFF then holds signing authority for every approver, so a BFF
  compromise means forged approvals.
- `prepare_decision(...) -> DecisionChallenge`, then
  `submit_signed_decision(envelope)` — the service produces the exact
  bytes to sign (`challenge.pae_b64`); the approver's client signs; the
  service only ever handles the signature bytes and the already-registered
  public key. A fully
  compromised BFF still cannot forge an approval.

`submit_signed_decision` re-derives and re-verifies everything from the
envelope — the challenge is advisory and never trusted. The envelope must
carry a valid signature for the approver it names, bind to the current
request body via `context_digest`, and fall inside the window (with a
bounded clock-skew allowance).

## Consequences

- Non-repudiation holds even against the party running approvo, **if**
  detached signing is used. The docs push callers toward it for anything
  that gates production.
- Client-side signing needs a client-side key: a WebCrypto/WebAuthn key, a
  CLI key file, an HSM agent. That is real integration work — hence the
  simpler server-side option remains available with its trade-off
  documented.
- Verification is `O(signatures)` per decision. Decisions have one or two
  signatures. Not a concern.
- `KeyRef` carries `not_before` / `not_after` / `revoked_at`; verification
  is evaluated **at the decision's timestamp**, so key rotation does not
  invalidate past approvals and revocation is not retroactive.
