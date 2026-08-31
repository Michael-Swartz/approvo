# Signing

approvo has one signing primitive and three ways to drive it. Pick per
approval flow — they coexist in the same service and the same ledger.

| Approach | Who holds the key | Server can forge? | Use for |
|---|---|---|---|
| **Detached ceremony** | the approver's client | no | gates on production |
| **Per-person `Signer`** | wherever you keep it (KMS per person) | only if that store is compromised | strong, no browser signing |
| **Org / custodial (`SigningService`)** | your backend, via a KMS | yes (mitigable) | internal tooling, high volume, zero approver key management |

The library core cares about none of this — `Signer` is a protocol and
`KeyDirectory` is the trust root. Everything below is wiring.

## The primitive: `Signer`

```python
class Signer(Protocol):
    algorithm: str                      # "ed25519", "ecdsa-p256-sha256", ...
    def key_id(self) -> str: ...
    def sign(self, data: bytes) -> bytes | Awaitable[bytes]: ...
    def public_material(self) -> PublicKeyMaterial: ...
```

`sign` may be sync or async (a KMS call is I/O). `approvo.sign_with(signer,
data)` normalises both and returns `(signature, keyid)`.

Shipped: `Ed25519Signer` (in-process, for dev/tests). KMS-backed signers
come from a `KeyProvider`.

## `KeyProvider` — KMS-agnostic backend

Resolves an opaque **key reference** to a primed `Signer` and a public
key. Core ships local providers; cloud ones are optional extras.

```python
from approvo.crypto import (
    CompositeKeyProvider, LocalFileKeyProvider, InMemoryKeyProvider, EnvKeyProvider,
)
from approvo.providers.gcpkms import GcpKmsKeyProvider   # pip install 'approvo[gcpkms]'

provider = CompositeKeyProvider([
    GcpKmsKeyProvider(),                       # gcpkms://...
    LocalFileKeyProvider(root="/etc/approvo"), # file://name  -> /etc/approvo/name.key
])
```

| Scheme | Provider | Extra |
|---|---|---|
| `memory://name` | `InMemoryKeyProvider` | — |
| `file:///abs` / `file://name` | `LocalFileKeyProvider` | — |
| `env://VAR` | `EnvKeyProvider` | — |
| `gcpkms://projects/…/cryptoKeyVersions/N` | `providers.gcpkms.GcpKmsKeyProvider` | `approvo[gcpkms]` |
| `awskms://<key-id-or-arn>` | `providers.awskms.AwsKmsKeyProvider` | `approvo[awskms]` |
| `vault://<mount>/<key>` | `providers.vault.VaultTransitKeyProvider` | `approvo[vault]` |

Writing your own is one class; validate it with
`approvo.testing.KeyProviderConformance` (see [Storage](storage.md#the-conformance-suite)
for the subclass-a-suite pattern).

## `KeyResolver` — which key signs what

```python
from approvo.crypto import StaticKeyResolver, SigningPurpose

resolver = StaticKeyResolver({
    SigningPurpose.DECISION:   "gcpkms://.../cryptoKeys/org-approvals/cryptoKeyVersions/3",
    SigningPurpose.CHECKPOINT: "gcpkms://.../cryptoKeys/org-log/cryptoKeyVersions/1",
})
```

`StaticKeyResolver` is "one org key signs every decision." Use
`TemplateKeyResolver` for one key per `log_id` (environment / tenant), or
implement `resolve(ctx) -> key_ref` for anything else.

## `SigningService` — put it together

```python
from approvo.crypto import SigningService

signing = SigningService(provider, resolver)
await signing.self_test()                      # sign+verify a nonce per key, at startup
```

### Bootstrap the trust root

What you sign with must be what verifiers accept. `SigningService` builds
the `KeyRef` entries for you:

```python
from approvo import KeyDirectory

key_dir = KeyDirectory(await signing.trust_from_static(
    issuer_owner_id="svc:approvo-issuer",   # decision_issuer key -> this owner
    log_owner_id="svc:approvo-log",         # checkpoint key -> this owner
    not_before="2026-01-01T00:00:00Z",
    log_ids=("releases",),                  # scope both keys to this log
))
# add your per-person approver keys here too, if you also use those
```

### Run the service

```python
svc = ApprovalService(
    events=..., key_dir=key_dir, identities=..., policy_store=...,
    signing=signing,          # no per-call signer=, no log_signer
)

# decision: server signs with the org key; pass evidence you authed the user
await svc.submit_decision(
    request_id=rid, approver_id="user:casey", verdict="approve",
    authn={"method": "oidc", "iss": "https://idp.example", "sub": "casey", "jti": "…"},
)

await svc.checkpoint()        # signed with the resolved checkpoint key
```

## How custodial decisions verify

A decision counts if **either**:

1. a `key_use="approver"` key owned by `approver_id` signed it, **or**
2. a `key_use="decision_issuer"` key scoped to this `log_id` signed it and
   `approver_id` is a known identity (eligibility is still the policy
   engine's call).

`verify()` labels which path each decision took. The `authn` blob is
signed and stored, for cross-checking against your IdP logs later.

**The trade-off:** with custodial signing you trust the server's
authentication instead of the approver's key. A compromised backend can
forge approvals for known identities. For production gates, use per-person
keys or the [detached ceremony](getting-started.md#detached-signing-recommended-for-production).
Full detail: [ADR-0012](adr/0012-custodial-attribution.md),
[Security model](security.md).

## GCP Cloud KMS notes

- Key ref is `gcpkms://` + the full CryptoKeyVersion resource name.
- Algorithms: `EC_SIGN_P256_SHA256`, `EC_SIGN_P384_SHA384`,
  `RSA_SIGN_PSS_*`, `RSA_SIGN_PKCS1_*`, and `EC_SIGN_ED25519` where
  available.
- Auth via Application Default Credentials — prefer Workload Identity over
  service-account key files.
- Grant `cloudkms.cryptoKeyVersions.useToSign` +
  `cloudkms.cryptoKeyVersions.viewPublicKey`, per key or key ring.
- Enable KMS **Data Access audit logs** — your independent record of who
  invoked signing.
- Provision keys at approver-onboarding time, not on the first-approval
  path (`CreateCryptoKey` is slow).
- HSM protection level for anything gating production.
