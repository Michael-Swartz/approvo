# API reference

Generated from docstrings. Everything importable from the top-level
`approvo` package is considered public and follows
[SemVer](https://semver.org/); submodule internals may change in a minor
release.

| Page | Contents |
|---|---|
| [ApprovalService](service.md) | The main entry point — requests, decisions, reads, checkpoints, verification |
| [Data models](models.md) | `ApprovalRequest`, `Decision`, `LedgerEntry`, `Checkpoint`, `Record`, `RequestView`, query/paging types |
| [Stores](stores.md) | The three storage protocols and `Reservation` |
| [Crypto & keys](crypto.md) | `Signer`, `Ed25519Signer`, `KeyRef`, `KeyDirectory`, DSSE envelope helpers |
| [Signing back ends](signing.md) | Algorithm registry, `KeyProvider`, `KeyResolver`, `SigningService`, cloud KMS providers |
| [Policy](policy.md) | `Policy`, `PolicyResult`, `evaluate`, `PolicyStore` |
| [Ledger internals](ledger.md) | Hash-chain and Merkle primitives, checkpoint build/sign/verify |
| [Errors](errors.md) | The exception hierarchy and suggested HTTP mapping |

## Top-level imports

```python
from approvo import (
    # service
    ApprovalService, new_nonce,
    # models
    ApprovalRequest, Decision, Identity, LedgerEntry, Checkpoint, Record,
    RequestView, RequestQuery, Page, DecisionChallenge,
    PolicyResult, Check, VerificationReport,
    # crypto
    Ed25519Signer, Signer, KeyRef, KeyDirectory, PublicKeyMaterial,
    wrap, wrap_async, unwrap_payload, pae, verify_envelope,
    verified_signatures, VerifiedSignature, decision_authorized,
    sign_with, public_key_ref, KEY_USES,
    # signing back ends
    KeyProvider, InMemoryKeyProvider, LocalFileKeyProvider, EnvKeyProvider,
    CompositeKeyProvider, KeyDescriptor, parse_key_ref,
    KeyResolver, StaticKeyResolver, TemplateKeyResolver,
    SigningContext, SigningPurpose, SigningService, TrustSpec,
    # policy
    Policy, PolicyStore, InMemoryPolicyStore,
    # ledger primitives
    next_entry, verify_segment, merkle_root, inclusion_proof,
    verify_inclusion, build_checkpoint, sign_checkpoint,
    sign_checkpoint_async, verify_checkpoint, verify_consistency,
    # store protocols
    EventStore, ProjectionStore, IdempotencyStore, Reservation,
    NullProjectionStore,
    # time
    Clock, SystemClock, FixedClock, to_rfc3339, parse_rfc3339,
    # canonical
    canonical_bytes, canonical_hash,
    # projection helpers
    build_view, eligible_approvers,
    # test helpers
    testing,
    # errors
    ApprovoError, RequestNotFound, SignatureInvalid, PolicyMismatch,
    IdempotencyConflict, LedgerConflict, ConcurrencyExhausted,
    ChallengeExpired, LedgerTampered, VerificationFailed, StoreError,
    SigningError, KeyProviderError, KeyResolutionError, UnsupportedAlgorithmError,
)
from approvo.stores import (
    EventStore, ProjectionStore, IdempotencyStore, NullProjectionStore,
)
from approvo.testing import (
    EventStoreConformance, ProjectionStoreConformance,
    IdempotencyStoreConformance, KeyProviderConformance,
)
# optional KMS back ends
from approvo.providers.gcpkms import GcpKmsKeyProvider   # pip install 'approvo[gcpkms]'
from approvo.providers.awskms import AwsKmsKeyProvider   # pip install 'approvo[awskms]'
from approvo.providers.vault import VaultTransitKeyProvider  # pip install 'approvo[vault]'
```
