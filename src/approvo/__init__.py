"""approvo — auditable, tamper-evident, idempotent approvals.

A library, not a service. You bring the datastore and the HTTP layer;
approvo brings content-addressed requests, signed decisions, a
hash-chained ledger, and verification that re-derives status from scratch.

Quick start::

    from approvo import ApprovalService, Ed25519Signer, KeyDirectory, Policy
    from approvo.stores import EventStore, ProjectionStore

See https://michael-swartz.github.io/approvo/ for full documentation, and
:mod:`approvo.stores.base` for the storage contract to implement against
your own database.
"""

from . import testing
from .canonical import canonical_bytes, canonical_hash
from .chain import next_entry, verify_segment
from .checkpoint import (
    build_checkpoint,
    sign_checkpoint,
    sign_checkpoint_async,
    verify_checkpoint,
    verify_consistency,
)
from .clock import Clock, FixedClock, SystemClock, parse_rfc3339, to_rfc3339
from .crypto.envelope import pae, unwrap_payload, wrap, wrap_async
from .crypto.keyprovider import (
    CompositeKeyProvider,
    EnvKeyProvider,
    InMemoryKeyProvider,
    KeyDescriptor,
    KeyProvider,
    LocalFileKeyProvider,
    parse_key_ref,
)
from .crypto.keys import KEY_USES, KeyDirectory, KeyRef
from .crypto.resolver import (
    KeyResolver,
    SigningContext,
    SigningPurpose,
    StaticKeyResolver,
    TemplateKeyResolver,
)
from .crypto.signer import Ed25519Signer, PublicKeyMaterial, Signer, public_key_ref, sign_with
from .crypto.signing import SigningService, TrustSpec
from .crypto.verifier import (
    VerifiedSignature,
    decision_authorized,
    verified_signatures,
    verify_envelope,
)
from .errors import (
    ApprovoError,
    ChallengeExpired,
    ConcurrencyExhausted,
    IdempotencyConflict,
    KeyProviderError,
    KeyResolutionError,
    LedgerConflict,
    LedgerTampered,
    PolicyMismatch,
    RequestNotFound,
    SignatureInvalid,
    SigningError,
    StoreError,
    UnsupportedAlgorithmError,
    VerificationFailed,
)
from .merkle import inclusion_proof, merkle_root, verify_inclusion
from .models import (
    ApprovalRequest,
    Check,
    Checkpoint,
    Decision,
    DecisionChallenge,
    Identity,
    LedgerEntry,
    Page,
    PolicyResult,
    Record,
    RequestQuery,
    RequestView,
    VerificationReport,
)
from .policy.model import InMemoryPolicyStore, Policy, PolicyStore
from .projection import build_view, eligible_approvers
from .service import ApprovalService, new_nonce
from .stores.base import (
    EventStore,
    IdempotencyStore,
    NullProjectionStore,
    ProjectionStore,
    Reservation,
)

__version__ = "0.1.0"

__all__ = [
    "KEY_USES",
    "ApprovalRequest",
    "ApprovalService",
    "ApprovoError",
    "ChallengeExpired",
    "Check",
    "Checkpoint",
    "Clock",
    "CompositeKeyProvider",
    "ConcurrencyExhausted",
    "Decision",
    "DecisionChallenge",
    "Ed25519Signer",
    "EnvKeyProvider",
    "EventStore",
    "FixedClock",
    "IdempotencyConflict",
    "IdempotencyStore",
    "Identity",
    "InMemoryKeyProvider",
    "InMemoryPolicyStore",
    "KeyDescriptor",
    "KeyDirectory",
    "KeyProvider",
    "KeyProviderError",
    "KeyRef",
    "KeyResolutionError",
    "KeyResolver",
    "LedgerConflict",
    "LedgerEntry",
    "LedgerTampered",
    "LocalFileKeyProvider",
    "NullProjectionStore",
    "Page",
    "Policy",
    "PolicyMismatch",
    "PolicyResult",
    "PolicyStore",
    "ProjectionStore",
    "PublicKeyMaterial",
    "Record",
    "RequestNotFound",
    "RequestQuery",
    "RequestView",
    "Reservation",
    "SignatureInvalid",
    "Signer",
    "SigningContext",
    "SigningError",
    "SigningPurpose",
    "SigningService",
    "StaticKeyResolver",
    "StoreError",
    "SystemClock",
    "TemplateKeyResolver",
    "TrustSpec",
    "UnsupportedAlgorithmError",
    "VerificationFailed",
    "VerificationReport",
    "VerifiedSignature",
    "build_checkpoint",
    "build_view",
    "canonical_bytes",
    "canonical_hash",
    "decision_authorized",
    "eligible_approvers",
    "inclusion_proof",
    "merkle_root",
    "new_nonce",
    "next_entry",
    "pae",
    "parse_key_ref",
    "parse_rfc3339",
    "public_key_ref",
    "sign_checkpoint",
    "sign_checkpoint_async",
    "sign_with",
    "testing",
    "to_rfc3339",
    "unwrap_payload",
    "verified_signatures",
    "verify_checkpoint",
    "verify_consistency",
    "verify_envelope",
    "verify_inclusion",
    "verify_segment",
    "wrap",
    "wrap_async",
]
