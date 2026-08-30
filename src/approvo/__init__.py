"""approvo — auditable, tamper-evident, idempotent approvals.

A library, not a service. You bring the datastore and the HTTP layer;
approvo brings content-addressed requests, signed decisions, a
hash-chained ledger, and verification that re-derives status from scratch.

Quick start::

    from approvo import ApprovalService, Ed25519Signer, KeyDirectory, Policy
    from approvo.stores import MemoryEventStore, MemoryProjectionStore

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
    verify_checkpoint,
    verify_consistency,
)
from .clock import Clock, FixedClock, SystemClock, parse_rfc3339, to_rfc3339
from .crypto.envelope import pae, unwrap_payload, wrap
from .crypto.keys import KeyDirectory, KeyRef
from .crypto.signer import Ed25519Signer, Signer
from .crypto.verifier import verify_envelope
from .errors import (
    ApprovoError,
    ChallengeExpired,
    ConcurrencyExhausted,
    IdempotencyConflict,
    LedgerConflict,
    LedgerTampered,
    PolicyMismatch,
    RequestNotFound,
    SignatureInvalid,
    StoreError,
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
    "ApprovalRequest",
    "ApprovalService",
    "ApprovoError",
    "ChallengeExpired",
    "Check",
    "Checkpoint",
    "Clock",
    "ConcurrencyExhausted",
    "Decision",
    "DecisionChallenge",
    "Ed25519Signer",
    "EventStore",
    "FixedClock",
    "IdempotencyConflict",
    "IdempotencyStore",
    "Identity",
    "InMemoryPolicyStore",
    "KeyDirectory",
    "KeyRef",
    "LedgerConflict",
    "LedgerEntry",
    "LedgerTampered",
    "NullProjectionStore",
    "Page",
    "Policy",
    "PolicyMismatch",
    "PolicyResult",
    "PolicyStore",
    "ProjectionStore",
    "Record",
    "RequestNotFound",
    "RequestQuery",
    "RequestView",
    "Reservation",
    "SignatureInvalid",
    "Signer",
    "StoreError",
    "SystemClock",
    "VerificationFailed",
    "VerificationReport",
    "build_checkpoint",
    "build_view",
    "canonical_bytes",
    "canonical_hash",
    "eligible_approvers",
    "inclusion_proof",
    "merkle_root",
    "new_nonce",
    "next_entry",
    "pae",
    "parse_rfc3339",
    "sign_checkpoint",
    "testing",
    "to_rfc3339",
    "unwrap_payload",
    "verify_checkpoint",
    "verify_consistency",
    "verify_envelope",
    "verify_inclusion",
    "verify_segment",
    "wrap",
]
