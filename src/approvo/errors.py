"""Typed exception hierarchy.

Every failure mode a caller might branch on has its own type, so a BFF can
map them to HTTP status codes without string matching. Suggested mapping:

===================================  ======
Exception                            HTTP
===================================  ======
``RequestNotFound``                  404
``UnknownPolicy``                    404
``SubjectConstraintViolation``       422
``PolicyMismatch``                   409
``IdempotencyConflict``              409
``LedgerConflict`` (after retries)   503
``ChallengeExpired``                 410
``SignatureInvalid``                 400
``KeyNotAuthorized``                 403
``KeyExpiredOrRevoked``              403
``SeparationOfDutiesViolation``      403
``RequestExpired``                   410
``LedgerTampered`` (any subtype)     500 + page someone
===================================  ======
"""

from __future__ import annotations


class ApprovoError(Exception):
    """Base class for all approvo errors."""


class RequestNotFound(ApprovoError):
    pass


class UnknownPolicy(ApprovoError):
    pass


class PolicyMismatch(ApprovoError):
    """The policy pinned by the request no longer matches the stored policy."""


class SubjectConstraintViolation(ApprovoError):
    pass


class IdempotencyConflict(ApprovoError):
    """The same idempotency key was reused with a different payload."""


class ChallengeExpired(ApprovoError):
    """A signing challenge was submitted after its expiry."""


class SignatureInvalid(ApprovoError):
    pass


class KeyNotAuthorized(ApprovoError):
    pass


class KeyExpiredOrRevoked(ApprovoError):
    pass


class SeparationOfDutiesViolation(ApprovoError):
    pass


class RequestExpired(ApprovoError):
    pass


class LedgerConflict(ApprovoError):
    """Two writers raced to append the same sequence number.

    Expected under concurrency; the service retries automatically. Escaping
    this exception means retries were exhausted — treat as backpressure.
    """


class ConcurrencyExhausted(LedgerConflict):
    """Append retries were exhausted under sustained write contention."""


class StoreError(ApprovoError):
    """The underlying datastore failed. Wraps driver exceptions."""


class SigningError(ApprovoError):
    """A signing backend failed to produce a signature."""


class KeyProviderError(SigningError):
    """A :class:`~approvo.crypto.keyprovider.KeyProvider` could not resolve or
    load a key. Wraps KMS / Vault / filesystem driver exceptions."""


class KeyResolutionError(SigningError):
    """A :class:`~approvo.crypto.resolver.KeyResolver` produced no key
    reference for the given signing context."""


class UnsupportedAlgorithmError(SigningError):
    """The signature scheme on a key or signer is not in the registry."""


class LedgerTampered(ApprovoError):
    """The ledger failed integrity verification. Always an incident."""


class ChainBroken(LedgerTampered):
    """An entry's prev_hash does not match the previous entry."""


class EntryHashMismatch(LedgerTampered):
    """An entry's recorded hash does not match its recomputed hash."""


class SeqGap(LedgerTampered):
    """Sequence numbers are not contiguous."""


class CheckpointUnverified(LedgerTampered):
    """A checkpoint signature or root hash failed to verify."""


class ConsistencyFailure(LedgerTampered):
    """The log is not a consistent extension of a previously trusted checkpoint."""


class VerificationFailed(ApprovoError):
    """One or more checks in a verification report failed."""
