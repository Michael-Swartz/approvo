"""Core data model.

All models are frozen dataclasses with explicit ``to_dict``/``from_dict``
converters producing canonicalizable JSON (see :mod:`approvo.canonical`).
Timestamps are RFC 3339 UTC strings throughout.

Identity rules:

- An :class:`ApprovalRequest`'s ``request_id`` is the canonical hash of its
  *identity-bearing* fields — ``created_at`` is deliberately excluded so
  that retrying the same logical request yields the same id (idempotency).
- A :class:`Decision` embeds ``context_digest``, the canonical hash of the
  full request as the approver saw it. A signature over a decision is
  therefore bound to exactly one request body — the subject cannot be
  swapped after the fact.

:class:`LedgerEntry` carries ``request_id`` *inside* its hashed core. That
field is what external datastores index on, so a BFF can load one
request's events without scanning the log — and because it is hashed, an
attacker cannot re-point an entry at a different request to hide it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, Literal, TypeVar

from .canonical import canonical_hash

REQUEST_SCHEMA = "approvo/request/v1"
DECISION_SCHEMA = "approvo/decision/v1"
CHECKPOINT_SCHEMA = "approvo/checkpoint/v1"
POLICY_SCHEMA = "approvo/policy/v1"

DECISION_PAYLOAD_TYPE = "application/vnd.approvo.decision+json"

Status = Literal["pending", "approved", "rejected", "expired"]
Verdict = Literal["approve", "reject"]

EventType = Literal[
    "request.created",
    "decision.recorded",
    "status.changed",
    "checkpoint.published",
]

T = TypeVar("T")


@dataclass(frozen=True)
class Identity:
    """A party allowed to interact with the system."""

    id: str  # stable identifier, e.g. "user:alice"
    roles: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"id": self.id, "roles": list(self.roles)}

    @classmethod
    def from_dict(cls, d: dict) -> Identity:
        return cls(id=d["id"], roles=tuple(d.get("roles", ())))


@dataclass(frozen=True)
class ApprovalRequest:
    kind: str  # e.g. "software-release"
    subject: dict  # kind-specific payload, e.g. {"artifact_digest": ..., "version": ...}
    requested_by: str  # Identity.id
    policy_id: str
    policy_digest: str  # pins the exact policy bytes in force at request time
    created_at: str
    not_valid_after: str  # approval window closes
    nonce: str = ""  # set to distinguish intentional duplicates of the same subject
    schema: str = REQUEST_SCHEMA

    @property
    def request_id(self) -> str:
        return canonical_hash(self.identity_dict())

    def identity_dict(self) -> dict:
        """The identity-bearing fields: same inputs => same request_id."""
        return {
            "schema": self.schema,
            "kind": self.kind,
            "subject": self.subject,
            "requested_by": self.requested_by,
            "policy_id": self.policy_id,
            "policy_digest": self.policy_digest,
            "not_valid_after": self.not_valid_after,
            "nonce": self.nonce,
        }

    def to_dict(self) -> dict:
        return {**self.identity_dict(), "created_at": self.created_at, "request_id": self.request_id}

    def context_digest(self) -> str:
        """What decisions bind to: the full request including created_at."""
        return canonical_hash({**self.identity_dict(), "created_at": self.created_at})

    @classmethod
    def from_dict(cls, d: dict) -> ApprovalRequest:
        return cls(
            kind=d["kind"],
            subject=d["subject"],
            requested_by=d["requested_by"],
            policy_id=d["policy_id"],
            policy_digest=d["policy_digest"],
            created_at=d["created_at"],
            not_valid_after=d["not_valid_after"],
            nonce=d.get("nonce", ""),
            schema=d.get("schema", REQUEST_SCHEMA),
        )


@dataclass(frozen=True)
class Decision:
    request_id: str
    context_digest: str  # canonical hash of the request the approver saw
    verdict: Verdict
    approver_id: str
    decided_at: str
    comment: str = ""
    idempotency_key: str = ""
    schema: str = DECISION_SCHEMA

    def to_dict(self) -> dict:
        return {
            "schema": self.schema,
            "request_id": self.request_id,
            "context_digest": self.context_digest,
            "verdict": self.verdict,
            "approver_id": self.approver_id,
            "decided_at": self.decided_at,
            "comment": self.comment,
            "idempotency_key": self.idempotency_key,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Decision:
        return cls(
            request_id=d["request_id"],
            context_digest=d["context_digest"],
            verdict=d["verdict"],
            approver_id=d["approver_id"],
            decided_at=d["decided_at"],
            comment=d.get("comment", ""),
            idempotency_key=d.get("idempotency_key", ""),
            schema=d.get("schema", DECISION_SCHEMA),
        )


@dataclass(frozen=True)
class LedgerEntry:
    seq: int  # 0-based, contiguous within a log
    recorded_at: str
    prev_hash: str  # entry_hash of seq-1; ZERO_HASH at genesis
    event_type: EventType
    request_id: str | None  # indexed by stores; None for log-wide events
    payload: dict
    entry_hash: str = ""  # canonical hash of everything above

    def core_dict(self) -> dict:
        return {
            "seq": self.seq,
            "recorded_at": self.recorded_at,
            "prev_hash": self.prev_hash,
            "event_type": self.event_type,
            "request_id": self.request_id,
            "payload": self.payload,
        }

    def to_dict(self) -> dict:
        return {**self.core_dict(), "entry_hash": self.entry_hash}

    def sealed(self) -> LedgerEntry:
        return LedgerEntry(**self.core_dict(), entry_hash=canonical_hash(self.core_dict()))

    @classmethod
    def from_dict(cls, d: dict) -> LedgerEntry:
        return cls(
            seq=d["seq"],
            recorded_at=d["recorded_at"],
            prev_hash=d["prev_hash"],
            event_type=d["event_type"],
            request_id=d.get("request_id"),
            payload=d["payload"],
            entry_hash=d.get("entry_hash", ""),
        )


@dataclass(frozen=True)
class Checkpoint:
    """A signed tree head: 'as of tree_size entries, the Merkle root was X'."""

    tree_size: int
    root_hash: str
    published_at: str
    log_id: str = "default"
    prev_root_hash: str | None = None
    signatures: tuple[dict, ...] = ()  # [{"keyid": ..., "sig": b64}, ...]
    schema: str = CHECKPOINT_SCHEMA

    def signed_dict(self) -> dict:
        """The bytes the log key signs — everything except the signatures."""
        return {
            "schema": self.schema,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "published_at": self.published_at,
            "prev_root_hash": self.prev_root_hash,
        }

    def to_dict(self) -> dict:
        return {**self.signed_dict(), "signatures": list(self.signatures)}

    @classmethod
    def from_dict(cls, d: dict) -> Checkpoint:
        return cls(
            tree_size=d["tree_size"],
            root_hash=d["root_hash"],
            published_at=d["published_at"],
            log_id=d.get("log_id", "default"),
            prev_root_hash=d.get("prev_root_hash"),
            signatures=tuple(d.get("signatures", ())),
            schema=d.get("schema", CHECKPOINT_SCHEMA),
        )


@dataclass(frozen=True)
class PolicyResult:
    status: Status
    satisfied_by: tuple[str, ...] = ()  # approver ids whose approvals counted
    reasons: tuple[str, ...] = ()  # human-readable evaluation trace

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "satisfied_by": list(self.satisfied_by),
            "reasons": list(self.reasons),
        }

    @classmethod
    def from_dict(cls, d: dict) -> PolicyResult:
        return cls(
            status=d["status"],
            satisfied_by=tuple(d.get("satisfied_by", ())),
            reasons=tuple(d.get("reasons", ())),
        )


@dataclass(frozen=True)
class Record:
    """Authoritative view of one request, re-derived from the ledger.

    Never cached, never trusted from storage. This is what a deploy gate
    must consult — as opposed to :class:`RequestView`, which is a
    projection built for listing things in a UI.
    """

    request: ApprovalRequest
    decisions: tuple[Decision, ...]
    status: Status
    policy_result: PolicyResult

    def to_dict(self) -> dict:
        return {
            "request": self.request.to_dict(),
            "decisions": [d.to_dict() for d in self.decisions],
            "status": self.status,
            "policy_result": self.policy_result.to_dict(),
        }


# --------------------------------------------------------------------------- #
# BFF read models — derived, queryable, explicitly untrusted
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RequestView:
    """Denormalized projection of a request, for list/filter/search screens.

    Rebuildable from the ledger at any time
    (:meth:`~approvo.service.ApprovalService.rebuild_projections`). Safe to
    render; **not** safe to gate on. Gate on
    :meth:`~approvo.service.ApprovalService.get_status`.
    """

    request_id: str
    kind: str
    status: Status
    requested_by: str
    policy_id: str
    subject: dict
    created_at: str
    not_valid_after: str
    updated_at: str
    approvals: int
    threshold: int
    approvers: tuple[str, ...] = ()
    pending_for: tuple[str, ...] = ()  # eligible approvers who have not decided
    last_seq: int = 0  # ledger position this view reflects

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "kind": self.kind,
            "status": self.status,
            "requested_by": self.requested_by,
            "policy_id": self.policy_id,
            "subject": self.subject,
            "created_at": self.created_at,
            "not_valid_after": self.not_valid_after,
            "updated_at": self.updated_at,
            "approvals": self.approvals,
            "threshold": self.threshold,
            "approvers": list(self.approvers),
            "pending_for": list(self.pending_for),
            "last_seq": self.last_seq,
        }

    @classmethod
    def from_dict(cls, d: dict) -> RequestView:
        return cls(
            request_id=d["request_id"],
            kind=d["kind"],
            status=d["status"],
            requested_by=d["requested_by"],
            policy_id=d["policy_id"],
            subject=d["subject"],
            created_at=d["created_at"],
            not_valid_after=d["not_valid_after"],
            updated_at=d["updated_at"],
            approvals=d["approvals"],
            threshold=d["threshold"],
            approvers=tuple(d.get("approvers", ())),
            pending_for=tuple(d.get("pending_for", ())),
            last_seq=d.get("last_seq", 0),
        )


@dataclass(frozen=True)
class RequestQuery:
    """Filters for the projection store. All filters AND together."""

    status: tuple[Status, ...] | None = None
    kind: str | None = None
    requested_by: str | None = None
    awaiting: str | None = None  # eligible approver who hasn't decided yet
    subject_match: dict | None = None  # exact-match on subject fields
    limit: int = 50
    cursor: str | None = None  # opaque; stores encode their own paging token


@dataclass(frozen=True)
class Page(Generic[T]):
    items: tuple[T, ...]
    next_cursor: str | None = None

    def to_dict(self) -> dict:
        return {
            "items": [i.to_dict() for i in self.items],  # type: ignore[attr-defined]
            "next_cursor": self.next_cursor,
        }


# --------------------------------------------------------------------------- #
# Detached-signing ceremony
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class DecisionChallenge:
    """Exact bytes an approver must sign, produced by ``prepare_decision``.

    The BFF hands this to the client (browser, CLI, HSM agent). The client
    signs ``pae`` and returns the signature; the server never sees a
    private key, so it cannot forge an approval even if fully compromised.
    """

    request_id: str
    approver_id: str
    verdict: Verdict
    payload_type: str
    payload_b64: str  # canonical decision bytes, base64
    pae_b64: str  # DSSE pre-authentication encoding, base64 — sign THIS
    decided_at: str
    expires_at: str
    idempotency_key: str

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "approver_id": self.approver_id,
            "verdict": self.verdict,
            "payload_type": self.payload_type,
            "payload_b64": self.payload_b64,
            "pae_b64": self.pae_b64,
            "decided_at": self.decided_at,
            "expires_at": self.expires_at,
            "idempotency_key": self.idempotency_key,
        }

    @classmethod
    def from_dict(cls, d: dict) -> DecisionChallenge:
        return cls(
            request_id=d["request_id"],
            approver_id=d["approver_id"],
            verdict=d["verdict"],
            payload_type=d["payload_type"],
            payload_b64=d["payload_b64"],
            pae_b64=d["pae_b64"],
            decided_at=d["decided_at"],
            expires_at=d["expires_at"],
            idempotency_key=d["idempotency_key"],
        )


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Check:
    """One line of a verification report."""

    ok: bool
    description: str


@dataclass(frozen=True)
class VerificationReport:
    checks: tuple[Check, ...] = field(default_factory=tuple)
    verified_from_seq: int = 0
    verified_to_seq: int = 0

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.ok)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "verified_from_seq": self.verified_from_seq,
            "verified_to_seq": self.verified_to_seq,
            "checks": [{"ok": c.ok, "description": c.description} for c in self.checks],
        }

    def raise_for_failures(self) -> None:
        from .errors import VerificationFailed

        if not self.ok:
            lines = "; ".join(c.description for c in self.failures)
            raise VerificationFailed(f"{len(self.failures)} check(s) failed: {lines}")
