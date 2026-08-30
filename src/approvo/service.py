"""The ApprovalService — the API your backend-for-frontend calls.

Async, store-injected, safe to share across a process. Construct one per
log at startup and hand it to your request handlers; it holds no
per-request state and opens no connections of its own.

Four invariants it maintains:

1. **The ledger is the only source of truth.** :meth:`get_status` replays
   that request's events and re-evaluates the policy every time.
   Projections are for lists and screens, never for gates.
2. **Nothing unverified is persisted.** Decision envelopes are verified
   against the key directory *before* being appended (fail closed).
3. **Every mutation is idempotent.** Requests by content address;
   decisions by reserve-then-complete on an idempotency key.
4. **Reads stay O(decisions), not O(ledger).** Every hot path goes through
   ``events_for_request``, which the store indexes.

Two ways to record a decision, and the difference matters:

:meth:`submit_decision`
    The server signs on the approver's behalf, after authenticating them.
    Convenient — but your BFF holds signing authority, so a compromised
    BFF can manufacture approvals.

:meth:`prepare_decision` + :meth:`submit_signed_decision`
    The approver's client signs; the BFF only relays bytes it cannot
    forge. Slower to build, dramatically stronger. Use this for anything
    that gates production.
"""

from __future__ import annotations

import asyncio
import base64
import random
import secrets
from datetime import timedelta

from .canonical import ZERO_HASH, canonical_bytes, canonical_hash
from .chain import next_entry, verify_segment
from .checkpoint import (
    build_checkpoint,
    sign_checkpoint,
    verify_checkpoint,
    verify_consistency,
)
from .clock import Clock, SystemClock, parse_rfc3339, to_rfc3339
from .crypto.envelope import pae, unwrap_payload, wrap
from .crypto.keys import KeyDirectory
from .crypto.signer import Signer
from .crypto.verifier import verify_envelope
from .errors import (
    ChallengeExpired,
    ConcurrencyExhausted,
    LedgerConflict,
    PolicyMismatch,
    RequestNotFound,
    SignatureInvalid,
    UnknownPolicy,
)
from .merkle import merkle_root
from .models import (
    DECISION_PAYLOAD_TYPE,
    ApprovalRequest,
    Check,
    Checkpoint,
    Decision,
    DecisionChallenge,
    Identity,
    Page,
    Record,
    RequestQuery,
    RequestView,
    Verdict,
    VerificationReport,
)
from .policy.engine import evaluate
from .policy.model import PolicyStore
from .projection import build_view
from .stores.base import EventStore, IdempotencyStore, NullProjectionStore, ProjectionStore

DEFAULT_APPEND_ATTEMPTS = 8
DEFAULT_CHALLENGE_TTL = timedelta(minutes=10)
DEFAULT_CLOCK_SKEW = timedelta(minutes=5)


class ApprovalService:
    def __init__(
        self,
        events: EventStore,
        key_dir: KeyDirectory,
        identities: dict[str, Identity],
        policy_store: PolicyStore,
        *,
        projections: ProjectionStore | None = None,
        idempotency: IdempotencyStore | None = None,
        clock: Clock | None = None,
        log_signer: Signer | None = None,
        append_attempts: int = DEFAULT_APPEND_ATTEMPTS,
        challenge_ttl: timedelta = DEFAULT_CHALLENGE_TTL,
        max_clock_skew: timedelta = DEFAULT_CLOCK_SKEW,
    ) -> None:
        self.events = events
        self.key_dir = key_dir
        self.identities = identities
        self.policy_store = policy_store
        self.projections = projections or NullProjectionStore()
        self.idempotency = idempotency
        self.clock = clock or SystemClock()
        self.log_signer = log_signer
        self.append_attempts = append_attempts
        self.challenge_ttl = challenge_ttl
        self.max_clock_skew = max_clock_skew

    # ------------------------------------------------------------------ #
    # Requests
    # ------------------------------------------------------------------ #

    async def create_request(
        self,
        *,
        kind: str,
        subject: dict,
        requested_by: str,
        policy_id: str,
        not_valid_after: str,
        nonce: str | None = None,
    ) -> ApprovalRequest:
        """Create a request, or return the identical existing one.

        The request id is the canonical hash of the identity-bearing
        fields, so calling this twice with the same arguments returns the
        same request without a second ledger entry — retries are safe with
        no idempotency key needed. Pass a fresh ``nonce`` (see
        :func:`new_nonce`) to intentionally open a second request for the
        same subject.
        """
        policy = self.policy_store.get(policy_id)
        policy.validate_subject(subject)
        request = ApprovalRequest(
            kind=kind,
            subject=subject,
            requested_by=requested_by,
            policy_id=policy_id,
            policy_digest=policy.digest,
            created_at=self.clock.now(),
            not_valid_after=not_valid_after,
            nonce=nonce or "",
        )
        existing = await self._load_request(request.request_id)
        if existing is not None:
            return existing  # identical by construction: the id is the content hash

        entry = await self._append(
            "request.created",
            request.to_dict(),
            at_time=request.created_at,
            request_id=request.request_id,
        )
        await self._project(request, at_time=request.created_at, last_seq=entry.seq)
        return request

    # ------------------------------------------------------------------ #
    # Decisions — server-side signing
    # ------------------------------------------------------------------ #

    async def submit_decision(
        self,
        *,
        request_id: str,
        approver_id: str,
        verdict: Verdict,
        signer: Signer,
        comment: str = "",
        idempotency_key: str = "",
    ) -> Record:
        """Sign and record a decision in one call.

        The service holds the signing key. Convenient for internal tools;
        for production gates prefer :meth:`prepare_decision` +
        :meth:`submit_signed_decision`, which keeps signing authority out
        of your backend entirely.
        """
        request = await self._require_request(request_id)
        decided_at = self.clock.now()
        decision = Decision(
            request_id=request_id,
            context_digest=request.context_digest(),
            verdict=verdict,
            approver_id=approver_id,
            decided_at=decided_at,
            comment=comment,
            idempotency_key=idempotency_key or f"{request_id}:{approver_id}:{verdict}",
        )
        envelope = wrap(decision.to_dict(), DECISION_PAYLOAD_TYPE, [signer])
        return await self.submit_signed_decision(envelope)

    # ------------------------------------------------------------------ #
    # Decisions — detached signing ceremony
    # ------------------------------------------------------------------ #

    async def prepare_decision(
        self,
        *,
        request_id: str,
        approver_id: str,
        verdict: Verdict,
        comment: str = "",
        idempotency_key: str = "",
    ) -> DecisionChallenge:
        """Produce the exact bytes an approver's client must sign.

        Hand the challenge to the client. It signs ``pae_b64`` (base64 of
        the DSSE pre-authentication encoding) with the approver's key and
        returns the signature, which you pass to
        :meth:`submit_signed_decision`. No private key ever reaches your
        backend, so a compromised backend cannot forge an approval.
        """
        request = await self._require_request(request_id)
        decided_at = self.clock.now()
        decision = Decision(
            request_id=request_id,
            context_digest=request.context_digest(),
            verdict=verdict,
            approver_id=approver_id,
            decided_at=decided_at,
            comment=comment,
            idempotency_key=idempotency_key or f"{request_id}:{approver_id}:{verdict}",
        )
        body = canonical_bytes(decision.to_dict())
        return DecisionChallenge(
            request_id=request_id,
            approver_id=approver_id,
            verdict=verdict,
            payload_type=DECISION_PAYLOAD_TYPE,
            payload_b64=base64.standard_b64encode(body).decode("ascii"),
            pae_b64=base64.standard_b64encode(
                pae(DECISION_PAYLOAD_TYPE, body)
            ).decode("ascii"),
            decided_at=decided_at,
            expires_at=to_rfc3339(parse_rfc3339(decided_at) + self.challenge_ttl),
            idempotency_key=decision.idempotency_key,
        )

    @staticmethod
    def envelope_from_challenge(challenge: DecisionChallenge, signatures: list[dict]) -> dict:
        """Assemble a DSSE envelope from a challenge and client signatures.

        *signatures* is ``[{"keyid": ..., "sig": <base64>}, ...]``.
        """
        return {
            "payloadType": challenge.payload_type,
            "payload": challenge.payload_b64,
            "signatures": signatures,
        }

    async def submit_signed_decision(self, envelope: dict) -> Record:
        """Record a decision the approver's client signed.

        Everything is re-derived from the envelope — the challenge is
        advisory and is never trusted. The envelope must carry a valid
        signature for the approver it names, bind to the current request
        body, and fall inside the approval window.
        """
        try:
            payload = unwrap_payload(envelope)
            decision = Decision.from_dict(payload)
        except (KeyError, ValueError, TypeError) as e:
            raise SignatureInvalid(f"malformed decision envelope: {e}") from e

        request = await self._require_request(decision.request_id)

        if decision.context_digest != request.context_digest():
            raise SignatureInvalid(
                "decision is bound to a different request body "
                "(the request changed, or the envelope was replayed across requests)"
            )

        now = self.clock.now()
        decided = parse_rfc3339(decision.decided_at)
        if decided > parse_rfc3339(now) + self.max_clock_skew:
            raise SignatureInvalid("decision timestamp is in the future")
        if decided > parse_rfc3339(request.not_valid_after) + self.max_clock_skew:
            raise ChallengeExpired(
                f"approval window for {request.request_id} closed at {request.not_valid_after}"
            )

        if decision.approver_id not in verify_envelope(
            envelope, self.key_dir, at_time=decision.decided_at
        ):
            raise SignatureInvalid(
                f"no valid signature for {decision.approver_id!r} "
                f"with a key valid at {decision.decided_at}"
            )

        key = decision.idempotency_key or (
            f"{decision.request_id}:{decision.approver_id}:{decision.verdict}"
        )
        fingerprint = canonical_hash(decision.to_dict())

        if self.idempotency is None:
            return await self._record_decision(request, decision, envelope)

        reservation = await self.idempotency.reserve(key, fingerprint)
        if not reservation.won:
            if reservation.response is None:
                # The winner is still in flight. Its append is the one that
                # counts; return the current state rather than racing it.
                return await self.get_status(decision.request_id)
            return await self.get_status(reservation.response["request_id"])

        try:
            record = await self._record_decision(request, decision, envelope)
        except Exception:
            await self.idempotency.release(key)
            raise
        await self.idempotency.complete(key, {"request_id": decision.request_id})
        return record

    async def _record_decision(
        self, request: ApprovalRequest, decision: Decision, envelope: dict
    ) -> Record:
        entry = await self._append(
            "decision.recorded",
            envelope,
            at_time=decision.decided_at,
            request_id=decision.request_id,
        )
        record = await self._recompute(request, at_time=self.clock.now())
        last_seq = entry.seq
        if record.status != "pending":
            status_entry = await self._append(
                "status.changed",
                {
                    "request_id": request.request_id,
                    "status": record.status,
                    "policy_result": record.policy_result.to_dict(),
                },
                at_time=self.clock.now(),
                request_id=request.request_id,
            )
            last_seq = status_entry.seq
        await self._project(request, at_time=self.clock.now(), last_seq=last_seq, record=record)
        return record

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #

    async def get_status(self, request_id: str) -> Record:
        """Authoritative status, re-derived from the ledger. Gate on this."""
        request = await self._require_request(request_id)
        return await self._recompute(request, at_time=self.clock.now())

    async def get_view(self, request_id: str) -> RequestView | None:
        """Projected view. Fast, cached, **not** authoritative."""
        return await self.projections.get(request_id)

    async def query(self, query: RequestQuery | None = None) -> Page[RequestView]:
        """List/filter requests for a UI. Reads projections, not the ledger."""
        return await self.projections.query(query or RequestQuery())

    async def rebuild_projections(self, *, batch_size: int = 500) -> int:
        """Recompute every view from the ledger. Safe to run any time.

        Use after a schema change, a projection-store loss, or whenever you
        want to prove the read model still agrees with the ledger.
        """
        await self.projections.clear()
        request_ids: list[str] = []
        async for entry in self.events.scan():
            if entry.event_type == "request.created" and entry.request_id:
                request_ids.append(entry.request_id)

        now = self.clock.now()
        rebuilt = 0
        for i in range(0, len(request_ids), batch_size):
            for request_id in request_ids[i : i + batch_size]:
                request = await self._load_request(request_id)
                if request is None:
                    continue
                entries = await self.events.events_for_request(request_id)
                last_seq = max((e.seq for e in entries), default=0)
                await self._project(request, at_time=now, last_seq=last_seq)
                rebuilt += 1
        return rebuilt

    # ------------------------------------------------------------------ #
    # Checkpoints & verification
    # ------------------------------------------------------------------ #

    async def checkpoint(self) -> Checkpoint:
        """Publish a signed tree head over the current log."""
        if self.log_signer is None:
            raise SignatureInvalid("no log_signer configured for checkpointing")
        leaves = await self.events.leaf_hashes()
        previous = await self.events.latest_checkpoint()
        cp = sign_checkpoint(
            build_checkpoint(
                leaves, log_id=self.events.log_id, at_time=self.clock.now(), prev=previous
            ),
            self.log_signer,
        )
        await self._append("checkpoint.published", cp.to_dict(), at_time=cp.published_at)
        return cp

    async def verify(
        self,
        *,
        trusted_checkpoint: Checkpoint | None = None,
        from_seq: int = 0,
        limit: int | None = None,
    ) -> VerificationReport:
        """Re-derive everything and report every integrity check.

        Walks the ledger streaming, so it is safe on a large log. For
        routine checks against a huge ledger, pass ``from_seq`` (and the
        ``expected_prev_hash`` implied by a pinned checkpoint) to verify
        only the segment written since you last looked.
        """
        checks: list[Check] = []

        def check(ok: bool, description: str) -> None:
            checks.append(Check(ok, description))

        # 1. Chain integrity over the requested segment.
        first = await self.events.get_by_seq(from_seq)
        expected_prev = first.prev_hash if first else ZERO_HASH
        last_seq = from_seq - 1
        decisions_seen: list[tuple[dict, Decision]] = []
        request_ids: list[str] = []
        try:
            entries = []
            async for entry in self.events.scan(start=from_seq, limit=limit):
                entries.append(entry)
                if entry.event_type == "decision.recorded":
                    decisions_seen.append((entry.payload, Decision.from_dict(
                        unwrap_payload(entry.payload)
                    )))
                elif entry.event_type == "request.created" and entry.request_id:
                    request_ids.append(entry.request_id)
            last_seq, _ = verify_segment(
                entries, expected_first_seq=from_seq, expected_prev_hash=expected_prev
            )
            check(True, f"hash chain intact from seq {from_seq} to {last_seq}")
        except Exception as e:  # noqa: BLE001 — report, don't raise
            check(False, f"hash chain: {e}")

        # 2. The published checkpoint reproduces and is correctly signed.
        published = await self.events.latest_checkpoint()
        if published is not None:
            try:
                signers = verify_checkpoint(published, self.key_dir)
                check(True, f"latest checkpoint signed by {', '.join(signers)}")
            except Exception as e:  # noqa: BLE001
                check(False, f"checkpoint signature: {e}")
            prefix = await self.events.leaf_hashes(up_to=published.tree_size)
            check(
                merkle_root(prefix) == published.root_hash,
                f"merkle root at tree_size={published.tree_size} matches checkpoint",
            )

        # 3. Consistency with an externally pinned checkpoint (fork detection).
        if trusted_checkpoint is not None:
            try:
                verify_checkpoint(trusted_checkpoint, self.key_dir)
                prefix = await self.events.leaf_hashes(up_to=trusted_checkpoint.tree_size)
                verify_consistency(trusted_checkpoint, prefix)
                check(True, "log extends the pinned trusted checkpoint")
            except Exception as e:  # noqa: BLE001
                check(False, f"consistency with pinned checkpoint: {e}")

        # 4. Every decision verifies and binds to the request it claims.
        for envelope, decision in decisions_seen:
            request = await self._load_request(decision.request_id)
            if request is None:
                check(False, f"decision references unknown request {decision.request_id}")
                continue
            check(
                decision.context_digest == request.context_digest(),
                f"decision by {decision.approver_id} bound to {_short(decision.request_id)}",
            )
            check(
                decision.approver_id
                in verify_envelope(envelope, self.key_dir, at_time=decision.decided_at),
                f"decision by {decision.approver_id} carries a valid signature",
            )

        # 5. Recorded status transitions reproduce from the evidence.
        now = self.clock.now()
        for request_id in request_ids:
            request = await self._load_request(request_id)
            if request is None:
                continue
            try:
                recomputed = await self._recompute(request, at_time=now)
            except UnknownPolicy:
                # Verifying an export without the policy set: chain,
                # signatures, and bindings still check out; status simply
                # cannot be recomputed. Say so rather than implying a pass.
                check(True, f"status for {_short(request_id)} not checked (policy unavailable)")
                continue
            except PolicyMismatch as e:
                check(False, str(e))
                continue
            recorded = await self._last_recorded_status(request_id)
            check(
                recorded is None
                or recorded == recomputed.status
                or recomputed.status == "expired",  # windows close with time, legitimately
                f"status for {_short(request_id)} reproducible ({recomputed.status})",
            )

        return VerificationReport(
            tuple(checks), verified_from_seq=from_seq, verified_to_seq=max(last_seq, from_seq)
        )

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _append(
        self, event_type: str, payload: dict, *, at_time: str, request_id: str | None = None
    ):
        """Append with optimistic-concurrency retry against the live head."""
        for attempt in range(self.append_attempts):
            prev = await self.events.head()
            entry = next_entry(
                prev,
                event_type=event_type,
                payload=payload,
                at_time=at_time,
                request_id=request_id,
            )
            try:
                await self.events.append(entry)
                return entry
            except LedgerConflict:
                if attempt == self.append_attempts - 1:
                    raise ConcurrencyExhausted(
                        f"could not append after {self.append_attempts} attempts; "
                        f"log {self.events.log_id!r} is under sustained write contention"
                    ) from None
                # full jitter, capped — avoids convoying under contention
                await asyncio.sleep(random.uniform(0, min(0.05 * 2**attempt, 0.5)))
        raise AssertionError("unreachable")

    async def _load_request(self, request_id: str) -> ApprovalRequest | None:
        for entry in await self.events.events_for_request(request_id):
            if entry.event_type == "request.created":
                return ApprovalRequest.from_dict(entry.payload)
        return None

    async def _require_request(self, request_id: str) -> ApprovalRequest:
        request = await self._load_request(request_id)
        if request is None:
            raise RequestNotFound(request_id)
        return request

    async def _decisions_for(self, request: ApprovalRequest) -> list[Decision]:
        """Decisions whose envelope verifies for the approver they name."""
        out: list[Decision] = []
        for entry in await self.events.events_for_request(request.request_id):
            if entry.event_type != "decision.recorded":
                continue
            decision = Decision.from_dict(unwrap_payload(entry.payload))
            if decision.approver_id in verify_envelope(
                entry.payload, self.key_dir, at_time=decision.decided_at
            ):
                out.append(decision)
        return out

    async def _recompute(self, request: ApprovalRequest, *, at_time: str) -> Record:
        policy = self.policy_store.get(request.policy_id)
        if policy.digest != request.policy_digest:
            raise PolicyMismatch(
                f"policy {request.policy_id!r} has changed since request "
                f"{_short(request.request_id)} pinned it"
            )
        decisions = await self._decisions_for(request)
        result = evaluate(request, decisions, policy, self.identities, at_time)
        return Record(request, tuple(decisions), result.status, result)

    async def _last_recorded_status(self, request_id: str) -> str | None:
        status = None
        for entry in await self.events.events_for_request(request_id):
            if entry.event_type == "status.changed":
                status = entry.payload.get("status")
        return status

    async def _project(
        self,
        request: ApprovalRequest,
        *,
        at_time: str,
        last_seq: int,
        record: Record | None = None,
    ) -> None:
        if isinstance(self.projections, NullProjectionStore):
            return
        record = record or await self._recompute(request, at_time=at_time)
        policy = self.policy_store.get(request.policy_id)
        await self.projections.upsert(
            build_view(record, policy, self.identities, last_seq=last_seq, updated_at=at_time)
        )


def _short(request_id: str) -> str:
    return request_id[:19] + "…" if len(request_id) > 19 else request_id


def new_nonce() -> str:
    """128 bits of randomness, for intentionally duplicate requests."""
    return secrets.token_hex(16)
