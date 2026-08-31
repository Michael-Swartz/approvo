"""Envelope verification against the key directory.

Dispatches per signature on the key's ``scheme`` through
:mod:`approvo.crypto.algorithms`. Unknown keyids, expired/revoked keys,
and bad signatures are skipped rather than raised — a decision simply
doesn't count, and the policy engine decides what missing approvals mean.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from ..errors import UnsupportedAlgorithmError
from .algorithms import get_scheme
from .envelope import signable_bytes
from .keys import KeyDirectory, KeyRef


@dataclass(frozen=True)
class VerifiedSignature:
    keyid: str
    owner_id: str
    key_use: str


def verified_signatures(
    envelope: dict, key_dir: KeyDirectory, at_time: str
) -> list[VerifiedSignature]:
    """Every signature on *envelope* that checks out with a key valid at *at_time*."""
    signable = signable_bytes(envelope)
    out: list[VerifiedSignature] = []
    seen: set[str] = set()
    for sig in envelope.get("signatures", ()):
        key: KeyRef | None = key_dir.get(sig.get("keyid", ""))
        if key is None or not key.valid_at(at_time):
            continue
        try:
            get_scheme(key.scheme).verify(
                key.public_bytes(), base64.standard_b64decode(sig["sig"]), signable
            )
        except (InvalidSignature, ValueError, KeyError, TypeError, UnsupportedAlgorithmError):
            continue
        if key.keyid not in seen:
            seen.add(key.keyid)
            out.append(VerifiedSignature(key.keyid, key.owner_id, key.key_use))
    return out


def verify_envelope(envelope: dict, key_dir: KeyDirectory, at_time: str) -> list[str]:
    """Owner ids with a valid signature on *envelope* as of *at_time*.

    Kept for the common case and for existing callers/tests. For the
    decision-authorisation rule (per-person key *or* an authorised
    decision-issuer key) use :func:`decision_authorized`.
    """
    result: list[str] = []
    for v in verified_signatures(envelope, key_dir, at_time):
        if v.owner_id not in result:
            result.append(v.owner_id)
    return result


def decision_authorized(
    envelope: dict,
    *,
    approver_id: str,
    log_id: str,
    key_dir: KeyDirectory,
    at_time: str,
    known_identity: bool = True,
) -> bool:
    """True if *envelope* is a legitimate decision by *approver_id* on *log_id*.

    Two acceptable shapes:

    1. A signature from an ``approver`` key whose ``owner_id`` is
       *approver_id* — the per-person model.
    2. A signature from a ``decision_issuer`` key scoped to *log_id* —
       custodial / org-level signing. The named *approver_id* must be a
       known identity; whether that person is *eligible* is then the
       policy engine's call.
    """
    for v in verified_signatures(envelope, key_dir, at_time):
        if v.key_use == "approver" and v.owner_id == approver_id:
            return True
        if v.key_use == "decision_issuer" and known_identity:
            key = key_dir.get(v.keyid)
            if key is not None and key.scoped_to(log_id):
                return True
    return False
