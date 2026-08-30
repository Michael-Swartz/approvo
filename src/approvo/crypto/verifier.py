"""Envelope verification against the key directory.

Returns the *owner ids* whose signatures verified with a key that was
valid at ``at_time``. Unknown keyids and expired/revoked keys are
silently skipped — a decision simply doesn't count rather than blowing
up the whole verification pass (the policy engine decides what missing
approvals mean).
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .envelope import signable_bytes
from .keys import KeyDirectory


def verify_envelope(envelope: dict, key_dir: KeyDirectory, at_time: str) -> list[str]:
    """Return owner ids with a valid signature on *envelope* as of *at_time*."""
    signable = signable_bytes(envelope)
    verified: list[str] = []
    for sig in envelope.get("signatures", ()):
        key = key_dir.get(sig.get("keyid", ""))
        if key is None or key.scheme != "ed25519" or not key.valid_at(at_time):
            continue
        try:
            Ed25519PublicKey.from_public_bytes(key.public_bytes()).verify(
                base64.standard_b64decode(sig["sig"]), signable
            )
        except (InvalidSignature, ValueError, KeyError):
            continue
        if key.owner_id not in verified:
            verified.append(key.owner_id)
    return verified
