"""Signed checkpoints (signed tree heads) — pure, no I/O.

A checkpoint commits to the whole log at a point in time: "as of
``tree_size`` entries the Merkle root was ``root_hash``", signed by the
log key.

Why this matters more when the ledger lives in an external database: the
hash chain alone only proves *internal* consistency. Anyone who can
``TRUNCATE`` and re-insert can produce a perfectly self-consistent lie.
A checkpoint pinned somewhere the database operator cannot write turns
that into a provable fork.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_bytes
from .crypto.keys import KeyDirectory
from .crypto.signer import Signer
from .errors import CheckpointUnverified, ConsistencyFailure
from .merkle import merkle_root
from .models import Checkpoint

CHECKPOINT_SIG_CONTEXT = b"approvo/checkpoint/v1\n"


def signable_bytes(cp: Checkpoint) -> bytes:
    return CHECKPOINT_SIG_CONTEXT + canonical_bytes(cp.signed_dict())


def build_checkpoint(
    leaf_hashes: list[str],
    *,
    log_id: str,
    at_time: str,
    prev: Checkpoint | None = None,
) -> Checkpoint:
    """Compute an unsigned checkpoint over *leaf_hashes*."""
    return Checkpoint(
        tree_size=len(leaf_hashes),
        root_hash=merkle_root(leaf_hashes),
        published_at=at_time,
        log_id=log_id,
        prev_root_hash=prev.root_hash if prev else None,
    )


def sign_checkpoint(cp: Checkpoint, signer: Signer) -> Checkpoint:
    """Return *cp* with *signer*'s signature appended."""
    sig = {
        "keyid": signer.key_id(),
        "sig": base64.standard_b64encode(signer.sign(signable_bytes(cp))).decode("ascii"),
    }
    return Checkpoint.from_dict({**cp.to_dict(), "signatures": [*cp.signatures, sig]})


def verify_checkpoint(cp: Checkpoint, key_dir: KeyDirectory) -> list[str]:
    """Return owner ids whose signatures on *cp* verify; raise if none do."""
    signable = signable_bytes(cp)
    verified: list[str] = []
    for sig in cp.signatures:
        key = key_dir.get(sig.get("keyid", ""))
        if key is None or key.scheme != "ed25519" or not key.valid_at(cp.published_at):
            continue
        try:
            Ed25519PublicKey.from_public_bytes(key.public_bytes()).verify(
                base64.standard_b64decode(sig["sig"]), signable
            )
        except (InvalidSignature, ValueError, KeyError):
            continue
        verified.append(key.owner_id)
    if not verified:
        raise CheckpointUnverified(
            f"no valid signature on checkpoint at tree_size={cp.tree_size}"
        )
    return verified


def verify_consistency(trusted: Checkpoint, prefix_leaf_hashes: list[str]) -> None:
    """Prove the log extends a previously *trusted* checkpoint.

    *prefix_leaf_hashes* must be the first ``trusted.tree_size`` leaves of
    the current log. Their Merkle root must reproduce ``trusted.root_hash``
    exactly; anything else means history was rewritten.

    (Bandwidth-optimized RFC 6962 consistency proofs, for verifiers that
    cannot fetch the prefix, are on the roadmap — see ADR-0003.)
    """
    if len(prefix_leaf_hashes) < trusted.tree_size:
        raise ConsistencyFailure(
            f"log has shrunk: trusted tree_size={trusted.tree_size}, "
            f"log has {len(prefix_leaf_hashes)} entries"
        )
    root = merkle_root(prefix_leaf_hashes[: trusted.tree_size])
    if root != trusted.root_hash:
        raise ConsistencyFailure(
            f"log is not an extension of the trusted checkpoint "
            f"(prefix root {root} != trusted {trusted.root_hash})"
        )
