"""RFC 6962-style Merkle tree over ledger entry hashes.

Leaves are the ledger's ``entry_hash`` strings. Domain separation follows
RFC 6962: leaf = H(0x00 || data), node = H(0x01 || left || right).
Inclusion proofs let a third party verify one entry belongs to a signed
checkpoint without being shown the whole log — which matters when the log
lives in someone else's database.

Pure functions, no I/O.
"""

from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(leaf: str) -> bytes:
    return _h(LEAF_PREFIX + leaf.encode("utf-8"))


def _node(left: bytes, right: bytes) -> bytes:
    return _h(NODE_PREFIX + left + right)


def _root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return _h(b"")
    if len(leaves) == 1:
        return leaves[0]
    # split at the largest power of two strictly less than len (RFC 6962)
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return _node(_root(leaves[:k]), _root(leaves[k:]))


def merkle_root(leaves: list[str]) -> str:
    return "sha256:" + _root([leaf_hash(x) for x in leaves]).hex()


def inclusion_proof(leaves: list[str], index: int) -> list[str]:
    """Audit path for ``leaves[index]``, bottom-up, as hex strings."""
    if not 0 <= index < len(leaves):
        raise IndexError(index)

    def path(hashes: list[bytes], i: int) -> list[bytes]:
        if len(hashes) == 1:
            return []
        k = 1
        while k * 2 < len(hashes):
            k *= 2
        if i < k:
            return path(hashes[:k], i) + [_root(hashes[k:])]
        return path(hashes[k:], i - k) + [_root(hashes[:k])]

    return [p.hex() for p in path([leaf_hash(x) for x in leaves], index)]


def verify_inclusion(leaf: str, index: int, tree_size: int, proof: list[str], root: str) -> bool:
    """Check that *leaf* at *index* is included in *root* over *tree_size* leaves."""
    if not 0 <= index < tree_size:
        return False
    computed = _verify_inclusion(
        leaf_hash(leaf), index, tree_size, [bytes.fromhex(p) for p in proof]
    )
    return computed is not None and computed == bytes.fromhex(root.removeprefix("sha256:"))


def _verify_inclusion(node: bytes, index: int, size: int, proof: list[bytes]) -> bytes | None:
    """Recompute the root from an audit path (recursive mirror of inclusion_proof)."""
    if size == 1:
        return node if not proof else None
    if not proof:
        return None
    k = 1
    while k * 2 < size:
        k *= 2
    sibling = proof[-1]
    if index < k:
        sub = _verify_inclusion(node, index, k, proof[:-1])
        return _node(sub, sibling) if sub is not None else None
    sub = _verify_inclusion(node, index - k, size - k, proof[:-1])
    return _node(sibling, sub) if sub is not None else None
