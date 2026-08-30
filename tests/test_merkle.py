import pytest

from approvo.merkle import inclusion_proof, merkle_root, verify_inclusion

LEAVES = [f"sha256:{i:064x}" for i in range(13)]


@pytest.mark.parametrize("size", range(1, 14))
def test_inclusion_proofs_verify_for_all_indices(size):
    leaves = LEAVES[:size]
    root = merkle_root(leaves)
    for i in range(size):
        proof = inclusion_proof(leaves, i)
        assert verify_inclusion(leaves[i], i, size, proof, root)


def test_wrong_leaf_fails():
    root = merkle_root(LEAVES)
    proof = inclusion_proof(LEAVES, 3)
    assert not verify_inclusion(LEAVES[4], 3, len(LEAVES), proof, root)


def test_wrong_index_fails():
    root = merkle_root(LEAVES)
    proof = inclusion_proof(LEAVES, 3)
    assert not verify_inclusion(LEAVES[3], 4, len(LEAVES), proof, root)


def test_truncated_proof_fails():
    root = merkle_root(LEAVES)
    proof = inclusion_proof(LEAVES, 3)
    assert not verify_inclusion(LEAVES[3], 3, len(LEAVES), proof[:-1], root)


def test_root_changes_with_any_leaf():
    tampered = LEAVES.copy()
    tampered[5] = "sha256:" + "f" * 64
    assert merkle_root(tampered) != merkle_root(LEAVES)
