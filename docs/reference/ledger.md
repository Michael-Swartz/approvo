# Ledger internals

You rarely call these directly — `ApprovalService` does. They are public
so you can verify a ledger you obtained from anywhere (a database dump, an
export, another process) without the service.

## Hash chain

::: approvo.chain.next_entry

::: approvo.chain.verify_segment

## Merkle tree

::: approvo.merkle.merkle_root

::: approvo.merkle.inclusion_proof

::: approvo.merkle.verify_inclusion

::: approvo.merkle.leaf_hash

## Checkpoints

::: approvo.checkpoint.build_checkpoint

::: approvo.checkpoint.sign_checkpoint

::: approvo.checkpoint.verify_checkpoint

::: approvo.checkpoint.verify_consistency

::: approvo.checkpoint.signable_bytes
