"""Hash-chain construction and verification — pure, no I/O.

Separating these from the store lets you verify a ledger you fetched from
anywhere: a Postgres cursor, a Mongo batch, an S3 export, a JSON file
someone emailed you. The store's only job is to hand over entries in
sequence order.

Tamper-evidence model:

- each entry's ``entry_hash`` covers all of its content,
- each entry's ``prev_hash`` is the previous entry's ``entry_hash``,

so editing, deleting, inserting, or reordering any entry breaks the chain
for everything after it. Checkpoints (see :mod:`approvo.checkpoint`)
extend this to detect wholesale log replacement.
"""

from __future__ import annotations

from collections.abc import Iterable

from .canonical import ZERO_HASH, canonical_hash
from .errors import ChainBroken, EntryHashMismatch, SeqGap
from .models import LedgerEntry


def next_entry(
    prev: LedgerEntry | None,
    *,
    event_type: str,
    payload: dict,
    at_time: str,
    request_id: str | None = None,
) -> LedgerEntry:
    """Build the sealed entry that would follow *prev*."""
    return LedgerEntry(
        seq=(prev.seq + 1) if prev else 0,
        recorded_at=at_time,
        prev_hash=prev.entry_hash if prev else ZERO_HASH,
        event_type=event_type,  # type: ignore[arg-type]
        request_id=request_id,
        payload=payload,
    ).sealed()


def verify_segment(
    entries: Iterable[LedgerEntry],
    *,
    expected_first_seq: int = 0,
    expected_prev_hash: str = ZERO_HASH,
) -> tuple[int, str]:
    """Verify a contiguous run of entries; return ``(last_seq, last_hash)``.

    Pass the previous segment's return values as ``expected_first_seq`` and
    ``expected_prev_hash`` to verify a long ledger incrementally, page by
    page, without holding it all in memory.

    Raises a :class:`~approvo.errors.LedgerTampered` subtype on the first
    integrity failure.
    """
    seq, prev_hash = expected_first_seq, expected_prev_hash
    last_seq, last_hash = expected_first_seq - 1, expected_prev_hash
    for entry in entries:
        if entry.seq != seq:
            raise SeqGap(f"expected seq {seq}, found {entry.seq}")
        if entry.prev_hash != prev_hash:
            raise ChainBroken(f"prev_hash mismatch at seq {entry.seq}")
        if entry.entry_hash != canonical_hash(entry.core_dict()):
            raise EntryHashMismatch(f"entry_hash mismatch at seq {entry.seq}")
        last_seq, last_hash = entry.seq, entry.entry_hash
        seq, prev_hash = entry.seq + 1, entry.entry_hash
    return last_seq, last_hash
